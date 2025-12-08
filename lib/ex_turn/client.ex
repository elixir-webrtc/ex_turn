defmodule ExTURN.Client do
  @moduledoc """
  Memory-based TURN client.
  """
  require Logger

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Nonce, Realm, Username, XORMappedAddress}

  alias ExTURN.Attribute.{
    Data,
    ChannelNumber,
    Lifetime,
    RequestedTransport,
    XORPeerAddress,
    XORRelayedAddress
  }

  @type addr() :: {:inet.ip_address(), :inet.port_number()}

  @typedoc """
  Notifications emitted by the client.
  """
  @type notification() ::
          {:ex_turn, client_ref :: reference(),
           msg :: public_notification_message() | internal_notification_message()}

  @type public_notification_message() ::
          {:allocation_expired, addr()}
          | {:permission_expired, :inet.ip_address()}
          | {:channel_expired, addr()}

  @typedoc """
  Internal notification message.

  Has to be passed back to the client with `handle_message/2`.
  """
  @opaque internal_notification_message() ::
            :refresh_alloc
            | {:refresh_permission, :inet.ip_address()}
            | {:refresh_channel, addr()}
            | {:transaction_timeout, transaction_id :: integer()}

  @typedoc """
  Messages that can be passed to `handle_message/2`.
  """
  @type message() ::
          {:socket_data, :inet.ip_address(), :inet.port_number(), binary()}
          | internal_notification_message()

  @typedoc """
  Return values of `handle_message/2`.

  * `:ok` - no further actions are required.
  * `:send` - requires data to be sent over a socket owned by the user.
  * `:allocation_created` - an allocation has been successfully created.
  * `:permission_created` - a permission has been successfully created and
  the client is ready to send data with `send/3`.
  * `:permission_expired` - a permission could not be refreshed and eventually expired.
  Together with expired permission, all channels bound to the permission ip also expire.
  * `:channel_created` - a channel has been successfully created and all
  subsequent calls to `send/3` will use channel data message format.
  * `:channel_expired` - a channel could not be refreshed and eventually expired.
  * `:data` - data has been received from a peer.
  * `:error` - an error has occured and the client cannot be used anymore.
  """
  @type on_handle_message() ::
          {:ok, t()}
          | {:send, addr(), binary(), t()}
          | {:allocation_created, addr(), t()}
          | {:permission_created, :inet.ip_address(), t()}
          | {:permission_expired, :inet.ip_address(), t()}
          | {:channel_created, addr(), t()}
          | {:channel_expired, addr(), t()}
          | {:data, src :: addr(), binary(), t()}
          | {:error, reason :: atom(), t()}

  @typedoc """
  Type describing `ExTURN.Client` struct.

  Possible states:
    * `:new` - the first allocation request has not been sent yet
    * `:auth` - the first allocation request has been sent
    * `:alloc` - an actuall allocation request with auth attributes has been sent
    * `:allocated` - an allocation has been successfully created
    * `:deallocating` - a deallocation request (REFRESH with lifetime=0) has been sent
    * `:deallocated` - the allocation has been successfully deallocated
    * `:error` - an error has occured and the client cannot be used anymore.
  """
  @type t() :: %__MODULE__{
          ref: reference(),
          state: :new | :auth | :alloc | :allocated | :deallocating | :deallocated | :error,
          uri: ExSTUN.URI.t(),
          turn_ip: :inet.ip_address(),
          turn_port: :inet.port_number(),
          username: binary(),
          password: binary(),
          realm: binary(),
          nonce: binary(),
          key: binary(),
          transactions: %{(transaction_id :: integer()) => ExSTUN.Message.t()},
          permissions: %{
            :inet.ip_address() => %{:refresh_timer => reference(), :exp_timer => reference()}
          },
          addr_channel: %{addr() => pos_integer()},
          channel_addr: %{pos_integer() => addr()},
          channel_timer: %{pos_integer() => reference()},
          alloc_exp_timer: reference()
        }

  @enforce_keys [:ref, :uri, :turn_ip, :turn_port, :username, :password]
  defstruct @enforce_keys ++
              [
                :realm,
                :nonce,
                :key,
                :alloc_exp_timer,
                state: :new,
                transactions: %{},
                permissions: %{},
                addr_channel: %{},
                channel_addr: %{},
                channel_timer: %{}
              ]

  # Permission lifetime must be 300 seconds. See RFC 5766 sec. 8.
  @permission_lifetime_ms 300 * 1000

  # Channel lifetime lasts for 10 minutes. See RFC 5766 sec. 11.
  @channel_lifetime_ms 10 * 60 * 1000

  @transaction_timeout 1000

  # This macro is used to flush mailbox after an allocation, permission or channel has been refreshed.
  # In fact, this should never happen as we send refresh requests a few minutes before
  # an allocation, permission or channel expires.
  defmacrop flush_mailbox(pattern) do
    quote do
      receive do
        unquote(pattern) -> :ok
      after
        0 -> :ok
      end
    end
  end

  @spec new(ExSTUN.URI.t(), binary(), binary()) ::
          {:ok, t()} | {:error, :unsupported_turn_uri | :invalid_turn_server}
  def new(uri, username, password) do
    with true <- supported?(uri),
         {:ok, ip} <- resolve(uri) do
      {:ok,
       %__MODULE__{
         ref: make_ref(),
         uri: uri,
         turn_ip: ip,
         turn_port: uri.port,
         username: username,
         password: password
       }}
    else
      false ->
        {:error, :unsupported_turn_uri}

      {:error, reason} ->
        Logger.debug("Couldn't resolve TURN address: #{uri.host}, reason: #{reason}.")
        {:error, :invalid_turn_server}
    end
  end

  @spec allocate(t()) :: {:send, addr(), binary(), t()}
  def allocate(%__MODULE__{state: :new} = client) do
    req =
      %Type{class: :request, method: :allocate}
      |> Message.new([%RequestedTransport{value: :udp}])
      |> Message.with_fingerprint()

    client = %__MODULE__{client | state: :auth}

    execute_transaction(client, req)
  end

  @spec create_permission(t(), :inet.ip_address()) :: {:send, addr(), binary(), t()}
  def create_permission(%__MODULE__{state: :allocated} = client, ip) do
    req = permission_request(ip, client.username, client.realm, client.nonce, client.key)
    execute_transaction(client, req)
  end

  @spec create_channel(t(), :inet.ip_address(), :inet.port_number()) ::
          {:ok, t()} | {:send, addr(), binary(), t()}
  def create_channel(%__MODULE__{state: :allocated} = client, ip, port) do
    # TODO: Wait 5 minutes before re-using channel number or transport address.
    # See RFC 5766 sec. 11.

    tr =
      Enum.find(client.transactions, fn {_id, msg} ->
        if msg.type.class == :request and msg.type.method == :channel_bind do
          {:ok, xor_addr} = Message.get_attribute(msg, XORPeerAddress)
          xor_addr.address == ip and xor_addr.port == port
        else
          false
        end
      end)

    if tr do
      Logger.debug("""
      There is already channel transaction for: #{inspect(ip)}:#{port} in-progress. Ignoring request.
      """)

      {:ok, client}
    else
      channel_number = find_free_channel_number(Map.values(client.addr_channel))

      req =
        channel_bind_request(
          channel_number,
          ip,
          port,
          client.username,
          client.realm,
          client.nonce,
          client.key
        )

      execute_transaction(client, req)
    end
  end

  @spec send(t(), addr(), binary()) :: {:ok, t()} | {:send, addr(), binary(), t()}
  def send(%__MODULE__{state: :allocated} = client, {ip, port} = dst, data) do
    permission = Map.has_key?(client.permissions, ip)
    channel = Map.get(client.addr_channel, dst)

    case {permission, channel} do
      {false, nil} ->
        Logger.warning("""
        Tyring to send data but there is no permission for: #{inspect(ip)}. Ignoring.
        """)

        {:ok, client}

      {true, nil} ->
        msg =
          %Type{class: :indication, method: :send}
          |> Message.new([
            %XORPeerAddress{address: ip, port: port},
            %Data{value: data}
          ])
          |> Message.with_fingerprint()
          |> Message.encode()

        {:send, {client.turn_ip, client.turn_port}, msg, client}

      {true, channel} ->
        channel_data = <<channel::16, byte_size(data)::16, data::binary>>
        {:send, {client.turn_ip, client.turn_port}, channel_data, client}
    end
  end

  def send(%__MODULE__{state: state} = client, _dst, _data) do
    Logger.warning("Trying to send data in invalid state: #{state}. Ignoring.")
    {:ok, client}
  end

  @doc """
  Deallocates the TURN allocation by sending a REFRESH request with lifetime=0.

  This should be called when the allocation is no longer needed to cleanly
  release resources on the TURN server.
  """
  @spec deallocate(t()) :: {:send, addr(), binary(), t()} | {:ok, t()}
  def deallocate(%__MODULE__{state: :allocated} = client) do
    Process.cancel_timer(client.alloc_exp_timer)
    flush_mailbox({:ex_turn, _, :allocation_expired})
    flush_mailbox({:ex_turn, _, :refresh_alloc})
    req = refresh_request_with_lifetime(0, client.username, client.realm, client.nonce, client.key)
    client = %__MODULE__{client | state: :deallocating}
    execute_transaction(client, req)
  end

  def deallocate(%__MODULE__{state: state} = client) do
    Logger.debug("Cannot deallocate in state #{state}. Ignoring.")
    {:ok, client}
  end

  @spec handle_message(t(), message()) :: on_handle_message()
  def handle_message(%__MODULE__{state: state} = client, msg) when state not in [:error, :deallocated] do
    do_handle_message(client, msg)
  end

  # Handle messages when client is in error or deallocated state.
  # These are no-ops since the client is already unusable.
  def handle_message(%__MODULE__{state: state} = client, msg) when state in [:error, :deallocated] do
    Logger.debug("Received message #{inspect(msg)} in #{state} state. Ignoring.")
    {:ok, client}
  end

  @spec has_permission?(t(), :inet.ip_address()) :: boolean()
  def has_permission?(client, ip), do: Map.has_key?(client.permissions, ip)

  @spec has_channel?(t(), :inet.ip_address(), :inet.port_number()) :: boolean()
  def has_channel?(client, ip, port), do: Map.has_key?(client.addr_channel, {ip, port})

  # PRIVATE FUNCTIONS

  defp do_handle_message(
         %__MODULE__{turn_ip: src_ip, turn_port: src_port} = client,
         {:socket_data, src_ip, src_port, packet}
       ) do
    cond do
      ExTURN.channel_data?(packet) == true ->
        handle_channel_data(client, packet)

      ExSTUN.stun?(packet) == true ->
        handle_stun_message(client, packet)

      true ->
        Logger.debug("Received data that is neither channel data nor STUN message. Ignoring.")
        {:ok, client}
    end
  end

  defp do_handle_message(client, :refresh_alloc) do
    req = refresh_request(client.username, client.realm, client.nonce, client.key)
    execute_transaction(client, req)
  end

  defp do_handle_message(client, {:refresh_permission, ip}) do
    req = permission_request(ip, client.username, client.realm, client.nonce, client.key)
    execute_transaction(client, req)
  end

  defp do_handle_message(client, {:refresh_channel, {ip, port} = peer_addr}) do
    channel_number = Map.fetch!(client.addr_channel, peer_addr)

    req =
      channel_bind_request(
        channel_number,
        ip,
        port,
        client.username,
        client.realm,
        client.nonce,
        client.key
      )

    execute_transaction(client, req)
  end

  defp do_handle_message(client, {:transaction_timeout, t_id}) do
    case pop_in(client.transactions[t_id]) do
      {nil, client} ->
        {:ok, client}

      {msg, client} ->
        reason = String.to_atom("#{msg.type.method}_request_timeout")
        client = %__MODULE__{client | state: :error}
        {:error, reason, client}
    end
  end

  defp do_handle_message(client, :allocation_expired) do
    client = %__MODULE__{client | state: :error}
    {:error, :allocation_expired, client}
  end

  defp do_handle_message(client, {:permission_expired, ip}) do
    permissions = Map.delete(client.permissions, ip)

    {to_delete, _} =
      Map.split_with(client.addr_channel, fn {{ch_ip, _ch_port}, _ch_number} -> ch_ip == ip end)

    addrs_to_delete = Map.keys(to_delete)
    ch_to_delete = Map.values(to_delete)

    addr_channel = Map.drop(client.addr_channel, addrs_to_delete)
    channel_addr = Map.drop(client.channel_addr, ch_to_delete)
    channel_timer = Map.drop(client.channel_timer, ch_to_delete)

    client = %__MODULE__{
      client
      | permissions: permissions,
        addr_channel: addr_channel,
        channel_addr: channel_addr,
        channel_timer: channel_timer
    }

    {:permission_expired, ip, client}
  end

  defp do_handle_message(client, {:channel_expired, peer_addr}) do
    {channel_number, addr_channel} = Map.pop!(client.addr_channel, peer_addr)
    {_, channel_addr} = Map.pop!(client.channel_addr, channel_number)
    {_, channel_timer} = Map.pop!(client.channel_timer, channel_number)

    client = %__MODULE__{
      client
      | addr_channel: addr_channel,
        channel_addr: channel_addr,
        channel_timer: channel_timer
    }

    {:channel_expired, peer_addr, client}
  end

  defp handle_channel_data(client, <<channel_number::16, len::16, data::binary-size(len)>>) do
    case Map.get(client.channel_addr, channel_number) do
      nil ->
        Logger.debug("""
        Received message from unknown channel: #{channel_number}. Ignoring.
        Known channels: #{Map.keys(client.channel_addr)}.
        """)

        {:ok, client}

      {_ip, _port} = addr ->
        {:data, addr, data, client}
    end
  end

  defp handle_channel_data(client, _) do
    Logger.debug("Received invalid channel data. Ignoring.")
    {:ok, client}
  end

  defp handle_stun_message(client, packet) do
    case Message.decode(packet) do
      {:ok, resp} when is_map_key(client.transactions, resp.transaction_id) ->
        {req, client} = pop_in(client.transactions[resp.transaction_id])

        cond do
          resp.type.class == :error_response and
              match?({:ok, %ErrorCode{code: 438}}, Message.get_attribute(resp, ErrorCode)) ->
            handle_stale_nonce(client, req, resp)

          req.type.method == resp.type.method ->
            do_handle_stun_message(client, req, resp)

          true ->
            Logger.debug("""
            Received STUN response with non-matching method. Ignoring.
            STUN request: #{inspect(req)}.
            STUN response: #{inspect(resp)}.
            """)

            {:ok, client}
        end

      {:ok, resp} when resp.type == %Type{class: :indication, method: :data} ->
        with {:ok, xor_peer_addr} <- Message.get_attribute(resp, XORPeerAddress),
             {:ok, data} <- Message.get_attribute(resp, Data),
             {_, true} <- {:perm_check, Map.has_key?(client.permissions, xor_peer_addr.address)} do
          from = {xor_peer_addr.address, xor_peer_addr.port}
          {:data, from, data.value, client}
        else
          {:perm_check, false} ->
            {:ok, xor_peer_addr} = Message.get_attribute(resp, XORPeerAddress)

            Logger.debug("""
            Received data indication from an adress that we have no permission for. Ignoring.
            Address: #{inspect(xor_peer_addr.address)}.
            Permissions: #{inspect(client.permissions)}.
            """)

            {:ok, client}

          _ ->
            Logger.debug("""
            Received data indication without XOR-PEER-ADDRESS or DATA attribute. Ignoring.
            """)

            {:ok, client}
        end

      {:ok, resp} ->
        Logger.debug("""
        Received STUN message with unknown transaction id. Ignoring.
        Message: #{inspect(resp)}.
        """)

        {:ok, client}

      {:error, reason} ->
        Logger.debug("Couldn't decode STUN message, reason: #{reason}. Ignoring.")
        {:ok, client}
    end
  end

  defp handle_stale_nonce(client, req, resp) do
    case Message.get_attribute(resp, Nonce) do
      {:ok, %Nonce{value: nonce}} ->
        # TODO extend ex_stun API so this code isn't so hacky
        tmp_msg = Message.new(%Type{method: :binding, class: :request})
        client = %__MODULE__{client | nonce: nonce}
        attrs = Enum.reject(req.attributes, fn attr -> attr.type == 0x0015 end)
        req = %Message{req | transaction_id: tmp_msg.transaction_id, attributes: attrs}
        req = Message.add_attribute(req, Nonce.to_raw(%Nonce{value: nonce}, req))
        execute_transaction(client, req)

      nil ->
        Logger.debug(
          "Received stale nonce response without nonce attribute. Ignoring. Req: #{inspect(req)}, resp: #{inspect(resp)}"
        )

        {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{state: :auth} = client,
         _req,
         %Message{type: %Type{class: :error_response, method: :allocate}} = resp
       ) do
    with {:ok, %ErrorCode{code: 401}} <- Message.get_attribute(resp, ErrorCode),
         {:ok, nonce} <- Message.get_attribute(resp, Nonce),
         {:ok, realm} <- Message.get_attribute(resp, Realm) do
      key = Message.lt_key(client.username, client.password, realm.value)
      req = allocate_request(client.username, realm.value, nonce.value, key)

      client = %__MODULE__{
        client
        | state: :alloc,
          realm: realm.value,
          nonce: nonce.value,
          key: key
      }

      execute_transaction(client, req)
    else
      _ ->
        Logger.debug("""
        Received incorrect error response in state: :auth.
        No or invalid ERROR-CODE, NONCE or REALM. Ignoring.
        """)

        {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{state: :alloc} = client,
         _req,
         %Message{type: %Type{class: :success_response, method: :allocate}} = resp
       ) do
    with :ok <- Message.authenticate(resp, client.key),
         {:ok, xor_relayed_addr} <- Message.get_attribute(resp, XORRelayedAddress),
         {:ok, lifetime} <- Message.get_attribute(resp, Lifetime),
         {:ok, _xor_mapped_addr} <- Message.get_attribute(resp, XORMappedAddress) do
      notify_after(client, :refresh_alloc, div(lifetime.value * 1000, 2))
      exp_timer = notify_after(client, :allocation_expired, lifetime.value * 1000)
      client = %__MODULE__{client | state: :allocated, alloc_exp_timer: exp_timer}
      {:allocation_created, {xor_relayed_addr.address, xor_relayed_addr.port}, client}
    else
      _ -> {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{state: :alloc} = client,
         _req,
         %Message{type: %Type{class: :error_response, method: :allocate}} = resp
       ) do
    error_code =
      case Message.get_attribute(resp, ErrorCode) do
        {:ok, error_code} -> error_code.code
        _other -> nil
      end

    Logger.warning("Failed to create allocation, reason: #{error_code}. Closing client.")
    client = %__MODULE__{client | state: :error}
    {:error, :failed_to_allocate, client}
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         _req,
         %Message{type: %Type{class: :success_response, method: :refresh}} = resp
       ) do
    with :ok <- Message.authenticate(resp, client.key),
         {:ok, lifetime} <- Message.get_attribute(resp, Lifetime) do
      if lifetime.value == 0 do
        # Deallocation successful - allocation has been released
        Logger.debug("TURN allocation deallocated successfully")
        client = %__MODULE__{client | state: :deallocated}
        {:ok, client}
      else
        # Normal refresh - reschedule timers
        Process.cancel_timer(client.alloc_exp_timer)
        flush_mailbox({:ex_turn, _, :allocation_expired})
        notify_after(client, :refresh_alloc, div(lifetime.value * 1000, 2))
        exp_timer = notify_after(client, :allocation_expired, lifetime.value * 1000)
        client = %__MODULE__{client | alloc_exp_timer: exp_timer}
        {:ok, client}
      end
    else
      _ -> {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         %Message{type: %Type{class: :request, method: :refresh}},
         %Message{type: %Type{class: :error_response, method: :refresh}}
       ) do
    Logger.debug("Failed to refresh allocation.")
    {:ok, client}
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         %Message{type: %Type{class: :request, method: :create_permission}} = req,
         %Message{type: %Type{class: :success_response, method: :create_permission}} = resp
       ) do
    case Message.authenticate(resp, client.key) do
      :ok ->
        {:ok, xor_peer_addr} = Message.get_attribute(req, XORPeerAddress)

        new_client = install_or_refresh_permission(client, xor_peer_addr.address)

        case Map.get(client.permissions, xor_peer_addr.address) do
          nil -> {:permission_created, xor_peer_addr.address, new_client}
          _ -> {:ok, new_client}
        end

      {:error, _reason} ->
        {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         %Message{type: %Type{class: :request, method: :create_permission}} = req,
         %Message{type: %Type{class: :error_response, method: :create_permission}} = resp
       ) do
    with :ok <- Message.authenticate(resp, client.key),
         {:ok, error} <- Message.get_attribute(req, ErrorCode) do
      {:ok, xor_peer_addr} = Message.get_attribute(req, XORPeerAddress)

      if Map.has_key?(client.permissions, xor_peer_addr.address) do
        Logger.debug("""
        Failed to refresh permission for #{inspect(xor_peer_addr.address)}, reason: #{inspect(error)}\
        """)

        {:ok, client}
      else
        Logger.debug("""
        Failed to create  permission for #{inspect(xor_peer_addr.address)}, reason: #{inspect(error)}\
        """)

        client = %__MODULE__{client | state: :error}
        {:error, :failed_to_create_permission, client}
      end
    else
      _ -> {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         req,
         %Message{type: %Type{class: :success_response, method: :channel_bind}} = resp
       ) do
    with :ok <- Message.authenticate(resp, client.key),
         {:ok, xor_peer_addr} <- Message.get_attribute(req, XORPeerAddress),
         {:ok, channel_number} <- Message.get_attribute(req, ChannelNumber) do
      peer_addr = {xor_peer_addr.address, xor_peer_addr.port}

      cond do
        Map.has_key?(client.addr_channel, peer_addr) == true and
            Map.has_key?(client.channel_addr, channel_number.value) == true ->
          client = install_or_refresh_permission(client, xor_peer_addr.address)
          # refresh channel binding
          old_exp_timer = Map.fetch!(client.channel_timer, channel_number.value)
          Process.cancel_timer(old_exp_timer)
          flush_mailbox({:channel_expired, ^peer_addr})
          notify_after(client, {:refresh_channel, peer_addr}, div(@channel_lifetime_ms, 2))

          exp_timer = notify_after(client, {:channel_expired, peer_addr}, @channel_lifetime_ms)

          channel_timer = Map.put(client.channel_timer, channel_number.value, exp_timer)
          {:ok, %__MODULE__{client | channel_timer: channel_timer}}

        Map.has_key?(client.addr_channel, xor_peer_addr.address) == false and
            Map.has_key?(client.channel_addr, channel_number.value) == false ->
          client = install_or_refresh_permission(client, xor_peer_addr.address)
          # install channel binding
          notify_after(client, {:refresh_channel, peer_addr}, div(@channel_lifetime_ms, 2))

          exp_timer =
            notify_after(client, {:channel_expired, peer_addr}, @channel_lifetime_ms)

          addr_channel = Map.put(client.addr_channel, peer_addr, channel_number.value)
          channel_addr = Map.put(client.channel_addr, channel_number.value, peer_addr)
          channel_timer = Map.put(client.channel_timer, channel_number.value, exp_timer)

          client = %__MODULE__{
            client
            | addr_channel: addr_channel,
              channel_addr: channel_addr,
              channel_timer: channel_timer
          }

          {:channel_created, peer_addr, client}

        true ->
          Logger.debug(
            "Invalid channel bind success response. Invalid address or channel number. Ignoring"
          )

          {:ok, client}
      end
    else
      _ ->
        Logger.debug("Invalid channel bind success response. Ignoring.")
        {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         %Message{type: %Type{class: :request, method: :channel_bind}} = req,
         %Message{type: %Type{class: :error_response, method: :channel_bind}} = resp
       ) do
    {:ok, xor_peer_addr} = Message.get_attribute(req, XORPeerAddress)
    {:ok, channel_number} = Message.get_attribute(req, ChannelNumber)
    peer_addr = {xor_peer_addr.address, xor_peer_addr.port}

    with :ok <- Message.authenticate(resp, client.key),
         {:ok, error} <- Message.get_attribute(resp, ErrorCode) do
      if Map.has_key?(client.addr_channel, peer_addr) == true and
           Map.has_key?(client.channel_addr, channel_number.value) == true do
        Logger.debug(
          "Failed to refresh channel binding for: #{inspect(req)}, reason: #{inspect(error)}."
        )

        {:ok, client}
      else
        Logger.debug(
          "Failed to create channel binding for: #{inspect(req)}, reason: #{inspect(error)}. Closing client."
        )

        client = %__MODULE__{client | state: :error}
        {:error, :failed_to_create_channel, client}
      end
    else
      {:error, _reason} ->
        {:ok, client}
    end
  end

  defp do_handle_stun_message(client, req, resp) do
    Logger.debug("""
    Received unexpected STUN message in state: #{client.state}. Ignoring.
    Request: #{inspect(req)}
    Response: #{inspect(resp)}
    """)

    {:ok, client}
  end

  defp install_or_refresh_permission(client, ip) do
    case Map.get(client.permissions, ip) do
      nil ->
        :ok

      %{exp_timer: old_exp_timer, refresh_timer: old_refresh_timer} ->
        # If there already is a permission, cancel its timer
        Process.cancel_timer(old_refresh_timer)
        Process.cancel_timer(old_exp_timer)
        flush_mailbox({:ex_turn, _, {:refresh_permission, ^ip}})
        flush_mailbox({:ex_turn, _, {:permission_expired, ^ip}})
    end

    refresh_timer =
      notify_after(client, {:refresh_permission, ip}, div(@permission_lifetime_ms, 2))

    exp_timer = notify_after(client, {:permission_expired, ip}, @permission_lifetime_ms)

    permissions =
      Map.put(client.permissions, ip, %{refresh_timer: refresh_timer, exp_timer: exp_timer})

    %__MODULE__{client | permissions: permissions}
  end

  defp execute_transaction(client, req) do
    client = put_in(client.transactions[req.transaction_id], req)
    notify_after(client, {:transaction_timeout, req.transaction_id}, @transaction_timeout)
    {:send, {client.turn_ip, client.turn_port}, Message.encode(req), client}
  end

  defp supported?(%ExSTUN.URI{scheme: :turn, transport: :udp}), do: true
  defp supported?(_other), do: false

  defp resolve(uri) do
    ret =
      uri.host
      |> then(&String.to_charlist(&1))
      |> :inet.gethostbyname()

    case ret do
      {:ok, {:hostent, _, _, _, _, ips}} -> {:ok, List.first(ips)}
      {:error, _reason} = error -> error
    end
  end

  defp allocate_request(username, realm, nonce, key) do
    %Type{class: :request, method: :allocate}
    |> Message.new([
      %RequestedTransport{value: :udp},
      %Username{value: username},
      %Nonce{value: nonce},
      %Realm{value: realm}
    ])
    |> Message.with_integrity(key)
    |> Message.with_fingerprint()
  end

  defp refresh_request(username, realm, nonce, key) do
    %Type{class: :request, method: :refresh}
    |> Message.new([
      %Username{value: username},
      %Nonce{value: nonce},
      %Realm{value: realm}
    ])
    |> Message.with_integrity(key)
    |> Message.with_fingerprint()
  end

  defp refresh_request_with_lifetime(lifetime, username, realm, nonce, key) do
    %Type{class: :request, method: :refresh}
    |> Message.new([
      %Lifetime{value: lifetime},
      %Username{value: username},
      %Nonce{value: nonce},
      %Realm{value: realm}
    ])
    |> Message.with_integrity(key)
    |> Message.with_fingerprint()
  end

  defp permission_request(ip, username, realm, nonce, key) do
    %Type{class: :request, method: :create_permission}
    |> Message.new([
      # The port is ignored on the server side. See RFC 5766, sec. 9.1.
      %XORPeerAddress{address: ip, port: 0},
      %Username{value: username},
      %Nonce{value: nonce},
      %Realm{value: realm}
    ])
    |> Message.with_integrity(key)
    |> Message.with_fingerprint()
  end

  defp channel_bind_request(channel_number, ip, port, username, realm, nonce, key) do
    %Type{class: :request, method: :channel_bind}
    |> Message.new([
      %ChannelNumber{value: channel_number},
      %XORPeerAddress{address: ip, port: port},
      %Username{value: username},
      %Nonce{value: nonce},
      %Realm{value: realm}
    ])
    |> Message.with_integrity(key)
    |> Message.with_fingerprint()
  end

  defp find_free_channel_number(channels) do
    channels = MapSet.new(channels)
    Enum.find(0x4000..0x7FFF, &(not MapSet.member?(channels, &1)))
  end

  defp notify_after(client, msg, time),
    do: Process.send_after(self(), {:ex_turn, client.ref, msg}, time)
end
