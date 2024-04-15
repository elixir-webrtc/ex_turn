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

  Every notification has to be passed back to the client with `handle_message/2`.
  """
  @type notification() :: {:ex_turn, client_ref :: reference(), notification_message()}

  @typedoc """
  Notification message.

  Handled by the client. User code must not rely on its structure.
  """
  @opaque notification_message() ::
            :refresh_alloc
            | {:refresh_permission, XORRelayedAddress.t()}
            | {:transaction_timeout, transaction_id :: integer()}

  @typedoc """
  Messages that can be passed to `handle_message/2`.
  """
  @type message() ::
          {:socket_data, :inet.ip_address(), :inet.port_number(), binary()}
          | notification_message()

  @typedoc """
  Return values of `handle_message/2`.

  * `:ok` - no further actions are required.
  * `:send` - requires data to be sent over a socket owned by the user.
  * `:allocation_created` - an allocation has been successfully created.
  * `:permission_created` - a permission has been successfully created and
  the client is ready to send data with `send/3`.
  * `:channel_created` - a channel has been successfully created and all
  subsequent calls to `send/3` will use channel data message format.
  * `:data` - data has been received from a peer.
  * `:error` - an error has occured and the client cannot be used anymore.
  """
  @type on_handle_message() ::
          {:ok, t()}
          | {:send, addr(), binary(), t()}
          | {:allocation_created, addr(), t()}
          | {:permission_created, :inet.ip_address(), t()}
          | {:channel_created, addr(), t()}
          | {:data, src :: addr(), binary(), t()}
          | {:error, reason :: atom(), t()}

  @typedoc """
  Type describing `ExTURN.Client` struct.

  Possible states:
    * `:new` - the first allocation request has not been sent yet
    * `:auth` - the first allocation request has been sent
    * `:alloc` - an actuall allocation request with auth attributes has been sent
    * `:allocated` - an allocation has been successfully created
    * `:error` - an error has occured and the client cannot be used anymore.
  """
  @type t() :: %__MODULE__{
          ref: reference(),
          state: :new | :auth | :alloc | :allocated | :error,
          uri: ExSTUN.URI.t(),
          turn_ip: :inet.ip_address(),
          turn_port: :inet.port_number(),
          username: binary(),
          password: binary(),
          realm: binary(),
          nonce: binary(),
          key: binary(),
          transactions: %{(transaction_id :: integer()) => ExSTUN.Message.t()},
          permissions: MapSet.t(:inet.ip_address()),
          addr_channel: %{addr() => pos_integer()},
          channel_addr: %{pos_integer() => addr()}
        }

  @enforce_keys [:ref, :uri, :turn_ip, :turn_port, :username, :password]
  defstruct @enforce_keys ++
              [
                :realm,
                :nonce,
                :key,
                state: :new,
                transactions: %{},
                permissions: MapSet.new(),
                addr_channel: %{},
                channel_addr: %{}
              ]

  # Permission lifetime must be 300 seconds. See RFC 5766 sec. 8.
  @permission_lifetime_ms 300 * 1000

  # Channel lifetime lasts for 10 minutes. See RFC 5766 sec. 11.
  @channel_lifetime_ms 10 * 60 * 1000

  @transaction_timeout 1000

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
    permission = MapSet.member?(client.permissions, ip)
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

  @spec handle_message(t(), message()) :: on_handle_message()
  def handle_message(%__MODULE__{state: state} = client, msg) when state != :error do
    do_handle_message(client, msg)
  end

  @spec has_permission?(t(), :inet.ip_address()) :: boolean()
  def has_permission?(client, ip), do: MapSet.member?(client.permissions, ip)

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

        if req.type.method == resp.type.method do
          do_handle_stun_message(client, req, resp)
        else
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
             {_, true} <- {:perm_check, MapSet.member?(client.permissions, xor_peer_addr.address)} do
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
      client = %__MODULE__{client | state: :allocated}
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
      notify_after(client, :refresh_alloc, div(lifetime.lifetime * 1000, 2))
      {:ok, client}
    else
      _ -> {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         _req,
         %Message{type: %Type{class: :error_response, method: :refresh}}
       ) do
    Logger.warning("Failed to refresh allocation. Closing client.")
    client = %__MODULE__{client | state: :error}
    {:error, :failed_to_refresh_alloc, client}
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         req,
         %Message{type: %Type{class: :success_response, method: :create_permission}} = resp
       ) do
    case Message.authenticate(resp, client.key) do
      :ok ->
        {:ok, xor_peer_addr} = Message.get_attribute(req, XORPeerAddress)

        notify_after(
          client,
          {:refresh_permission, xor_peer_addr},
          div(@permission_lifetime_ms, 2)
        )

        permissions = MapSet.put(client.permissions, xor_peer_addr.address)
        client = %__MODULE__{client | permissions: permissions}
        {:permission_created, xor_peer_addr.address, client}

      {:error, _reason} ->
        {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         req,
         %Message{type: %Type{class: :success_response, method: :channel_bind}} = resp
       ) do
    case Message.authenticate(resp, client.key) do
      :ok ->
        {:ok, xor_peer_addr} = Message.get_attribute(req, XORPeerAddress)
        {:ok, channel_number} = Message.get_attribute(req, ChannelNumber)

        notify_after(client, {:refresh_channel, xor_peer_addr}, div(@channel_lifetime_ms, 2))

        # creating/refreshing a channel, also creates/refreshes permission
        permissions = MapSet.put(client.permissions, xor_peer_addr.address)

        peer_addr = {xor_peer_addr.address, xor_peer_addr.port}
        addr_channel = Map.put(client.addr_channel, peer_addr, channel_number.value)
        channel_addr = Map.put(client.channel_addr, channel_number.value, peer_addr)

        client = %__MODULE__{
          client
          | permissions: permissions,
            addr_channel: addr_channel,
            channel_addr: channel_addr
        }

        {:channel_created, {xor_peer_addr.address, xor_peer_addr.port}, client}

      {:error, _reason} ->
        {:ok, client}
    end
  end

  defp do_handle_stun_message(
         %__MODULE__{} = client,
         req,
         %Message{type: %Type{class: :error_response, method: :channel_bind}}
       ) do
    Logger.warning("Failed to create channel binding for: #{inspect(req)}. Closing client.")
    client = %__MODULE__{client | state: :error}
    {:error, :failed_to_create_channel, client}
  end

  defp do_handle_stun_message(client, req, resp) do
    Logger.debug("""
    Received unexpected STUN message in state: #{client.state}. Ignoring.
    Request: #{inspect(req)}
    Response: #{inspect(resp)}
    """)

    {:ok, client}
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
