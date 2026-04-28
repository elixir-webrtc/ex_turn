defmodule ExTURN.ClientTest do
  use ExUnit.Case, async: true

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Nonce, Realm, Username, XORMappedAddress}

  alias ExTURN.Client
  alias ExTURN.Attribute.{Data, Lifetime, XORPeerAddress, XORRelayedAddress}

  @turn_uri ExSTUN.URI.parse!("turn:127.0.0.1:3478?transport=udp")
  @username "testusername"
  @password "testpassword"
  @nonce "testnonce"
  # used for testing stale nonce response
  @new_nonce "newtestnonce"
  @realm "testrealm"
  @data "RFC 5766"

  @turn_ip {127, 0, 0, 1}
  @turn_port 3478

  @relay_ip {127, 0, 0, 1}
  @relay_port 12_345

  @peer_ip {127, 0, 0, 2}
  @peer_port 12_345

  test "new/3" do
    assert {:ok, %Client{}} = Client.new(@turn_uri, @username, @password)
  end

  describe "allocation" do
    test "create" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      allocate(client)
    end

    test "refresh success response" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)

      alloc_exp_timer = client.alloc_exp_timer

      {:send, _dst, data, client} = Client.handle_message(client, :refresh_alloc)
      {:ok, req} = Message.decode(data)
      resp = refresh_success_response(req)

      resp = {:socket_data, client.turn_ip, client.turn_port, resp}
      assert {:ok, new_client} = Client.handle_message(client, resp)
      # assert that the timer has changed
      assert new_client.alloc_exp_timer != nil
      assert new_client.alloc_exp_timer != alloc_exp_timer
    end

    test "refresh error response" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)

      alloc_exp_timer = client.alloc_exp_timer

      {:send, _dst, data, client} = Client.handle_message(client, :refresh_alloc)
      {:ok, req} = Message.decode(data)
      resp = insufficient_capacity_error_response(req)

      resp = {:socket_data, client.turn_ip, client.turn_port, resp}
      assert {:ok, new_client} = Client.handle_message(client, resp)
      # assert that the timer hasn't changed 
      assert new_client.alloc_exp_timer == alloc_exp_timer
    end
  end

  test "stale nonce" do
    {:ok, client} = Client.new(@turn_uri, @username, @password)
    client = allocate(client)

    {:send, _dst, data, client} = Client.handle_message(client, :refresh_alloc)

    {:ok, req} = Message.decode(data)
    resp = stale_nonce_response(req)

    resp = {:socket_data, client.turn_ip, client.turn_port, resp}
    assert {:send, _dst, data, _client} = Client.handle_message(client, resp)
    {:ok, new_req} = Message.decode(data)

    assert new_req.transaction_id != req.transaction_id
    assert new_req.type == req.type
    assert {:ok, %Nonce{value: @new_nonce}} = Message.get_attribute(new_req, Nonce)
  end

  describe "close" do
    test "state :new transitions to :error without sending" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)

      assert {:ok, closed} = Client.close(client)
      assert closed.state == :error
    end

    test "state :auth transitions to :error without sending" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      {:send, _dst, _msg, client} = Client.allocate(client)
      assert client.state == :auth

      assert {:ok, closed} = Client.close(client)
      assert closed.state == :error
    end

    test "state :alloc transitions to :error without sending" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      {:send, _dst, msg, client} = Client.allocate(client)
      {:ok, req} = Message.decode(msg)

      resp = allocate_error_response(req)
      resp = {:socket_data, client.turn_ip, client.turn_port, resp}
      {:send, _dst, _msg, client} = Client.handle_message(client, resp)
      assert client.state == :alloc

      assert {:ok, closed} = Client.close(client)
      assert closed.state == :error
    end

    test "state :allocated sends Refresh with Lifetime=0 and transitions to :error" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)

      assert {:send, {@turn_ip, @turn_port}, msg, closed} = Client.close(client)
      assert closed.state == :error

      {:ok, req} = Message.decode(msg)
      assert req.type == %Type{class: :request, method: :refresh}

      assert {:ok, %Lifetime{value: 0}} = Message.get_attribute(req, Lifetime)
      assert {:ok, %Username{value: @username}} = Message.get_attribute(req, Username)
      assert {:ok, %Realm{value: @realm}} = Message.get_attribute(req, Realm)
      assert {:ok, %Nonce{value: @nonce}} = Message.get_attribute(req, Nonce)

      # authenticated with long-term credential derived from the allocation
      key = Message.lt_key(@username, @password, @realm)
      assert :ok == Message.authenticate(req, key)
    end

    test "state :allocated cancels the allocation expiration timer" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      alloc_exp_timer = client.alloc_exp_timer
      assert Process.read_timer(alloc_exp_timer) != false

      assert {:send, _dst, _msg, _closed} = Client.close(client)
      assert Process.read_timer(alloc_exp_timer) == false
    end

    test "state :allocated cancels permission timers" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      %{refresh_timer: refresh_timer, exp_timer: exp_timer} =
        Map.fetch!(client.permissions, @peer_ip)

      assert Process.read_timer(refresh_timer) != false
      assert Process.read_timer(exp_timer) != false

      assert {:send, _dst, _msg, _closed} = Client.close(client)

      assert Process.read_timer(refresh_timer) == false
      assert Process.read_timer(exp_timer) == false
    end

    test "state :allocated cancels channel timers" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_channel(client, @peer_ip, @peer_port)

      [channel_timer] = Map.values(client.channel_timer)
      assert Process.read_timer(channel_timer) != false

      assert {:send, _dst, _msg, _closed} = Client.close(client)

      assert Process.read_timer(channel_timer) == false
    end

    test "state :allocated flushes pending refresh/expiry messages" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      # Inject the messages that the timers would eventually emit so we can
      # prove close/1 drains them.
      send(self(), {:ex_turn, client.ref, :refresh_alloc})
      send(self(), {:ex_turn, client.ref, :allocation_expired})
      send(self(), {:ex_turn, client.ref, {:refresh_permission, @peer_ip}})
      send(self(), {:ex_turn, client.ref, {:permission_expired, @peer_ip}})

      assert {:send, _dst, _msg, _closed} = Client.close(client)

      refute_received {:ex_turn, _, :refresh_alloc}
      refute_received {:ex_turn, _, :allocation_expired}
      refute_received {:ex_turn, _, {:refresh_permission, _}}
      refute_received {:ex_turn, _, {:permission_expired, _}}
    end

    test "state :error returns {:ok, client} unchanged" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      errored = %{client | state: :error}

      assert {:ok, ^errored} = Client.close(errored)
    end
  end

  describe "permission" do
    test "create" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      create_permission(client, @peer_ip)
    end

    test "refresh success response" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      [%{exp_timer: exp_timer, refresh_timer: refresh_timer}] = Map.values(client.permissions)

      # refresh permission
      {:send, _dst, data, client} = Client.handle_message(client, {:refresh_permission, @peer_ip})
      {:ok, req} = Message.decode(data)
      resp = create_permission_success_response(req)
      resp = {:socket_data, client.turn_ip, client.turn_port, resp}
      {:ok, client} = Client.handle_message(client, resp)

      # assert there is a new timer 
      [%{exp_timer: new_exp_timer, refresh_timer: new_refresh_timer}] =
        Map.values(client.permissions)

      assert exp_timer != new_exp_timer
      assert refresh_timer != new_refresh_timer
      assert Process.read_timer(exp_timer) == false
      assert Process.read_timer(refresh_timer) == false
    end

    test "refresh error response" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      [%{exp_timer: exp_timer, refresh_timer: refresh_timer}] = Map.values(client.permissions)

      # refresh permission
      {:send, _dst, data, client} = Client.handle_message(client, {:refresh_permission, @peer_ip})
      {:ok, req} = Message.decode(data)
      resp = insufficient_capacity_error_response(req)
      resp = {:socket_data, client.turn_ip, client.turn_port, resp}
      {:ok, _client} = Client.handle_message(client, resp)

      # assert there is no new timer
      [%{exp_timer: new_exp_timer, refresh_timer: new_refresh_timer}] =
        Map.values(client.permissions)

      assert new_exp_timer == exp_timer
      assert new_refresh_timer == refresh_timer
      assert Process.read_timer(new_exp_timer) != false
    end
  end

  describe "channel" do
    test "create with permission created beforehand" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)
      create_channel(client, @peer_ip, @peer_port)
    end

    test "create without permission" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      create_channel(client, @peer_ip, @peer_port)
    end

    test "refresh success response" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_channel(client, @peer_ip, @peer_port)

      exp_timer = Map.values(client.channel_timer) |> List.first()

      {:send, _dst, data, client} =
        Client.handle_message(client, {:refresh_channel, {@peer_ip, @peer_port}})

      {:ok, req} = Message.decode(data)

      resp = create_channel_bind_success_response(req)
      resp = {:socket_data, client.turn_ip, client.turn_port, resp}
      assert {:ok, client} = Client.handle_message(client, resp)

      new_exp_timer = Map.values(client.channel_timer) |> List.first()

      assert new_exp_timer != nil
      assert exp_timer != new_exp_timer
      assert Process.read_timer(exp_timer) == false
      assert Process.read_timer(new_exp_timer) != false
    end

    test "refresh error response" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_channel(client, @peer_ip, @peer_port)

      exp_timer = Map.values(client.channel_timer) |> List.first()

      {:send, _dst, data, client} =
        Client.handle_message(client, {:refresh_channel, {@peer_ip, @peer_port}})

      {:ok, req} = Message.decode(data)

      resp = insufficient_capacity_error_response(req)
      resp = {:socket_data, client.turn_ip, client.turn_port, resp}
      assert {:ok, client} = Client.handle_message(client, resp)

      new_exp_timer = Map.values(client.channel_timer) |> List.first()

      assert exp_timer == new_exp_timer
      assert Process.read_timer(exp_timer) != false
      assert client.state != :error
    end
  end

  describe "send/3" do
    test "with permission" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      assert {:send, _dst, data, _client} =
               Client.send(client, {@peer_ip, @peer_port}, @data)

      assert {:ok, msg} = Message.decode(data)

      assert msg.type.class == :indication
      assert msg.type.method == :send

      assert {:ok, %XORPeerAddress{address: @peer_ip, port: @peer_port}} =
               Message.get_attribute(msg, XORPeerAddress)

      assert {:ok, %Data{value: @data}} = Message.get_attribute(msg, Data)
    end

    test "with permission and channel" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)
      client = create_channel(client, @peer_ip, @peer_port)

      assert {:send, _dst, data, _client} =
               Client.send(client, {@peer_ip, @peer_port}, @data)

      [channel_no] = Map.keys(client.channel_addr)
      len = byte_size(@data)
      assert <<^channel_no::16, ^len::16, @data::binary>> = data
    end

    test "without permission" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)

      assert {:ok, _client} = Client.send(client, {@peer_ip, @peer_port}, @data)
    end

    test "without allocation" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)

      assert {:ok, _client} = Client.send(client, {@peer_ip, @peer_port}, @data)
    end
  end

  describe "receiving data" do
    test "with data indication" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      data = data_indication(@data, @peer_ip, @peer_port)

      msg = {:socket_data, @turn_ip, @turn_port, data}

      assert {:data, {@peer_ip, @peer_port}, @data, %Client{}} =
               Client.handle_message(client, msg)
    end

    test "with channel" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)
      client = create_channel(client, @peer_ip, @peer_port)

      [channel_no] = Map.keys(client.channel_addr)

      data = <<channel_no::16, byte_size(@data)::16, @data::binary>>

      msg = {:socket_data, @turn_ip, @turn_port, data}

      assert {:data, {@peer_ip, @peer_port}, @data, %Client{}} =
               Client.handle_message(client, msg)
    end

    test "without permission" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)

      data = data_indication(@data, @peer_ip, @peer_port)

      msg = {:socket_data, @turn_ip, @turn_port, data}

      assert {:ok, %Client{}} = Client.handle_message(client, msg)
    end

    test "without channel" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      data = <<0x8000::16, byte_size(@data)::16, @data::binary>>

      msg = {:socket_data, @turn_ip, @turn_port, data}

      assert {:ok, %Client{}} = Client.handle_message(client, msg)

      client = %{client | state: :error}
      assert {:error, :invalid_state, ^client} = Client.handle_message(client, msg)
    end
  end

  defp allocate(client) do
    assert {:send, _dst, msg, client} = Client.allocate(client)
    assert {:ok, req} = Message.decode(msg)

    resp = allocate_error_response(req)
    resp = {:socket_data, client.turn_ip, client.turn_port, resp}
    assert {:send, _dst, msg, client} = Client.handle_message(client, resp)
    assert {:ok, req} = Message.decode(msg)

    resp = allocate_success_response(req)
    resp = {:socket_data, client.turn_ip, client.turn_port, resp}
    assert {:allocation_created, _, client} = Client.handle_message(client, resp)
    assert client.alloc_exp_timer != nil

    client
  end

  defp create_permission(client, ip) do
    assert {:send, _dst, msg, client} = Client.create_permission(client, ip)
    assert {:ok, req} = Message.decode(msg)

    resp = create_permission_success_response(req)
    resp = {:socket_data, client.turn_ip, client.turn_port, resp}
    assert {:permission_created, _ip, client} = Client.handle_message(client, resp)

    client
  end

  defp create_channel(client, ip, port) do
    assert {:send, _dst, msg, client} = Client.create_channel(client, ip, port)
    assert {:ok, req} = Message.decode(msg)

    resp = create_channel_bind_success_response(req)
    resp = {:socket_data, client.turn_ip, client.turn_port, resp}
    assert {:channel_created, {^ip, ^port}, client} = Client.handle_message(client, resp)

    client
  end

  defp allocate_error_response(req) do
    Message.new(req.transaction_id, %Type{class: :error_response, method: :allocate}, [
      %Nonce{value: @nonce},
      %Realm{value: @realm},
      %ErrorCode{code: 401}
    ])
    |> Message.encode()
  end

  defp allocate_success_response(req) do
    key = auth_request(req)

    Message.new(req.transaction_id, %Type{class: :success_response, method: :allocate}, [
      %XORRelayedAddress{address: @relay_ip, port: @relay_port},
      %Lifetime{value: 600},
      %XORMappedAddress{address: @relay_ip, port: @relay_port}
    ])
    |> Message.with_integrity(key)
    |> Message.encode()
  end

  defp refresh_success_response(req) do
    key = auth_request(req)

    Message.new(req.transaction_id, %Type{class: :success_response, method: :refresh}, [
      %Lifetime{value: 600}
    ])
    |> Message.with_integrity(key)
    |> Message.encode()
  end

  defp stale_nonce_response(req) do
    Message.new(req.transaction_id, %Type{class: :error_response, method: req.type.method}, [
      %Nonce{value: @new_nonce},
      %ErrorCode{code: 438}
    ])
    |> Message.encode()
  end

  defp create_permission_success_response(req) do
    key = auth_request(req)

    Message.new(
      req.transaction_id,
      %Type{class: :success_response, method: :create_permission},
      []
    )
    |> Message.with_integrity(key)
    |> Message.encode()
  end

  defp create_channel_bind_success_response(req) do
    key = auth_request(req)

    Message.new(
      req.transaction_id,
      %Type{class: :success_response, method: :channel_bind},
      []
    )
    |> Message.with_integrity(key)
    |> Message.encode()
  end

  defp insufficient_capacity_error_response(req) do
    key = auth_request(req)

    Message.new(
      req.transaction_id,
      %Type{class: :error_response, method: req.type.method},
      [%ErrorCode{code: 508}]
    )
    |> Message.with_integrity(key)
    |> Message.encode()
  end

  defp data_indication(data, src_ip, src_port) do
    ExSTUN.Message.new(%Type{method: :data, class: :indication}, [
      %Data{value: data},
      %XORPeerAddress{address: src_ip, port: src_port}
    ])
    |> Message.with_fingerprint()
    |> Message.encode()
  end

  # Server authenticates incoming requests using attributes included in a message.
  defp auth_request(req) do
    assert {:ok, username} = Message.get_attribute(req, Username)
    assert {:ok, realm} = Message.get_attribute(req, Realm)
    assert {:ok, nonce} = Message.get_attribute(req, Nonce)

    assert realm.value == @realm
    assert nonce.value == @nonce

    key = Message.lt_key(username.value, @password, realm.value)
    assert :ok == Message.authenticate(req, key)

    key
  end
end
