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
  @realm "testrealm"

  @turn_ip {127, 0, 0, 1}
  @turn_port 3478

  @relay_ip {127, 0, 0, 1}
  @relay_port 12_345

  @peer_ip {192, 168, 0, 1}
  @peer_port 12_345

  test "new/3" do
    assert {:ok, %Client{}} = Client.new(@turn_uri, @username, @password)
  end

  test "allocate/1" do
    {:ok, client} = Client.new(@turn_uri, @username, @password)
    allocate(client)
  end

  test "create_permission/2" do
    {:ok, client} = Client.new(@turn_uri, @username, @password)
    client = allocate(client)
    create_permission(client, @peer_ip)
  end

  describe "create_channel/3" do
    test "with permission created beforehand" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)
      create_channel(client, @peer_ip, @peer_port)
    end

    test "without permission" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      create_channel(client, @peer_ip, @peer_port)
    end
  end

  describe "send/3" do
    test "with permission" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      assert {:send, _dst, data, _client} =
               Client.send(client, {@peer_ip, @peer_port}, <<"RFC 5766">>)

      assert {:ok, msg} = Message.decode(data)

      assert msg.type.class == :indication
      assert msg.type.method == :send

      assert {:ok, %XORPeerAddress{address: @peer_ip, port: @peer_port}} =
               Message.get_attribute(msg, XORPeerAddress)

      assert {:ok, %Data{value: <<"RFC 5766">>}} = Message.get_attribute(msg, Data)
    end

    test "with permission and channel" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)
      client = create_channel(client, @peer_ip, @peer_port)

      assert {:send, _dst, data, _client} =
               Client.send(client, {@peer_ip, @peer_port}, <<"RFC 5766">>)

      assert <<_channel_num::16, _len::16, "RFC 5766"::binary>> = data
    end

    test "without permission" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)

      assert {:ok, _client} = Client.send(client, {@peer_ip, @peer_port}, <<"RFC 5766">>)
    end

    test "without allocation" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)

      assert {:ok, _client} = Client.send(client, {@peer_ip, @peer_port}, <<"RFC 5766">>)
    end
  end

  describe "receiving data" do
    test "with data indication" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      data =
        ExSTUN.Message.new(%Type{method: :data, class: :indication}, [
          %Data{value: "testdata"},
          %XORPeerAddress{address: @peer_ip, port: @peer_port}
        ])
        |> Message.with_fingerprint()
        |> Message.encode()

      msg = {:socket_data, @turn_ip, @turn_port, data}

      assert {:data, {@peer_ip, @peer_port}, "testdata", %Client{}} =
               Client.handle_message(client, msg)
    end

    test "with channel" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)
      client = create_channel(client, @peer_ip, @peer_port)

      [channel_no] = Map.keys(client.channel_addr)

      data = "testdata"
      data = <<channel_no::16, byte_size(data)::16, data::binary>>

      msg = {:socket_data, @turn_ip, @turn_port, data}

      assert {:data, {@peer_ip, @peer_port}, "testdata", %Client{}} =
               Client.handle_message(client, msg)
    end

    test "without permission" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)

      data =
        ExSTUN.Message.new(%Type{method: :data, class: :indication}, [
          %Data{value: "testdata"},
          %XORPeerAddress{address: @peer_ip, port: @peer_port}
        ])
        |> Message.with_fingerprint()
        |> Message.encode()

      msg = {:socket_data, @turn_ip, @turn_port, data}

      assert {:ok, %Client{}} = Client.handle_message(client, msg)
    end

    test "without channel" do
      {:ok, client} = Client.new(@turn_uri, @username, @password)
      client = allocate(client)
      client = create_permission(client, @peer_ip)

      data = "testdata"
      data = <<0x8000::16, byte_size(data)::16, data::binary>>

      msg = {:socket_data, @turn_ip, @turn_port, data}

      assert {:ok, %Client{}} = Client.handle_message(client, msg)
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
      %Lifetime{lifetime: 600},
      %XORMappedAddress{address: @relay_ip, port: @relay_port}
    ])
    |> Message.with_integrity(key)
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
