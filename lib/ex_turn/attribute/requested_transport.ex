defmodule ExTURN.Attribute.RequestedTransport do
  @moduledoc false
  @behaviour ExSTUN.Message.Attribute

  alias ExSTUN.Message.RawAttribute

  @attr_type 0x0019

  @type t() :: %__MODULE__{value: :udp | :tcp}

  @enforce_keys [:value]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{} = raw_attr, _message) do
    decode(raw_attr.value)
  end

  @impl true
  def to_raw(%__MODULE__{value: :udp}, _msg) do
    %RawAttribute{type: @attr_type, value: <<17, 0, 0, 0>>}
  end

  def to_raw(%__MODULE__{value: :tcp}, _msg) do
    %RawAttribute{type: @attr_type, value: <<6, 0, 0, 0>>}
  end

  defp decode(<<17, 0, 0, 0>>), do: {:ok, %__MODULE__{value: :udp}}
  defp decode(<<6, 0, 0, 0>>), do: {:ok, %__MODULE__{value: :tcp}}
  defp decode(_other), do: {:error, :invalid_requested_transport}
end
