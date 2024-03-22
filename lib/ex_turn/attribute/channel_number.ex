defmodule ExTURN.Attribute.ChannelNumber do
  @moduledoc false
  @behaviour ExSTUN.Message.Attribute

  alias ExSTUN.Message.RawAttribute

  @attr_type 0x000C

  @type t() :: %__MODULE__{value: integer()}

  @enforce_keys [:value]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def to_raw(%__MODULE__{value: number}, _message) do
    %RawAttribute{type: @attr_type, value: <<number::16, 0::16>>}
  end

  @impl true
  def from_raw(%RawAttribute{value: <<number::16, 0::16>>}, _msg) do
    {:ok, %__MODULE__{value: number}}
  end

  @impl true
  def from_raw(%RawAttribute{}, _msg) do
    {:error, :invalid_channel_number}
  end
end
