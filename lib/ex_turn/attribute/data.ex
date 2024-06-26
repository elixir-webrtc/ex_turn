defmodule ExTURN.Attribute.Data do
  @moduledoc false
  @behaviour ExSTUN.Message.Attribute

  alias ExSTUN.Message.RawAttribute

  @attr_type 0x0013

  @type t() :: %__MODULE__{value: binary()}

  @enforce_keys [:value]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{} = raw_attr, _message) do
    {:ok, %__MODULE__{value: raw_attr.value}}
  end

  @impl true
  def to_raw(%__MODULE__{value: data}, _message) do
    %RawAttribute{type: @attr_type, value: data}
  end
end
