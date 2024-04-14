defmodule ExTURN do
  @moduledoc """
  Module with helper functions
  """

  @doc """
  Checks if binary is a TURN channel data.

  Based on RFC 5766, sec. 11.
  """
  @spec channel_data?(binary()) :: boolean()
  def channel_data?(<<1::2, _rest::bitstring>>), do: true
  def channel_data?(_), do: false
end
