# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Type.CoseKey do
  @moduledoc false

  use Ash.Type

  @impl Ash.Type
  def cast_input(value, _constraints) when is_map(value) do
    {:ok, value}
  end

  def cast_input(value, _constraints) when is_binary(value) do
    decode(value)
  end

  def cast_input(_, _), do: :error

  @impl Ash.Type
  def cast_stored(value, _constraints) when is_binary(value) do
    decode(value)
  end

  def cast_stored(nil, _constraints), do: {:ok, nil}
  def cast_stored(_, _), do: :error

  @impl Ash.Type
  def dump_to_native(value, _constraints) when is_map(value) do
    encode(value)
  end

  def dump_to_native(nil, _constraints), do: {:ok, nil}
  def dump_to_native(_, _), do: :error

  @impl Ash.Type
  def storage_type(_constraints) do
    :binary
  end

  # # #
  # Private functions
  # # #

  defp decode(value) do
    case CBOR.decode(value) do
      {:ok, decoded_value, ""} -> {:ok, decoded_value}
      {:ok, _decoded_value, _rest} -> :error
      {:error, _error} -> :error
    end
  end

  defp encode(value) do
    {:ok, CBOR.encode(value)}
  rescue
    Protocol.UndefinedError ->
      :error
  end
end
