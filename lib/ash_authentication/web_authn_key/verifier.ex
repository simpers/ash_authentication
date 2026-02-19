# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnKey.Verifier do
  @moduledoc false

  use Spark.Dsl.Transformer

  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError

  @doc false
  @impl Transformer
  @spec after?(any()) :: boolean()
  def after?(_), do: true

  @doc false
  @impl Transformer
  @spec before?(any()) :: boolean()
  def before?(_), do: false

  @doc false
  @impl Transformer
  @spec after_compile?() :: boolean()
  def after_compile?, do: true

  @doc false
  @impl Transformer
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with :ok <- verify_cbor_dependency() do
      {:ok, dsl_state}
    end
  end

  defp verify_cbor_dependency do
    if Code.ensure_loaded?(:cbor) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:web_authn_key],
         message: """
         The :cbor dependency is required for WebAuthn support.

         Add it to your dependencies in mix.exs:

             {:cbor, "~> 1.0"}
         """
       )}
    end
  end
end
