# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnKey.Transformer do
  @moduledoc false

  use Spark.Dsl.Transformer

  alias Spark.Dsl.Transformer

  @type step_return() :: {:ok, map()} | {:error, any()}

  @doc false
  @impl Transformer
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    maybe_define_relationship(dsl_state)
  end

  @spec maybe_define_foreign_key(dsl_state :: map()) :: step_return()
  def maybe_define_foreign_key(dsl_state) do
    # Transformer.get_persisted(dsl_state)
    {:ok, dsl_state}
  end

  @spec maybe_define_relationship(dsl_state :: map()) :: step_return()
  def maybe_define_relationship(dsl_state) do
    case get_option(dsl_state, [:web_authn_key], :user_resource) do
      nil ->
        {:error, CompileError,
         description: "the required key `:user_resource` was found to be `nil`!"}

      _user_resource ->
        get_entities(dsl_state, [:relationships])
        {:ok, dsl_state}
    end
  end

  # # #
  # ! Private functions
  # # #

  defp get_entities(state, path) do
    Transformer.get_entities(state, path)
  end

  defp get_option(state, section_path, name) do
    Transformer.get_option(state, section_path, name)
  end
end
