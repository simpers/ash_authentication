# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Transformer do
  @moduledoc false

  import AshAuthentication.Strategy.Custom.Helpers
  import AshAuthentication.Utils
  import AshAuthentication.Validations.Action

  alias Ash.Resource
  alias Ash.Resource.Change.Builtins
  alias AshAuthentication.WebAuthnKey
  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError

  alias AshAuthentication.SetAshAuthenticationContextChange
  alias AshAuthentication.Strategy.WebAuthn

  @web_authn_key_argument :web_authn_key

  @doc false
  @spec transform(WebAuthn.t(), dsl_state) ::
          {:ok, WebAuthn.t() | dsl_state} | {:error, any()}
        when dsl_state: map()
  def transform(strategy, dsl_state) do
    strategy =
      strategy
      |> maybe_set_register_action_name()
      |> maybe_set_register_begin_action_name()
      |> maybe_set_register_finish_action_name()
      |> maybe_set_sign_in_begin_action_name()
      |> maybe_set_sign_in_finish_action_name()

    with {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.register_action_name,
             &build_register_action(&1, strategy)
           ),
         :ok <- validate_register_action(dsl_state, strategy) do
      action_names = [
        strategy.register_begin_action_name,
        strategy.register_finish_action_name,
        strategy.sign_in_begin_action_name,
        strategy.sign_in_finish_action_name
      ]

      dsl_state =
        action_names
        |> register_strategy_actions(dsl_state, strategy)
        |> put_strategy(strategy)

      {:ok, dsl_state}
    end
  end

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_set_register_action_name(strategy)
       when is_nil(strategy.register_action_name),
       do: %{strategy | register_action_name: :"register_with_#{strategy.name}"}

  defp maybe_set_register_action_name(strategy), do: strategy

  defp build_register_action(dsl_state, strategy) do
    with {:ok, relationship_name} <- web_authn_keys_relationship_name(dsl_state, strategy),
         {:ok, upsert_action_name} <-
           WebAuthnKey.Info.web_authn_key_upsert_action_name(strategy.key_resource) do
      argument =
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
          name: @web_authn_key_argument,
          type: :map,
          allow_nil?: false
        )

      changes = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
          change: SetAshAuthenticationContextChange,
          description:
            "Set AshAuthentication private context so policy bypass checks can authorize registration."
        ),
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
          change:
            Builtins.manage_relationship(
              @web_authn_key_argument,
              relationship_name,
              type: :create,
              on_no_match: {:create, upsert_action_name},
              error_path: @web_authn_key_argument
            ),
          description:
            "Persist the verified WebAuthn key via the user relationship in the same action."
        )
      ]

      Transformer.build_entity(Resource.Dsl, [:actions], :create,
        name: strategy.register_action_name,
        accept: :*,
        arguments: [argument],
        changes: changes
      )
    end
  end

  defp validate_register_action(dsl_state, strategy) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.register_action_name) do
      with :ok <- validate_action_option(action, :type, [:create]),
           :ok <- validate_action_has_change(action, SetAshAuthenticationContextChange),
           :ok <- validate_action_has_argument(action, @web_authn_key_argument),
           :ok <-
             validate_action_argument_option(action, @web_authn_key_argument, :allow_nil?, [false]),
           :ok <-
             validate_action_argument_option(action, @web_authn_key_argument, :type, [
               :map,
               Ash.Type.Map
             ]) do
        validate_action_has_change(action, Ash.Resource.Change.ManageRelationship)
      end
    end
  end

  defp web_authn_keys_relationship_name(dsl_state, strategy) do
    dsl_state
    |> Resource.Info.relationships()
    |> Enum.find(&(&1.type == :has_many and &1.destination == strategy.key_resource))
    |> case do
      nil ->
        {:error,
         DslError.exception(
           path: [:relationships],
           message:
             "Expected a has_many relationship from #{inspect(strategy.resource)} to #{inspect(strategy.key_resource)} for WebAuthn registration."
         )}

      relationship ->
        {:ok, relationship.name}
    end
  end

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_set_register_begin_action_name(strategy)
       when is_nil(strategy.register_begin_action_name),
       do: %{strategy | register_begin_action_name: :"register_begin_with_#{strategy.name}"}

  defp maybe_set_register_begin_action_name(strategy), do: strategy

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_set_register_finish_action_name(strategy)
       when is_nil(strategy.register_finish_action_name),
       do: %{strategy | register_finish_action_name: :"register_finish_with_#{strategy.name}"}

  defp maybe_set_register_finish_action_name(strategy), do: strategy

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_set_sign_in_begin_action_name(strategy)
       when is_nil(strategy.sign_in_begin_action_name),
       do: %{strategy | sign_in_begin_action_name: :"sign_in_begin_with_#{strategy.name}"}

  defp maybe_set_sign_in_begin_action_name(strategy), do: strategy

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_set_sign_in_finish_action_name(strategy)
       when is_nil(strategy.sign_in_finish_action_name),
       do: %{strategy | sign_in_finish_action_name: :"sign_in_finish_with_#{strategy.name}"}

  defp maybe_set_sign_in_finish_action_name(strategy), do: strategy
end
