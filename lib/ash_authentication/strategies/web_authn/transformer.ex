# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Transformer do
  @moduledoc false

  import AshAuthentication.Strategy.Custom.Helpers

  alias AshAuthentication.Strategy.WebAuthn

  @doc false
  @spec transform(WebAuthn.t(), dsl_state) ::
          {:ok, WebAuthn.t() | dsl_state} | {:error, any()}
        when dsl_state: map()
  def transform(strategy, dsl_state) do
    strategy =
      strategy
      |> maybe_set_register_begin_action_name()
      |> maybe_set_register_finish_action_name()
      |> maybe_set_sign_in_begin_action_name()
      |> maybe_set_sign_in_finish_action_name()

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
