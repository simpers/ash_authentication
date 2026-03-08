# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.TransformerTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.Info
  alias AshAuthentication.SetAshAuthenticationContextChange
  alias AshAuthentication.Validations.Action
  alias Ash.Resource

  @moduletag feature: :webauthn

  describe "default action names" do
    test "it sets all four begin/finish action names" do
      assert {:ok, strategy} = Info.strategy(Example.UserWithWebAuthnWithDefaults, :web_authn)

      assert strategy.register_action_name == :register_with_web_authn
      assert strategy.register_begin_action_name == :register_begin_with_web_authn
      assert strategy.register_finish_action_name == :register_finish_with_web_authn
      assert strategy.sign_in_begin_action_name == :sign_in_begin_with_web_authn
      assert strategy.sign_in_finish_action_name == :sign_in_finish_with_web_authn
    end

    test "it ensures register action includes authentication context change" do
      assert {:ok, strategy} = Info.strategy(Example.UserWithWebAuthnWithDefaults, :web_authn)

      assert %{name: action_name} =
               action =
               Resource.Info.action(strategy.resource, strategy.register_action_name)

      assert action_name == strategy.register_action_name
      assert :ok = Action.validate_action_has_change(action, SetAshAuthenticationContextChange)

      assert :ok =
               Action.validate_action_has_change(action, Ash.Resource.Change.ManageRelationship)

      assert :ok = Action.validate_action_has_argument(action, :web_authn_key)

      assert :ok =
               Action.validate_action_argument_option(action, :web_authn_key, :allow_nil?, [false])

      assert :ok =
               Action.validate_action_argument_option(action, :web_authn_key, :type, [
                 :map,
                 Ash.Type.Map
               ])
    end
  end
end
