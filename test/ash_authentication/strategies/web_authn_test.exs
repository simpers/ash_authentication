# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthnTest do
  @moduledoc false
  use DataCase, async: true

  @moduletag feature: :webauthn

  alias AshAuthentication.{Info, Strategy}

  describe "strategy protocol" do
    setup do
      {:ok, strategy: Info.strategy!(Example.User, :web_authn)}
    end

    test "name/1 returns the strategy name", %{strategy: strategy} do
      assert Strategy.name(strategy) == :web_authn
    end

    test "actions/1 returns all four phases", %{strategy: strategy} do
      assert Strategy.actions(strategy) == [
               :register_begin,
               :register_finish,
               :sign_in_begin,
               :sign_in_finish
             ]
    end

    test "phases/1 returns all four phases", %{strategy: strategy} do
      assert Strategy.phases(strategy) == [
               :register_begin,
               :register_finish,
               :sign_in_begin,
               :sign_in_finish
             ]
    end

    test "routes/1 returns routes for all phases", %{strategy: strategy} do
      routes = Strategy.routes(strategy)

      assert length(routes) == 4
      assert {"/user/web_authn/register_begin", :register_begin} in routes
      assert {"/user/web_authn/register_finish", :register_finish} in routes
      assert {"/user/web_authn/sign_in_begin", :sign_in_begin} in routes
      assert {"/user/web_authn/sign_in_finish", :sign_in_finish} in routes
    end

    test "method_for_phase/2 returns :post for all phases", %{strategy: strategy} do
      assert Strategy.method_for_phase(strategy, :register_begin) == :post
      assert Strategy.method_for_phase(strategy, :register_finish) == :post
      assert Strategy.method_for_phase(strategy, :sign_in_begin) == :post
      assert Strategy.method_for_phase(strategy, :sign_in_finish) == :post
    end

    test "tokens_required?/1 returns true", %{strategy: strategy} do
      assert Strategy.tokens_required?(strategy) == true
    end
  end

  describe "transformer" do
    test "sets default action names based on strategy name" do
      strategy = Info.strategy!(Example.User, :web_authn)

      assert strategy.register_begin_action_name == :register_begin_with_web_authn
      assert strategy.register_finish_action_name == :register_finish_with_web_authn
      assert strategy.sign_in_begin_action_name == :sign_in_begin_with_web_authn
      assert strategy.sign_in_finish_action_name == :sign_in_finish_with_web_authn
    end

    test "strategy has correct configuration from DSL" do
      strategy = Info.strategy!(Example.User, :web_authn)

      assert strategy.key_resource == Example.WebAuthnKey
      assert strategy.relying_party == "example.com"
      assert strategy.require_identity? == false
      assert strategy.resource == Example.User
    end
  end

  describe "actions (stubs)" do
    setup do
      {:ok, strategy: Info.strategy!(Example.User, :web_authn)}
    end

    test "register_begin returns :not_implemented", %{strategy: strategy} do
      assert {:error, :not_implemented} =
               Strategy.action(strategy, :register_begin, %{}, [])
    end

    test "register_finish returns :not_implemented", %{strategy: strategy} do
      assert {:error, :not_implemented} =
               Strategy.action(strategy, :register_finish, %{}, [])
    end

    test "sign_in_begin returns :not_implemented", %{strategy: strategy} do
      assert {:error, :not_implemented} =
               Strategy.action(strategy, :sign_in_begin, %{}, [])
    end

    test "sign_in_finish returns :not_implemented", %{strategy: strategy} do
      assert {:error, :not_implemented} =
               Strategy.action(strategy, :sign_in_finish, %{}, [])
    end
  end
end
