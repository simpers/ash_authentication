# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.StrategyTest do
  @moduledoc false

  use ExUnit.Case, async: true

  @moduletag feature: :webauthn

  use Mimic

  alias AshAuthentication.{Info, Strategy, Strategy.WebAuthn}

  import Plug.Test

  describe "Strategy.phases/1" do
    test "it returns all four begin/finish phases" do
      phases = Strategy.phases(%WebAuthn{})
      assert phases == [:register_begin, :register_finish, :sign_in_begin, :sign_in_finish]
    end
  end

  describe "Strategy.actions/1" do
    test "it returns all four begin/finish actions" do
      actions = Strategy.actions(%WebAuthn{})
      assert actions == [:register_begin, :register_finish, :sign_in_begin, :sign_in_finish]
    end
  end

  describe "Strategy.routes/1" do
    test "it returns routes for all four phases" do
      assert {:ok, strategy} = Info.strategy(Example.User, :web_authn)

      assert Strategy.routes(strategy) == [
               {"/user/web_authn/register_begin", :register_begin},
               {"/user/web_authn/register_finish", :register_finish},
               {"/user/web_authn/sign_in_begin", :sign_in_begin},
               {"/user/web_authn/sign_in_finish", :sign_in_finish}
             ]
    end
  end

  describe "Strategy.plug/3" do
    for phase <- [:register_begin, :register_finish, :sign_in_begin, :sign_in_finish] do
      test "it delegates to `WebAuthn.Plug.#{phase}/2`" do
        conn = conn(:get, "/")
        strategy = %WebAuthn{}

        WebAuthn.Plug
        |> expect(unquote(phase), fn rx_conn, rx_strategy ->
          assert rx_conn == conn
          assert rx_strategy == strategy

          conn
        end)

        Strategy.plug(strategy, unquote(phase), conn)
      end
    end
  end
end
