# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.TransformerTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.Info

  @moduletag feature: :webauthn

  describe "default action names" do
    test "it sets all four begin/finish action names" do
      assert {:ok, strategy} = Info.strategy(Example.UserWithWebAuthn, :web_authn)

      assert strategy.register_begin_action_name == :register_begin_with_web_authn
      assert strategy.register_finish_action_name == :register_finish_with_web_authn
      assert strategy.sign_in_begin_action_name == :sign_in_begin_with_web_authn
      assert strategy.sign_in_finish_action_name == :sign_in_finish_with_web_authn
    end
  end
end
