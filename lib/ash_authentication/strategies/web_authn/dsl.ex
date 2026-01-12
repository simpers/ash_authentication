# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.WebAuthn
  alias Spark.Dsl.Entity

  @schema [
    name: [
      type: :atom,
      doc: "Uniquely identifies the strategy.",
      required: true
    ],
    key_resource: [
      type: :atom,
      doc: "The WebAuthn key resource used to store credentials."
    ],
    relying_party: [
      type: :string,
      doc: "The WebAuthn Relying Party identifier (typically your domain name).",
      required: true
    ],
    require_identity?: [
      type: :boolean,
      doc: """
      Whether or not an identity (e.g. an email or username) is required for sign-in,
      or if the credential itself will be used to identify the user (discoverable credentials).
      """,
      default: false
    ],
    resource: [
      type: :atom,
      doc: "The user resource that the strategy is targeting."
    ],
    register_begin_action_name: [
      type: :atom,
      doc:
        "The name to use for the register begin action. Defaults to `register_begin_with_<strategy_name>`."
    ],
    register_finish_action_name: [
      type: :atom,
      doc:
        "The name to use for the register finish action. Defaults to `register_finish_with_<strategy_name>`."
    ],
    sign_in_begin_action_name: [
      type: :atom,
      doc:
        "The name to use for the sign-in begin action. Defaults to `sign_in_begin_with_<strategy_name>`."
    ],
    sign_in_finish_action_name: [
      type: :atom,
      doc:
        "The name to use for the sign-in finish action. Defaults to `sign_in_finish_with_<strategy_name>`."
    ]
  ]

  @doc false
  @spec dsl() :: map()
  def dsl do
    %Entity{
      name: :web_authn,
      describe: "Strategy for authentication using WebAuthn (passkeys)",
      args: [{:optional, :name, :web_authn}],
      hide: [:name],
      target: WebAuthn,
      schema: @schema
    }
  end
end
