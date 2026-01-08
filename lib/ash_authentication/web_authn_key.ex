# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnKey do
  @moduledoc false

  @dsl [
    %Spark.Dsl.Section{
      name: :web_authn_key,
      describe: "Configure WebAuthn options for this resource",
      no_depend_modules: [:domain, :user_resource],
      schema: [
        domain: [
          type: {:behaviour, Ash.Domain},
          doc: "The Ash domain to use to access this resource.",
          required: false
        ],
        user_resource: [
          type: {:behaviour, Ash.Resource},
          doc: "The user resource to which these identities belong.",
          required: true
        ],
        uid_attribute_name: [
          type: :atom,
          doc: "The name of the `uid` attribute on this resource.",
          default: :uid
        ],
        key_attribute_name: [
          type: :atom,
          doc: "The name of the `key` attribute on this resource.",
          default: :key
        ],
        strategy_attribute_name: [
          type: :atom,
          doc: "The name of the `strategy` attribute on this resource.",
          default: :strategy
        ],
        user_id_attribute_name: [
          type: :atom,
          doc: "The name of the `user_id` attribute on this resource.",
          default: :user_id
        ],
        upsert_action_name: [
          type: :atom,
          doc: "The name of the action used to create and update records.",
          default: :upsert
        ],
        destroy_action_name: [
          type: :atom,
          doc: "The name of the action used to destroy records.",
          default: :destroy
        ],
        read_action_name: [
          type: :atom,
          doc: "The name of the action used to query identities.",
          default: :read
        ],
        user_relationship_name: [
          type: :atom,
          doc: "The name of the belongs-to relationship between WebAUthn keys and users.",
          default: :user
        ]
      ]
    }
  ]

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [
      AshAuthentication.WebAuthnKey.Transformer,
      AshAuthentication.WebAuthnKey.Verifier
    ]
end
