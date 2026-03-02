# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithWebAuthnWithRequiredIdentity do
  @moduledoc false

  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication]

  attributes do
    uuid_primary_key :id, writable?: true
    timestamps()

    attribute :email, :ci_string,
      allow_nil?: false,
      public?: true
  end

  authentication do
    tokens do
      enabled? true
      store_all_tokens? true
      require_token_presence_for_authentication? true
      token_resource Example.Token
      signing_secret &Example.UserWithWebAuthnWithDefaults.get_config/2
    end

    add_ons do
      log_out_everywhere()
    end

    strategies do
      web_authn do
        key_resource Example.WebAuthnKeyWithRequiredIdentity
        relying_party Example.UserWithWebAuthnWithDefaults.Secret
        require_identity? true
      end
    end
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end

  identities do
    identity :email, [:email]
  end

  relationships do
    has_many :web_authn_keys, Example.WebAuthnKeyWithRequiredIdentity do
      destination_attribute :user_id
    end
  end

  postgres do
    table "user_with_web_authn"
    repo(Example.Repo)
  end
end
