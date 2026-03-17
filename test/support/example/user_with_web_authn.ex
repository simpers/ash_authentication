# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithWebAuthn do
  @moduledoc false

  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  require Logger

  attributes do
    uuid_primary_key :id, writable?: true
    timestamps()

    attribute :email, :ci_string, allow_nil?: false, public?: true
  end

  authentication do
    tokens do
      enabled? true
      store_all_tokens? true
      require_token_presence_for_authentication? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    add_ons do
      log_out_everywhere()
    end

    strategies do
      web_authn do
        key_resource Example.WebAuthnKey
        relying_party "example.com"
        require_identity? false
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
    has_many :web_authn_keys, Example.WebAuthnKey do
      destination_attribute :user_id
    end
  end

  postgres do
    table "user_with_web_authn"
    repo(Example.Repo)
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
