# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.WebAuthnKey do
  @moduledoc false

  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.WebAuthnKey]

  web_authn_key do
    user_resource Example.UserWithWebAuthn
  end

  actions do
    defaults [:read, :destroy]

    create :upsert do
      primary? true
      upsert? true
      upsert_identity :unique_credential_id

      accept [
        :credential_id,
        :public_key,
        :sign_count,
        :user_id,
        :aaguid,
        :transports,
        :last_used_at
      ]
    end
  end

  attributes do
    uuid_v7_primary_key :id

    attribute :credential_id, :binary, allow_nil?: false, sensitive?: true
    attribute :public_key, AshAuthentication.Type.CoseKey, allow_nil?: false, sensitive?: true
    attribute :sign_count, :integer, allow_nil?: false, default: 0
    attribute :aaguid, :binary
    attribute :transports, {:array, :string}
    attribute :last_used_at, :utc_datetime_usec
    attribute :user_id, :uuid, allow_nil?: false
  end

  relationships do
    belongs_to :user, Example.UserWithWebAuthn
  end

  postgres do
    repo(Example.Repo)
    table "user_webauthn_keys"
  end
end
