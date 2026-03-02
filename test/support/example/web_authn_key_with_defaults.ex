# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.WebAuthnKeyWithDefaults do
  @moduledoc false

  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.WebAuthnKey]

  web_authn_key do
    user_resource Example.UserWithWebAuthnWithDefaults
  end

  attributes do
    uuid_v7_primary_key :id
    attribute :name, :string
  end

  postgres do
    repo(Example.Repo)
    table "user_webauthn_keys"
  end
end
