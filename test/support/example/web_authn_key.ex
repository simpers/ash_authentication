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

  attributes do
    uuid_v7_primary_key :id
  end

  relationships do
    belongs_to :user, Example.UserWithWebAuthn
  end

  postgres do
    repo(Example.Repo)
    table "user_webauthn_keys"
  end
end
