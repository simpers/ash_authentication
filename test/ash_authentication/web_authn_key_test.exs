# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnKeyTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias Ash.Resource.Info

  @moduletag feature: :webauthn

  test "key extension injects required attributes, relationship, identity, and actions" do
    resource = Example.WebAuthnKeyWithDefaults

    assert Info.attribute(resource, :credential_id)
    assert Info.attribute(resource, :public_key)
    assert Info.attribute(resource, :sign_count)
    assert Info.attribute(resource, :aaguid)
    assert Info.attribute(resource, :transports)
    assert Info.attribute(resource, :last_used_at)
    assert Info.attribute(resource, :user_id)

    relationship = Enum.find(Info.relationships(resource), &(&1.name == :user))
    assert relationship
    assert relationship.type == :belongs_to
    assert relationship.destination == Example.UserWithWebAuthnWithDefaults

    identity = Enum.find(Info.identities(resource), &(&1.name == :unique_credential_id))
    assert identity
    assert :credential_id in identity.keys

    read_action = Info.action(resource, :read)
    assert read_action
    assert read_action.type == :read

    primary_read_action = Info.primary_action(resource, :read)
    assert primary_read_action
    assert primary_read_action.name == :read

    destroy_action = Info.action(resource, :destroy)
    assert destroy_action
    assert destroy_action.type == :destroy

    upsert_action = Info.action(resource, :upsert)
    assert upsert_action
    assert upsert_action.type == :create
    assert upsert_action.upsert?
    assert upsert_action.upsert_identity == :unique_credential_id

    for field <- [:credential_id, :public_key, :sign_count, :user_id] do
      assert field in upsert_action.accept
    end
  end
end
