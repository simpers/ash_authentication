# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthn.AdapterTest do
  @moduledoc false

  use ExUnit.Case, async: true

  @moduletag feature: :webauthn

  alias AshAuthentication.WebAuthn.Adapter
  alias AshAuthentication.WebAuthn.WaxAdapter

  describe "Adapter behaviour" do
    test "WaxAdapter implements the Adapter behaviour" do
      # Verify that WaxAdapter has the @behaviour attribute set to Adapter
      WaxAdapter.module_info(:attributes)
      |> Enum.any?(fn
        {:behaviour, [Adapter]} -> true
        _ -> false
      end)
      |> assert()
    end
  end

  describe "origin_match?/2" do
    test "matches exact origin" do
      assert WaxAdapter.origin_match?("https://example.com", ["https://example.com"]) == true
    end

    test "does not match different origin" do
      assert WaxAdapter.origin_match?("https://evil.com", ["https://example.com"]) == false
    end

    test "matches when origin is in list" do
      assert WaxAdapter.origin_match?("https://www.example.com", [
               "https://example.com",
               "https://www.example.com"
             ]) == true
    end
  end

  describe "new_registration_challenge/1" do
    test "returns challenge and options" do
      opts = [
        origin: "https://example.com",
        rp_name: "Example App",
        rp_id: "example.com",
        user_id: "user123",
        user_name: "test@example.com",
        user_display_name: "Test User"
      ]

      assert {:ok, result} = WaxAdapter.new_registration_challenge(opts)

      assert is_binary(result.challenge)
      assert byte_size(result.challenge) > 0

      assert result.public_key_credential_options.challenge == result.challenge
      assert result.public_key_credential_options.rp.name == "Example App"
      assert result.public_key_credential_options.rp.id == "example.com"
      assert result.public_key_credential_options.user.id == "user123"
      assert result.public_key_credential_options.user.name == "test@example.com"
      assert result.public_key_credential_options.user.displayName == "Test User"

      assert result.public_key_credential_options.pubKeyCredParams == [
               %{alg: -7, type: "public-key"}
             ]
    end

    test "uses default rp_name when not specified" do
      opts = [
        origin: "https://www.example.com",
        rp_id: "www.example.com"
      ]

      assert {:ok, result} = WaxAdapter.new_registration_challenge(opts)

      assert result.public_key_credential_options.rp.name == "Application"
    end

    test "uses auto rp_id when not specified" do
      opts = [
        origin: "https://www.example.com"
      ]

      assert {:ok, result} = WaxAdapter.new_registration_challenge(opts)

      assert result.public_key_credential_options.rp.id == "www.example.com"
    end
  end

  describe "new_authentication_challenge/2" do
    test "returns challenge with allowCredentials" do
      credential_ids_and_keys = [
        {"cred_id_1", %{1 => 2, 3 => -7}},
        {"cred_id_2", %{1 => 2, 3 => -7}}
      ]

      opts = [
        origin: "https://example.com",
        rp_id: "example.com"
      ]

      assert {:ok, result} =
               WaxAdapter.new_authentication_challenge(credential_ids_and_keys, opts)

      assert is_binary(result.challenge)
      assert byte_size(result.challenge) > 0

      assert result.public_key_credential_options.challenge == result.challenge
      assert result.public_key_credential_options.rpId == "example.com"

      assert length(result.public_key_credential_options.allowCredentials) == 2

      assert Enum.any?(result.public_key_credential_options.allowCredentials, fn cred ->
               cred.id == "cred_id_1" and cred.type == "public-key"
             end)

      assert Enum.any?(result.public_key_credential_options.allowCredentials, fn cred ->
               cred.id == "cred_id_2" and cred.type == "public-key"
             end)
    end

    test "returns empty allowCredentials for discoverable credentials" do
      opts = [
        origin: "https://example.com",
        rp_id: "example.com"
      ]

      assert {:ok, result} = WaxAdapter.new_authentication_challenge([], opts)

      assert result.public_key_credential_options.allowCredentials == []
    end
  end
end
