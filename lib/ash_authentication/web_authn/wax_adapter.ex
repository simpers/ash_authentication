# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthn.WaxAdapter do
  @moduledoc """
  Default WebAuthn adapter implementation using the `wax_` library.

  This module provides the default adapter that uses the `wax_` library
  for all WebAuthn cryptographic operations.
  """

  @behaviour AshAuthentication.WebAuthn.Adapter

  alias AshAuthentication.WebAuthn.Adapter

  @impl Adapter
  def new_registration_challenge(opts) do
    challenge =
      [
        origin: Keyword.fetch!(opts, :origin),
        rp_id: Keyword.get(opts, :rp_id, :auto),
        attestation: Keyword.get(opts, :attestation, "none"),
        timeout: Keyword.get(opts, :timeout, 20 * 60),
        user_verification: Keyword.get(opts, :user_verification, "preferred")
      ]
      |> Wax.new_registration_challenge()

    {:ok,
     %{
       challenge: challenge.bytes,
       public_key_credential_options: %{
         challenge: challenge.bytes,
         rp: %{
           name: Keyword.get(opts, :rp_name, "Application"),
           id: challenge.rp_id
         },
         user: %{
           id: Keyword.get(opts, :user_id, "user123"),
           name: Keyword.get(opts, :user_name, "user"),
           displayName: Keyword.get(opts, :user_display_name, "User")
         },
         pubKeyCredParams: [
           %{alg: -7, type: "public-key"}
         ],
         timeout: challenge.timeout * 1000,
         attestation: String.to_atom(challenge.attestation)
       }
     }}
  end

  @impl Adapter
  def verify_registration(attestation_object, client_data_json, challenge, opts) do
    wax_challenge =
      Wax.new_registration_challenge(
        origin: Keyword.fetch!(opts, :origin),
        rp_id: Keyword.get(opts, :rp_id, :auto),
        timeout: Keyword.get(opts, :timeout, 20 * 60),
        attestation: Keyword.get(opts, :attestation, "none"),
        user_verification: Keyword.get(opts, :user_verification, "preferred")
      )
      |> Map.put(:bytes, challenge)
      |> Map.put(:issued_at, System.os_time(:second))

    case Wax.register(attestation_object, client_data_json, wax_challenge) do
      {:ok, {authenticator_data, _attestation_result}} ->
        credential_public_key =
          authenticator_data.attested_credential_data.credential_public_key

        {:ok,
         %{
           credential_id: authenticator_data.attested_credential_data.credential_id,
           public_key: credential_public_key,
           sign_count: authenticator_data.sign_count
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl Adapter
  def new_authentication_challenge(credential_ids_and_keys, opts) do
    allow_credentials =
      Enum.map(credential_ids_and_keys, fn {id, _key} ->
        %{type: "public-key", id: id}
      end)

    challenge =
      Wax.new_authentication_challenge(
        allow_credentials: allow_credentials,
        origin: Keyword.fetch!(opts, :origin),
        rp_id: Keyword.get(opts, :rp_id, :auto),
        timeout: Keyword.get(opts, :timeout, 20 * 60),
        user_verification: Keyword.get(opts, :user_verification, "preferred")
      )

    {:ok,
     %{
       challenge: challenge.bytes,
       public_key_credential_options: %{
         challenge: challenge.bytes,
         allowCredentials: allow_credentials,
         rpId: challenge.rp_id,
         timeout: challenge.timeout * 1000,
         userVerification: normalize_user_verification(challenge.user_verification)
       }
     }}
  end

  defp normalize_user_verification(nil), do: nil

  defp normalize_user_verification(user_verification) when is_atom(user_verification),
    do: user_verification

  defp normalize_user_verification(user_verification) when is_binary(user_verification) do
    String.to_atom(user_verification)
  end

  @impl Adapter
  def verify_authentication(
        credential_id,
        authenticator_data,
        client_data_json,
        signature,
        challenge,
        _public_key,
        opts
      ) do
    wax_challenge =
      Wax.new_authentication_challenge(
        origin: Keyword.fetch!(opts, :origin),
        rp_id: Keyword.get(opts, :rp_id, :auto),
        timeout: Keyword.get(opts, :timeout, 20 * 60),
        user_verification: Keyword.get(opts, :user_verification, "preferred")
      )
      |> Map.put(:bytes, challenge)
      |> Map.put(:issued_at, System.os_time(:second))

    case Wax.authenticate(
           credential_id,
           authenticator_data,
           signature,
           client_data_json,
           wax_challenge
         ) do
      {:ok, authenticator_data} ->
        {:ok, %{sign_count: authenticator_data.sign_count}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl Adapter
  def origin_match?(origin, expected_origins) do
    Wax.origins_match?(origin, expected_origins)
  end
end
