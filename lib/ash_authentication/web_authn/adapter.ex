# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthn.Adapter do
  @moduledoc """
  Behaviour for WebAuthn adapter implementations.

  This module defines the interface for WebAuthn operations, allowing
  the strategy to work with different underlying implementations while
  maintaining a consistent API.

  The default implementation uses the `wax_` library.
  """

  @typedoc """
  Options passed to adapter callbacks.
  """
  @type opts :: keyword()

  @typedoc """
  A COSE key as a map.
  """
  @type cose_key :: map()

  @typedoc """
  A credential ID (binary).
  """
  @type credential_id :: binary()

  @typedoc """
  Result of a registration challenge.
  """
  @type registration_challenge :: %{
          challenge: binary(),
          public_key_credential_options: map()
        }

  @typedoc """
  Result of a successful registration verification.
  """
  @type registration_result :: %{
          credential_id: credential_id(),
          public_key: cose_key(),
          sign_count: non_neg_integer()
        }

  @typedoc """
  Result of an authentication challenge.
  """
  @type authentication_challenge :: %{
          challenge: binary(),
          public_key_credential_options: map()
        }

  @typedoc """
  Result of a successful authentication verification.
  """
  @type authentication_result :: %{
          sign_count: non_neg_integer()
        }

  @doc """
  Generate a new registration challenge.

  This creates a challenge that should be sent to the browser's
  WebAuthn API for credential registration.
  """
  @callback new_registration_challenge(opts :: opts()) ::
              {:ok, registration_challenge()} | {:error, term()}

  @doc """
  Verify a registration response from the browser.

  Takes the attestation object and client data JSON from the browser's
  WebAuthn API response, along with the original challenge.
  """
  @callback verify_registration(
              attestation_object :: binary(),
              client_data_json :: binary(),
              challenge :: binary(),
              opts :: opts()
            ) :: {:ok, registration_result()} | {:error, term()}

  @doc """
  Generate a new authentication challenge.

  Takes a list of credential IDs and their public keys to include in
  the allowCredentials list.
  """
  @callback new_authentication_challenge(
              credential_ids_and_keys :: [{credential_id(), cose_key()}],
              opts :: opts()
            ) :: {:ok, authentication_challenge()} | {:error, term()}

  @doc """
  Verify an authentication response from the browser.

  Takes the assertion data from the browser's WebAuthn API response,
  along with the original challenge and the credential's public key.
  """
  @callback verify_authentication(
              credential_id :: credential_id(),
              authenticator_data :: binary(),
              client_data_json :: binary(),
              signature :: binary(),
              challenge :: binary(),
              public_key :: cose_key(),
              opts :: opts()
            ) :: {:ok, authentication_result()} | {:error, term()}

  @doc """
  Verify that an origin matches expected origins.

  Used to validate that the client data origin matches what we expect.
  """
  @callback origin_match?(origin :: String.t(), expected_origins :: [String.t()]) ::
              boolean()
end
