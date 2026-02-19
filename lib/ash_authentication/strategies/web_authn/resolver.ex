# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Resolver do
  @moduledoc false

  import AshAuthentication.Plug.Helpers, only: [origin_from_http_request: 1]
  import AshAuthentication.WebAuthn.Utils

  alias AshAuthentication.Strategy.WebAuthn

  @spec resolve_origin_for_begin(WebAuthn.t(), map(), map()) ::
          {:ok, String.t()} | {:error, String.t()}
  def resolve_origin_for_begin(strategy, webauthn_options, context) do
    # Begin phase resolves values from configuration/request context.
    # These resolved values are then persisted in the state token.
    origin =
      fetch_param(webauthn_options, "origin") ||
        fetch_origin_secret(strategy, context) ||
        origin_from_http_request(context)

    require_binary(origin, "Missing WebAuthn origin")
  end

  @spec resolve_rp_id_for_begin(WebAuthn.t(), map(), map()) ::
          {:ok, String.t()} | {:error, String.t()}
  def resolve_rp_id_for_begin(strategy, webauthn_options, context) do
    rp_id =
      fetch_param(webauthn_options, "rp_id") ||
        fetch_param(webauthn_options, "relying_party") ||
        fetch_relying_party_secret(strategy, context)

    require_binary(rp_id, "Missing WebAuthn relying party id")
  end

  @spec resolve_origin_from_request(map()) :: {:ok, String.t()} | {:error, String.t()}
  def resolve_origin_from_request(claims) do
    # Finish phase must resolve from the request/state token only.
    # No configuration lookup should happen at finish time.
    claims
    |> fetch_param("origin")
    |> require_binary("Missing origin in state token")
  end

  @spec resolve_rp_id_from_request(map()) :: {:ok, String.t()} | {:error, String.t()}
  def resolve_rp_id_from_request(claims) do
    claims
    |> fetch_param("rp_id")
    |> require_binary("Missing relying party id in state token")
  end

  defp fetch_param(map, key) when is_map(map) and is_binary(key) do
    Map.get(map, key) || Map.get(map, String.to_existing_atom(key))
  rescue
    ArgumentError ->
      Map.get(map, key)
  end

  defp fetch_param(map, key) when is_map(map) and is_atom(key) do
    Map.get(map, key) || Map.get(map, Atom.to_string(key))
  end

  defp fetch_param(_, _), do: nil

  defp require_binary(value, _message) when is_binary(value), do: {:ok, value}
  defp require_binary(_, message), do: {:error, message}
end
