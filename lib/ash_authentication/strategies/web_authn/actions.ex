# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Actions do
  @moduledoc """
  Action handlers for the WebAuthn strategy.
  """

  require Logger

  require Ash.Query

  import Ash.Expr

  alias Ash.Changeset
  alias Ash.Query
  alias Ash.Resource
  alias AshAuthentication.Errors
  alias AshAuthentication.Info
  alias AshAuthentication.Jwt
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Resolver
  alias AshAuthentication.WebAuthnKey

  @state_token_lifetime {5, :minutes}

  @doc """
  Begin the registration process.

  Returns options for the browser's WebAuthn API along with a signed state token.
  """
  @spec register_begin(WebAuthn.t(), map(), keyword()) ::
          {:ok, Resource.record()} | {:error, any()}
  def register_begin(strategy, params, options) do
    {context, _options} = Keyword.pop(options, :context, %{})

    strategy
    |> begin_context(params, context)
    |> case do
      {:ok, %{webauthn_options: webauthn_options, origin: origin, rp_id: rp_id}} ->
        with {:ok, %{challenge: challenge, public_key_credential_options: public_key}} <-
               adapter().new_registration_challenge(
                 adapter_opts(
                   strategy,
                   webauthn_options,
                   origin,
                   rp_id,
                   params,
                   :register
                 )
               ),
             {:ok, state_token} <-
               build_state_token(
                 strategy,
                 "webauthn_register",
                 challenge,
                 origin,
                 rp_id,
                 context
               ) do
          public_key =
            public_key
            |> ensure_pub_key_params()
            |> put_authenticator_selection(webauthn_options)
            |> put_user_verification(webauthn_options, :register)
            |> encode_public_key_options()

          {:ok, %{public_key: public_key, state_token: state_token}}
        end

      other ->
        other
    end
    |> wrap_auth_error(strategy)
  end

  @doc """
  Complete the registration process.

  Verifies the browser's response and persists the credential.
  """
  @spec register_finish(WebAuthn.t(), map(), keyword()) ::
          {:ok, Resource.record()} | {:error, any()}
  def register_finish(strategy, params, options) do
    {context, options} = Keyword.pop(options, :context, %{})
    options = Keyword.put_new_lazy(options, :domain, fn -> Info.domain!(strategy.resource) end)

    result =
      with {:ok, finish_context} <- registration_finish_context(strategy, params, context),
           {:ok, %{credential_id: credential_id, public_key: public_key, sign_count: sign_count}} <-
             adapter().verify_registration(
               finish_context.attestation_object,
               finish_context.client_data_json,
               decode_base64url!(finish_context.claims["challenge"]),
               adapter_verify_opts(
                 strategy,
                 finish_context.claims,
                 finish_context.origin,
                 finish_context.rp_id
               )
             ),
           {:ok, user} <- create_user(strategy, params, options),
           {:ok, _key} <-
             upsert_key(strategy, user, credential_id, public_key, sign_count, options),
           {:ok, token, _claims} <- Jwt.token_for_user(user, %{}, [], context) do
        {:ok, Resource.put_metadata(user, :token, token)}
      end

    wrap_finish_error(strategy, result, :registration)
  end

  @doc """
  Begin the sign-in process.

  Returns options for the browser's WebAuthn API along with a signed state token.
  """
  @spec sign_in_begin(WebAuthn.t(), map(), keyword()) ::
          {:ok, Resource.record()} | {:error, any()}
  def sign_in_begin(strategy, params, options) do
    {context, _options} = Keyword.pop(options, :context, %{})

    strategy
    |> begin_context(params, context)
    |> case do
      {:ok, %{webauthn_options: webauthn_options, origin: origin, rp_id: rp_id}} ->
        with {:ok, %{challenge: challenge, public_key_credential_options: public_key}} <-
               adapter().new_authentication_challenge(
                 [],
                 adapter_opts(strategy, webauthn_options, origin, rp_id, params, :sign_in)
               ),
             {:ok, state_token} <-
               build_state_token(strategy, "webauthn_sign_in", challenge, origin, rp_id, context) do
          # Discovery (resident credentials) relies on omitting allowCredentials.
          public_key =
            public_key
            |> Map.delete(:allowCredentials)
            |> Map.delete("allowCredentials")
            |> put_user_verification(webauthn_options, :sign_in)
            |> encode_public_key_options()

          {:ok, %{public_key: public_key, state_token: state_token}}
        end

      other ->
        other
    end
    |> wrap_auth_error(strategy)
  end

  @doc """
  Complete the sign-in process.

  Verifies the browser's response and returns the authenticated user.
  """
  @spec sign_in_finish(WebAuthn.t(), map(), keyword()) ::
          {:ok, Resource.record()} | {:error, any()}
  def sign_in_finish(strategy, params, options) do
    {context, options} = Keyword.pop(options, :context, %{})
    options = Keyword.put_new_lazy(options, :domain, fn -> Info.domain!(strategy.resource) end)

    result =
      with {:ok, finish_context} <- sign_in_finish_context(strategy, params, context),
           {:ok,
            %{
              credential_id: credential_id,
              authenticator_data: authenticator_data,
              client_data_json: client_data_json,
              signature: signature
            }} <- decode_authentication_credential(finish_context.credential),
           {:ok, key} <- fetch_key_by_credential(strategy, credential_id, options),
           {:ok, %{sign_count: sign_count}} <-
             adapter().verify_authentication(
               key.public_key,
               authenticator_data,
               client_data_json,
               signature,
               decode_base64url!(finish_context.claims["challenge"]),
               adapter_verify_opts(
                 strategy,
                 finish_context.claims,
                 finish_context.origin,
                 finish_context.rp_id
               )
             ),
           {:ok, _key} <- maybe_update_key(key, sign_count, options),
           {:ok, user} <- load_user_from_key(strategy, key, options),
           {:ok, token, _claims} <- Jwt.token_for_user(user, %{}, [], context) do
        {:ok, Resource.put_metadata(user, :token, token)}
      end

    wrap_finish_error(strategy, result, :sign_in)
  end

  defp adapter do
    Application.get_env(
      :ash_authentication,
      :web_authn_adapter,
      AshAuthentication.WebAuthn.WaxAdapter
    )
  end

  defp adapter_opts(_strategy, webauthn_options, origin, rp_id, params, phase) do
    identity = fetch_param(params, "identity") || "user"
    display_name = fetch_param(params, "display_name") || identity || "User"

    base = [
      origin: origin,
      rp_id: rp_id,
      user_verification:
        normalize_enum(fetch_param(webauthn_options, "user_verification"), [
          "required",
          "preferred",
          "discouraged"
        ])
    ]

    base = maybe_put_option(base, :attestation, fetch_param(webauthn_options, "attestation"))

    case phase do
      :register ->
        base ++
          [
            user_id: :crypto.strong_rand_bytes(32),
            user_name: identity || "user",
            user_display_name: display_name || identity || "User"
          ]

      :sign_in ->
        base
    end
  end

  defp build_state_token(strategy, purpose, challenge, origin, rp_id, context) do
    # Store origin/rp_id with the challenge to support multi-tenant deployments
    # where a single server may handle multiple origins or relying parties.
    Jwt.token_for_resource(
      strategy.resource,
      %{
        "purpose" => purpose,
        "challenge" => encode_base64url(challenge),
        "origin" => origin,
        "rp_id" => rp_id
      },
      [token_lifetime: @state_token_lifetime],
      context
    )
    |> case do
      {:ok, token, _claims} -> {:ok, token}
      {:error, error} -> {:error, error}
    end
  end

  defp fetch_webauthn_options(params) do
    # Only the preferred key is supported for new WebAuthn clients.
    fetch_param(params, "webauthn_options") || %{}
  end

  defp verify_state_token(strategy, token, purpose, context) do
    with {:ok, claims, _resource} <- Jwt.verify(token, strategy.resource, [], context),
         ^purpose <- claims["purpose"] do
      {:ok, claims}
    else
      _ -> {:error, "Invalid state token"}
    end
  end

  defp fetch_registration_params(params) do
    credential = fetch_param(params, "credential")
    state_token = fetch_param(params, "state_token")

    if credential && state_token do
      {:ok, %{credential: credential, state_token: state_token}}
    else
      {:error, "Missing registration params"}
    end
  end

  defp fetch_sign_in_params(params) do
    credential = fetch_param(params, "credential")
    state_token = fetch_param(params, "state_token")

    if credential && state_token do
      {:ok, %{credential: credential, state_token: state_token}}
    else
      {:error, "Missing sign in params"}
    end
  end

  defp decode_registration_credential(credential) do
    response = fetch_param(credential, "response") || %{}

    attestation_object =
      fetch_param(response, "attestationObject") || fetch_param(response, "attestation_object")

    client_data_json =
      fetch_param(response, "clientDataJSON") || fetch_param(response, "client_data_json")

    if attestation_object && client_data_json do
      {:ok,
       %{
         attestation_object: decode_base64url!(attestation_object),
         client_data_json: decode_base64url!(client_data_json)
       }}
    else
      {:error, "Invalid registration credential"}
    end
  end

  defp decode_authentication_credential(credential) do
    response = fetch_param(credential, "response") || %{}

    credential_id =
      fetch_param(credential, "rawId") || fetch_param(credential, "raw_id") ||
        fetch_param(credential, "id")

    authenticator_data =
      fetch_param(response, "authenticatorData") ||
        fetch_param(response, "authenticator_data")

    client_data_json =
      fetch_param(response, "clientDataJSON") || fetch_param(response, "client_data_json")

    signature = fetch_param(response, "signature")

    if credential_id && authenticator_data && client_data_json && signature do
      {:ok,
       %{
         credential_id: decode_base64url!(credential_id),
         authenticator_data: decode_base64url!(authenticator_data),
         client_data_json: decode_base64url!(client_data_json),
         signature: decode_base64url!(signature)
       }}
    else
      {:error, "Invalid authentication credential"}
    end
  end

  defp create_user(strategy, params, options) do
    params =
      params
      |> Map.drop([
        "credential",
        "state_token",
        "webauthn_options",
        "identity",
        "display_name",
        :credential,
        :state_token,
        :webauthn_options,
        :identity,
        :display_name
      ])
      |> maybe_put_identity(strategy.resource, params)

    with %{name: action_name} <- Resource.Info.primary_action(strategy.resource, :create) do
      strategy.resource
      |> Changeset.new()
      |> Changeset.set_context(%{private: %{ash_authentication?: true}})
      |> Changeset.for_create(action_name, params, options)
      |> Ash.create(options)
    else
      _ -> {:error, "No create action available for user resource"}
    end
  end

  defp maybe_put_identity(params, resource, original_params) do
    identity = fetch_param(original_params, "identity")

    case identity_field(resource) do
      nil ->
        params

      field ->
        field_key = to_string(field)

        if identity && !Map.has_key?(params, field_key) && !Map.has_key?(params, field) do
          Map.put(params, field_key, identity)
        else
          params
        end
    end
  end

  defp identity_field(resource) do
    resource
    |> Resource.Info.identities()
    |> List.first()
    |> case do
      %{keys: [field]} -> field
      _ -> nil
    end
  end

  defp upsert_key(strategy, user, credential_id, public_key, sign_count, options) do
    key_resource = strategy.key_resource

    credential_id_attr =
      key_info_value!(
        key_resource,
        &WebAuthnKey.Info.web_authn_key_credential_id_attribute_name/1
      )

    public_key_attr =
      key_info_value!(key_resource, &WebAuthnKey.Info.web_authn_key_public_key_attribute_name/1)

    sign_count_attr =
      key_info_value!(key_resource, &WebAuthnKey.Info.web_authn_key_sign_count_attribute_name/1)

    user_id_attr =
      key_info_value!(key_resource, &WebAuthnKey.Info.web_authn_key_user_id_attribute_name/1)

    action_name =
      key_info_value!(key_resource, &WebAuthnKey.Info.web_authn_key_upsert_action_name/1)

    key_params = %{
      to_string(credential_id_attr) => credential_id,
      to_string(public_key_attr) => public_key,
      to_string(sign_count_attr) => sign_count,
      to_string(user_id_attr) => user.id
    }

    key_options = Keyword.put_new_lazy(options, :domain, fn -> key_domain(key_resource) end)

    key_resource
    |> Changeset.new()
    |> Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Changeset.for_create(action_name, key_params, key_options)
    |> Ash.create(key_options)
  end

  defp fetch_key_by_credential(strategy, credential_id, options) do
    key_resource = strategy.key_resource

    credential_id_attr =
      key_info_value!(
        key_resource,
        &WebAuthnKey.Info.web_authn_key_credential_id_attribute_name/1
      )

    read_action_name =
      key_info_value!(key_resource, &WebAuthnKey.Info.web_authn_key_read_action_name/1)

    user_relationship =
      key_info_value!(key_resource, &WebAuthnKey.Info.web_authn_key_user_relationship_name/1)

    key_options = Keyword.put_new_lazy(options, :domain, fn -> key_domain(key_resource) end)

    key_resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.filter(^ref(credential_id_attr) == ^credential_id)
    |> Query.load(user_relationship)
    |> Query.for_read(read_action_name, %{}, key_options)
    |> Ash.read(key_options)
    |> case do
      {:ok, [key]} -> {:ok, key}
      {:ok, []} -> {:error, "No matching credential"}
      {:ok, _} -> {:error, "Multiple credentials matched"}
      {:error, error} -> {:error, error}
    end
  end

  defp load_user_from_key(strategy, key, _options) do
    user_relationship =
      key_info_value!(
        strategy.key_resource,
        &WebAuthnKey.Info.web_authn_key_user_relationship_name/1
      )

    Map.get(key, user_relationship)
    |> case do
      nil -> {:error, "Credential has no associated user"}
      user -> {:ok, user}
    end
  end

  defp maybe_update_key(key, sign_count, options) do
    update_action = Resource.Info.primary_action(key.__struct__, :update)

    if update_action do
      key
      |> Changeset.new()
      |> Changeset.set_context(%{private: %{ash_authentication?: true}})
      |> Changeset.for_update(
        update_action.name,
        %{sign_count: sign_count, last_used_at: DateTime.utc_now()},
        options
      )
      |> Ash.update(options)
    else
      {:ok, key}
    end
  end

  defp key_domain(resource) do
    case WebAuthnKey.Info.web_authn_key_domain(resource) do
      {:ok, domain} -> domain
      :error -> Resource.Info.domain(resource)
    end
  end

  defp key_info_value!(resource, fun) when is_function(fun, 1) do
    case fun.(resource) do
      {:ok, value} -> value
      value -> value
    end
  end

  defp adapter_verify_opts(_strategy, claims, origin, rp_id) do
    [
      origin: origin,
      rp_id: rp_id,
      user_verification:
        normalize_enum(claims["user_verification"], [
          "required",
          "preferred",
          "discouraged"
        ])
    ]
    |> maybe_put_option(:attestation, claims["attestation"])
  end

  defp put_authenticator_selection(public_key, webauthn_options) do
    authenticator_attachment = fetch_param(webauthn_options, "authenticator_attachment")
    resident_key = fetch_param(webauthn_options, "resident_key")
    require_resident_key = fetch_param(webauthn_options, "require_resident_key")

    selection =
      %{}
      |> maybe_put_map(:authenticatorAttachment, authenticator_attachment)
      |> maybe_put_map(:residentKey, resident_key)
      |> maybe_put_map(:requireResidentKey, require_resident_key)

    if map_size(selection) == 0 do
      public_key
    else
      Map.put(public_key, :authenticatorSelection, selection)
    end
  end

  defp put_user_verification(public_key, webauthn_options, :register) do
    case normalize_enum(fetch_param(webauthn_options, "user_verification"), [
           "required",
           "preferred",
           "discouraged"
         ]) do
      nil ->
        public_key

      value ->
        selection = Map.get(public_key, :authenticatorSelection, %{})
        Map.put(public_key, :authenticatorSelection, Map.put(selection, :userVerification, value))
    end
  end

  defp put_user_verification(public_key, webauthn_options, :sign_in) do
    case normalize_enum(fetch_param(webauthn_options, "user_verification"), [
           "required",
           "preferred",
           "discouraged"
         ]) do
      nil -> public_key
      value -> Map.put(public_key, :userVerification, value)
    end
  end

  defp encode_public_key_options(public_key) do
    public_key
    |> update_binary_key(:challenge)
    |> update_binary_key("challenge")
    |> update_nested_user_id()
    |> update_credential_ids(:allowCredentials)
    |> update_credential_ids("allowCredentials")
    |> update_credential_ids(:excludeCredentials)
    |> update_credential_ids("excludeCredentials")
  end

  defp update_binary_key(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} when is_binary(value) -> Map.put(map, key, encode_base64url(value))
      _ -> map
    end
  end

  defp update_nested_user_id(map) do
    case Map.fetch(map, :user) do
      {:ok, user} when is_map(user) ->
        case Map.fetch(user, :id) do
          {:ok, value} when is_binary(value) ->
            Map.put(map, :user, Map.put(user, :id, encode_base64url(value)))

          _ ->
            map
        end

      _ ->
        map
    end
  end

  defp update_credential_ids(map, key) do
    case Map.fetch(map, key) do
      {:ok, credentials} when is_list(credentials) ->
        Map.put(
          map,
          key,
          Enum.map(credentials, fn credential ->
            case Map.fetch(credential, :id) do
              {:ok, value} when is_binary(value) ->
                Map.put(credential, :id, encode_base64url(value))

              _ ->
                credential
            end
          end)
        )

      _ ->
        map
    end
  end

  defp encode_base64url(value) when is_binary(value),
    do: Base.url_encode64(value, padding: false)

  defp decode_base64url!(value) when is_binary(value),
    do: Base.url_decode64!(value, padding: false)

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

  defp maybe_put_option(opts, _key, nil), do: opts
  defp maybe_put_option(opts, key, value), do: Keyword.put(opts, key, value)

  defp maybe_put_map(map, _key, nil), do: map
  defp maybe_put_map(map, key, value), do: Map.put(map, key, value)

  defp normalize_enum(nil, _allowed), do: nil

  defp normalize_enum(value, allowed) when is_binary(value) do
    if value in allowed, do: value, else: nil
  end

  defp normalize_enum(value, allowed) when is_atom(value) do
    value
    |> Atom.to_string()
    |> normalize_enum(allowed)
  end

  defp ensure_pub_key_params(public_key) when is_map(public_key) do
    params_key =
      cond do
        Map.has_key?(public_key, :pubKeyCredParams) -> :pubKeyCredParams
        Map.has_key?(public_key, "pubKeyCredParams") -> "pubKeyCredParams"
        true -> :pubKeyCredParams
      end

    params = Map.get(public_key, params_key, [])

    if has_required_pub_key_params?(params) do
      public_key
    else
      Map.put(public_key, params_key, default_pub_key_params())
    end
  end

  defp ensure_pub_key_params(public_key), do: public_key

  defp default_pub_key_params do
    [
      %{type: "public-key", alg: -7},
      %{type: "public-key", alg: -257}
    ]
  end

  defp has_required_pub_key_params?(params) when is_list(params) do
    algs =
      Enum.map(params, fn param ->
        Map.get(param, :alg) || Map.get(param, "alg")
      end)

    Enum.member?(algs, -7) and Enum.member?(algs, -257)
  end

  defp has_required_pub_key_params?(_), do: false

  defp begin_context(strategy, params, context) do
    webauthn_options = fetch_webauthn_options(params)

    with {:ok, origin} <- Resolver.resolve_origin_for_begin(strategy, webauthn_options, context),
         {:ok, rp_id} <- Resolver.resolve_rp_id_for_begin(strategy, webauthn_options, context) do
      {:ok,
       %{
         webauthn_options: webauthn_options,
         origin: origin,
         rp_id: rp_id
       }}
    end
  end

  defp registration_finish_context(strategy, params, context) do
    with {:ok, %{credential: credential, state_token: state_token}} <-
           fetch_registration_params(params),
         {:ok, claims} <-
           verify_state_token(strategy, state_token, "webauthn_register", context),
         {:ok, origin} <- Resolver.resolve_origin_from_request(claims),
         {:ok, rp_id} <- Resolver.resolve_rp_id_from_request(claims),
         {:ok, %{attestation_object: attestation_object, client_data_json: client_data_json}} <-
           decode_registration_credential(credential) do
      {:ok,
       %{
         claims: claims,
         origin: origin,
         rp_id: rp_id,
         attestation_object: attestation_object,
         client_data_json: client_data_json
       }}
    end
  end

  defp sign_in_finish_context(strategy, params, context) do
    with {:ok, %{credential: credential, state_token: state_token}} <-
           fetch_sign_in_params(params),
         {:ok, claims} <- verify_state_token(strategy, state_token, "webauthn_sign_in", context),
         {:ok, origin} <- Resolver.resolve_origin_from_request(claims),
         {:ok, rp_id} <- Resolver.resolve_rp_id_from_request(claims) do
      {:ok,
       %{
         credential: credential,
         claims: claims,
         origin: origin,
         rp_id: rp_id
       }}
    end
  end

  defp wrap_auth_error(result, strategy) do
    case result do
      {:ok, _} = ok ->
        ok

      {:error, error} ->
        {:error, auth_error(strategy, error)}

      error ->
        {:error, auth_error(strategy, error)}
    end
  end

  defp wrap_finish_error(strategy, result, phase) do
    case result do
      {:ok, _} = ok ->
        ok

      {:error, error} ->
        log_finish_error(strategy, error, phase)

      error ->
        log_finish_error(strategy, error, phase)
    end
  end

  defp auth_error(strategy, error) do
    Errors.AuthenticationFailed.exception(strategy: strategy, caused_by: error)
  end

  defp log_finish_error(strategy, error, phase) do
    exception = auth_error(strategy, error)

    Logger.error(
      "Error occured when trying to finish #{phase}: #{inspect(exception, pretty: true)}"
    )

    {:error, exception}
  end
end
