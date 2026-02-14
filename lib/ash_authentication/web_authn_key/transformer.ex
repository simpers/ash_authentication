# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnKey.Transformer do
  @moduledoc """
  The WebAuthn key transformer.

  Sets up the default schema for WebAuthn keys.
  """

  use Spark.Dsl.Transformer

  import AshAuthentication.Utils
  import AshAuthentication.Validations

  alias Ash.Resource
  alias AshAuthentication.WebAuthnKey
  alias Spark.Dsl.Transformer

  @doc false
  @impl Spark.Dsl.Transformer
  @spec after?(any) :: boolean()
  def after?(_), do: true

  @doc false
  @impl Spark.Dsl.Transformer
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with {:ok, dsl_state} <- maybe_set_domain(dsl_state, :web_authn_key),
         {:ok, credential_id_attr} <-
           WebAuthnKey.Info.web_authn_key_credential_id_attribute_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, credential_id_attr, :binary,
             allow_nil?: false,
             sensitive?: true,
             writable?: true,
             public?: false
           ),
         {:ok, public_key_attr} <-
           WebAuthnKey.Info.web_authn_key_public_key_attribute_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, public_key_attr, AshAuthentication.Type.CoseKey,
             allow_nil?: false,
             sensitive?: true,
             writable?: true,
             public?: false
           ),
         {:ok, sign_count_attr} <-
           WebAuthnKey.Info.web_authn_key_sign_count_attribute_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, sign_count_attr, :integer,
             allow_nil?: false,
             writable?: true,
             public?: false,
             default: 0
           ),
         {:ok, dsl_state} <- maybe_build_optional_attributes(dsl_state),
         {:ok, dsl_state} <- maybe_define_relationship(dsl_state),
         {:ok, dsl_state} <- maybe_build_unique_identity(dsl_state, credential_id_attr) do
      {:ok, dsl_state}
    end
  end

  defp maybe_build_optional_attributes(dsl_state) do
    with {:ok, dsl_state} <- maybe_build_aaguid(dsl_state),
         {:ok, dsl_state} <- maybe_build_transports(dsl_state),
         {:ok, dsl_state} <- maybe_build_last_used_at(dsl_state) do
      {:ok, dsl_state}
    end
  end

  defp maybe_build_aaguid(dsl_state) do
    with {:ok, aaguid_attr} <- WebAuthnKey.Info.web_authn_key_aaguid_attribute_name(dsl_state) do
      # Build aaguid only if there's no existing attribute with that name
      case find_attribute(dsl_state, aaguid_attr) do
        {:ok, _} ->
          {:ok, dsl_state}

        _ ->
          maybe_build_attribute(dsl_state, aaguid_attr, :binary,
            allow_nil?: true,
            writable?: true,
            public?: false
          )
      end
    end
  end

  defp maybe_build_transports(dsl_state) do
    with {:ok, transports_attr} <-
           WebAuthnKey.Info.web_authn_key_transports_attribute_name(dsl_state) do
      # Build transports only if there's no existing attribute with that name
      case find_attribute(dsl_state, transports_attr) do
        {:ok, _} ->
          {:ok, dsl_state}

        _ ->
          # Store as list of strings
          maybe_build_attribute(dsl_state, transports_attr, {:array, :string},
            allow_nil?: true,
            writable?: true,
            public?: false
          )
      end
    end
  end

  defp maybe_build_last_used_at(dsl_state) do
    with {:ok, last_used_at_attr} <-
           WebAuthnKey.Info.web_authn_key_last_used_at_attribute_name(dsl_state) do
      # Build last_used_at only if there's no existing attribute with that name
      case find_attribute(dsl_state, last_used_at_attr) do
        {:ok, _} ->
          {:ok, dsl_state}

        _ ->
          maybe_build_attribute(dsl_state, last_used_at_attr, :utc_datetime_usec,
            allow_nil?: true,
            writable?: true,
            public?: false
          )
      end
    end
  end

  defp maybe_define_relationship(dsl_state) do
    with {:ok, user_resource} <- WebAuthnKey.Info.web_authn_key_user_resource(dsl_state),
         {:ok, relationship_name} <-
           WebAuthnKey.Info.web_authn_key_user_relationship_name(dsl_state),
         {:ok, user_id_attr} <- WebAuthnKey.Info.web_authn_key_user_id_attribute_name(dsl_state) do
      # Build the belongs_to relationship if it doesn't exist
      case get_relationship(dsl_state, relationship_name) do
        {:ok, _} ->
          {:ok, dsl_state}

        _ ->
          {:ok, relationship} =
            Transformer.build_entity(Resource.Dsl, [:relationships], :belongs_to,
              name: relationship_name,
              destination: user_resource,
              attribute: user_id_attr,
              primary_key?: false,
              allow_nil?: false
            )

          {:ok, Transformer.add_entity(dsl_state, [:relationships], relationship)}
      end
    else
      nil ->
        {:ok, dsl_state}
    end
  end

  defp maybe_build_unique_identity(dsl_state, credential_id_attr) do
    with {:ok, _user_resource} <- WebAuthnKey.Info.web_authn_key_user_resource(dsl_state) do
      # Create a unique identity on credential_id
      # This enforces that a credential ID is globally unique
      identity_name = :unique_credential_id

      case get_identity(dsl_state, identity_name) do
        {:ok, _} ->
          {:ok, dsl_state}

        _ ->
          {:ok, identity} =
            Transformer.build_entity(Resource.Dsl, [:identities], :identity,
              name: identity_name,
              keys: [credential_id_attr]
            )

          {:ok, Transformer.add_entity(dsl_state, [:identities], identity)}
      end
    end
  end

  defp get_relationship(dsl_state, name) do
    dsl_state
    |> Transformer.get_entities([:relationships])
    |> Enum.find(fn rel -> rel.name == name end)
    |> case do
      nil -> :error
      relationship -> {:ok, relationship}
    end
  end

  defp get_identity(dsl_state, name) do
    dsl_state
    |> Transformer.get_entities([:identities])
    |> Enum.find(fn id -> id.name == name end)
    |> case do
      nil -> :error
      identity -> {:ok, identity}
    end
  end
end
