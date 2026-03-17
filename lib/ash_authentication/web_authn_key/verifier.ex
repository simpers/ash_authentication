# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnKey.Verifier do
  @moduledoc """
  The WebAuthn key verifier.

  Validates that the WebAuthnKey resource has all required attributes,
  relationships, and identities for proper WebAuthn functionality.
  """

  use Spark.Dsl.Verifier

  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Attribute

  alias Ash.Resource
  alias AshAuthentication.WebAuthnKey.Info
  alias Spark.{Dsl.Verifier, Error.DslError}

  @doc false
  @spec after?(any) :: boolean()
  def after?(_), do: true

  @doc false
  @spec before?(any) :: boolean()
  def before?(_), do: false

  @doc false
  @spec after_compile?() :: boolean()
  def after_compile?, do: true

  @doc false
  @impl Verifier
  @spec verify(map) :: :ok | {:error, term}
  def verify(dsl_state) do
    with :ok <- verify_dependencies(),
         :ok <- verify_credential_id_attribute(dsl_state),
         :ok <- verify_public_key_attribute(dsl_state),
         :ok <- verify_sign_count_attribute(dsl_state),
         :ok <- verify_user_relationship(dsl_state),
         :ok <- verify_credential_id_identity(dsl_state) do
      :ok
    end
  end

  @doc false
  @spec verify_dependencies() :: :ok | {:error, term}
  def verify_dependencies do
    with :ok <- verify_cbor_dependency(),
         :ok <- verify_wax_dependency() do
      :ok
    end
  end

  defp verify_cbor_dependency do
    if Code.ensure_loaded?(CBOR) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:web_authn_key],
         message: """
         The :cbor dependency is required for WebAuthn support.

         Add it to your dependencies in mix.exs:

             {:cbor, "~> 1.0"}
         """
       )}
    end
  end

  defp verify_wax_dependency do
    if Code.ensure_loaded?(Wax) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:web_authn_key],
         message: """
         The :wax_ dependency is required for WebAuthn support.

         Add it to your dependencies in mix.exs:

             {:wax_, "~> 0.7.0"}
         """
       )}
    end
  end

  defp verify_credential_id_attribute(dsl_state) do
    with {:ok, attr_name} <- Info.web_authn_key_credential_id_attribute_name(dsl_state),
         {:ok, attribute} <- find_attribute(dsl_state, attr_name),
         :ok <-
           validate_attribute_option(attribute, __MODULE__, :type, [:binary, Ash.Type.Binary]),
         :ok <- validate_attribute_option(attribute, __MODULE__, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, __MODULE__, :sensitive?, [true]) do
      :ok
    else
      {:error, error} ->
        {:error,
         DslError.exception(
           path: [:web_authn_key, :credential_id],
           message: error_message(:credential_id, error)
         )}
    end
  end

  defp verify_public_key_attribute(dsl_state) do
    with {:ok, attr_name} <- Info.web_authn_key_public_key_attribute_name(dsl_state),
         {:ok, attribute} <- find_attribute(dsl_state, attr_name),
         :ok <-
           validate_attribute_option(attribute, __MODULE__, :type, [:binary, Ash.Type.Binary]),
         :ok <- validate_attribute_option(attribute, __MODULE__, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, __MODULE__, :sensitive?, [true]) do
      :ok
    else
      {:error, error} ->
        {:error,
         DslError.exception(
           path: [:web_authn_key, :public_key],
           message: error_message(:public_key, error)
         )}
    end
  end

  defp verify_sign_count_attribute(dsl_state) do
    with {:ok, attr_name} <- Info.web_authn_key_sign_count_attribute_name(dsl_state),
         {:ok, attribute} <- find_attribute(dsl_state, attr_name),
         :ok <-
           validate_attribute_option(attribute, __MODULE__, :type, [:integer, Ash.Type.Integer]),
         :ok <- validate_attribute_option(attribute, __MODULE__, :allow_nil?, [false]) do
      :ok
    else
      {:error, error} ->
        {:error,
         DslError.exception(
           path: [:web_authn_key, :sign_count],
           message: error_message(:sign_count, error)
         )}
    end
  end

  defp verify_user_relationship(dsl_state) do
    with {:ok, relationship_name} <- Info.web_authn_key_user_relationship_name(dsl_state),
         {:ok, relationship} <- find_relationship(dsl_state, relationship_name) do
      if relationship.type == :belongs_to do
        :ok
      else
        {:error,
         DslError.exception(
           path: [:web_authn_key, :user_relationship],
           message: """
           The #{inspect(relationship_name)} relationship must be a belongs_to relationship.
           """
         )}
      end
    else
      {:error, _} ->
        {:error,
         DslError.exception(
           path: [:web_authn_key, :user_relationship],
           message: """
           The WebAuthnKey resource must have a belongs_to relationship to the user resource.
           """
         )}
    end
  end

  defp verify_credential_id_identity(dsl_state) do
    with {:ok, attr_name} <- Info.web_authn_key_credential_id_attribute_name(dsl_state),
         identity_name = :unique_credential_id,
         {:ok, identity} <- find_identity(dsl_state, identity_name) do
      if attr_name in identity.keys do
        :ok
      else
        {:error,
         DslError.exception(
           path: [:web_authn_key, :identity],
           message: """
           The #{inspect(identity_name)} identity must include the #{inspect(attr_name)} field.
           """
         )}
      end
    else
      {:error, _} ->
        {:error,
         DslError.exception(
           path: [:web_authn_key, :identity],
           message: """
           The WebAuthnKey resource must have a unique identity named :unique_credential_id
           on the credential_id attribute to prevent duplicate credentials.
           """
         )}
    end
  end

  defp error_message(field, error) do
    """
    The #{inspect(field)} attribute is not properly configured for WebAuthn support.

    Expected configuration:
    - type: :binary
    - allow_nil?: false
    - sensitive?: true (for credential_id and public_key)

    Error: #{inspect(error)}
    """
  end

  defp find_identity(dsl_state, identity_name) do
    dsl_state
    |> Resource.Info.identities()
    |> Enum.find(&(&1.name == identity_name))
    |> case do
      nil ->
        resource = Verifier.get_persisted(dsl_state, :module)

        {:error,
         DslError.exception(
           path: [:identities],
           message:
             "The resource `#{inspect(resource)}` does not define an identity named `#{inspect(identity_name)}`"
         )}

      identity ->
        {:ok, identity}
    end
  end
end
