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

  @valid_public_key_attribute_types [
    :binary,
    Ash.Type.Binary,
    AshAuthentication.Type.CoseKey
  ]

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
         :ok <- verify_credential_id_identity(dsl_state),
         :ok <- verify_actions(dsl_state) do
      :ok
    end
  end

  defp verify_actions(dsl_state) do
    with {:ok, read_action_name} <- Info.web_authn_key_read_action_name(dsl_state),
         :ok <- verify_action_type(dsl_state, read_action_name, :read),
         {:ok, destroy_action_name} <- Info.web_authn_key_destroy_action_name(dsl_state),
         :ok <- verify_action_type(dsl_state, destroy_action_name, :destroy),
         {:ok, upsert_action_name} <- Info.web_authn_key_upsert_action_name(dsl_state),
         :ok <- verify_upsert_action(dsl_state, upsert_action_name) do
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
           validate_attribute_option(
             attribute,
             __MODULE__,
             :type,
             @valid_public_key_attribute_types
           ),
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

  defp verify_action_type(dsl_state, action_name, expected_type) do
    with {:ok, action} <- find_action(dsl_state, action_name) do
      if action.type == expected_type do
        :ok
      else
        {:error,
         DslError.exception(
           path: [:web_authn_key, :actions, action_name],
           message:
             "Expected action #{inspect(action_name)} to be of type #{inspect(expected_type)}."
         )}
      end
    else
      {:error, _} ->
        {:error,
         DslError.exception(
           path: [:web_authn_key, :actions, action_name],
           message: "Required action #{inspect(action_name)} is not defined."
         )}
    end
  end

  defp verify_upsert_action(dsl_state, action_name) do
    with {:ok, action} <- find_action(dsl_state, action_name),
         :ok <- verify_upsert_type(action, action_name),
         :ok <- verify_upsert_enabled(action, action_name),
         :ok <- verify_upsert_identity(action, action_name),
         :ok <- verify_upsert_accepts_required_fields(dsl_state, action) do
      :ok
    else
      {:error, _} ->
        {:error,
         DslError.exception(
           path: [:web_authn_key, :actions, action_name],
           message: "Required upsert action #{inspect(action_name)} is not defined."
         )}

      {:invalid_upsert_action, message} ->
        {:error,
         DslError.exception(
           path: [:web_authn_key, :actions, action_name],
           message: message
         )}
    end
  end

  defp verify_upsert_type(action, action_name) do
    if action.type == :create do
      :ok
    else
      {:invalid_upsert_action,
       "Expected upsert action #{inspect(action_name)} to be a create action."}
    end
  end

  defp verify_upsert_enabled(action, action_name) do
    if action.upsert? do
      :ok
    else
      {:invalid_upsert_action,
       "Expected upsert action #{inspect(action_name)} to set upsert? true."}
    end
  end

  defp verify_upsert_identity(action, action_name) do
    if action.upsert_identity == :unique_credential_id do
      :ok
    else
      {:invalid_upsert_action,
       "Expected upsert action #{inspect(action_name)} to set upsert_identity to :unique_credential_id."}
    end
  end

  defp verify_upsert_accepts_required_fields(dsl_state, action) do
    with {:ok, credential_id_attr} <- Info.web_authn_key_credential_id_attribute_name(dsl_state),
         {:ok, public_key_attr} <- Info.web_authn_key_public_key_attribute_name(dsl_state),
         {:ok, sign_count_attr} <- Info.web_authn_key_sign_count_attribute_name(dsl_state),
         {:ok, user_id_attr} <- Info.web_authn_key_user_id_attribute_name(dsl_state) do
      required_fields = [credential_id_attr, public_key_attr, sign_count_attr, user_id_attr]

      case action.accept do
        accept when is_list(accept) ->
          missing = required_fields -- accept

          if Enum.empty?(missing) do
            :ok
          else
            {:invalid_upsert_action,
             "Upsert action must accept required fields #{inspect(required_fields)}. Missing: #{inspect(missing)}."}
          end

        _ ->
          {:invalid_upsert_action,
           "Upsert action must define an explicit accept list containing required credential fields."}
      end
    end
  end

  defp error_message(field, error) do
    """
    The #{inspect(field)} attribute is not properly configured for WebAuthn support.

    Expected configuration:
    - type: :binary
    - allow_nil?: false
    - sensitive?: true (for credential_id and public_key)

    The public_key attribute may also use AshAuthentication.Type.CoseKey.

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

  defp find_action(dsl_state, action_name) do
    dsl_state
    |> Resource.Info.actions()
    |> Enum.find(&(&1.name == action_name))
    |> case do
      nil ->
        resource = Verifier.get_persisted(dsl_state, :module)

        {:error,
         DslError.exception(
           path: [:actions],
           message:
             "The resource `#{inspect(resource)}` does not define an action named `#{inspect(action_name)}`"
         )}

      action ->
        {:ok, action}
    end
  end
end
