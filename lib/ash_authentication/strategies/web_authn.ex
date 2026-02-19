# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn do
  @moduledoc """
  Strategy for authenticating using a WebAuthn protocol, such as a YubiKey or a
  Passkey.
  """

  @type t :: %__MODULE__{
          name: atom(),
          key_resource: Ash.Resource.t(),
          relying_party: binary(),
          resource: Ash.Resource.t(),
          require_identity?: boolean(),
          register_begin_action_name: atom(),
          register_finish_action_name: atom(),
          sign_in_begin_action_name: atom(),
          sign_in_finish_action_name: atom(),
          __spark_metadata__: nil
        }

  defstruct name: nil,
            key_resource: nil,
            resource: nil,
            relying_party: nil,
            require_identity?: false,
            register_begin_action_name: nil,
            register_finish_action_name: nil,
            sign_in_begin_action_name: nil,
            sign_in_finish_action_name: nil,
            __spark_metadata__: nil

  alias AshAuthentication.Strategy.Custom
  alias AshAuthentication.Strategy.WebAuthn

  use Custom, entity: WebAuthn.Dsl.dsl()

  @doc false
  defdelegate dsl(), to: WebAuthn.Dsl

  @doc false
  defdelegate transform(strategy, dsl_state), to: WebAuthn.Transformer

  @doc false
  defdelegate verify(strategy, dsl_state), to: WebAuthn.Verifier
end
