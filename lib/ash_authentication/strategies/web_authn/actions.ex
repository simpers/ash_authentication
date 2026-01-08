# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Actions do
  @moduledoc """
  Action handlers for the WebAuthn strategy.

  These are stub implementations that will be completed in a future PR.
  """

  alias Ash.Resource
  alias AshAuthentication.Strategy.WebAuthn

  @doc """
  Begin the registration process.

  Returns options for the browser's WebAuthn API along with a signed state token.
  """
  @spec register_begin(WebAuthn.t(), map(), keyword()) ::
          {:ok, Resource.record()} | {:error, any()}
  def register_begin(_strategy, _params, _options) do
    {:error, :not_implemented}
  end

  @doc """
  Complete the registration process.

  Verifies the browser's response and persists the credential.
  """
  @spec register_finish(WebAuthn.t(), map(), keyword()) ::
          {:ok, Resource.record()} | {:error, any()}
  def register_finish(_strategy, _params, _options) do
    {:error, :not_implemented}
  end

  @doc """
  Begin the sign-in process.

  Returns options for the browser's WebAuthn API along with a signed state token.
  """
  @spec sign_in_begin(WebAuthn.t(), map(), keyword()) ::
          {:ok, Resource.record()} | {:error, any()}
  def sign_in_begin(_strategy, _params, _options) do
    {:error, :not_implemented}
  end

  @doc """
  Complete the sign-in process.

  Verifies the browser's response and returns the authenticated user.
  """
  @spec sign_in_finish(WebAuthn.t(), map(), keyword()) ::
          {:ok, Resource.record()} | {:error, any()}
  def sign_in_finish(_strategy, _params, _options) do
    {:error, :not_implemented}
  end
end
