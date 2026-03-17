# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Plug do
  @moduledoc """
  Plugs for the WebAuthn strategy.

  Handles the four phases of WebAuthn authentication:
  - `register_begin` - Initiates credential registration, returns options for the browser
  - `register_finish` - Completes credential registration with the browser's response
  - `sign_in_begin` - Initiates authentication, returns options for the browser
  - `sign_in_finish` - Completes authentication with the browser's response
  """

  require Logger

  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]

  import AshAuthentication.Plug.Helpers,
    only: [
      store_authentication_result: 2
    ]

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy
  alias AshAuthentication.Strategy.WebAuthn

  alias Plug.Conn

  @doc "Handle the beginning of a registration request"
  @spec register_begin(Conn.t(), WebAuthn.t()) :: Conn.t()
  def register_begin(conn, strategy) do
    Logger.debug("Handling WebAuthn registration begin")

    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :register_begin, params, opts)
    store_authentication_result(conn, result)
  end

  @doc "Handle the completion of a registration request"
  @spec register_finish(Conn.t(), WebAuthn.t()) :: Conn.t()
  def register_finish(conn, strategy) do
    Logger.debug("Handling WebAuthn registration finish")

    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :register_finish, params, opts)

    store_authentication_result(conn, result)
  end

  @doc "Handle the beginning of a sign-in request"
  @spec sign_in_begin(Conn.t(), WebAuthn.t()) :: Conn.t()
  def sign_in_begin(conn, strategy) do
    Logger.debug("Handling WebAuthn sign-in begin")

    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :sign_in_begin, params, opts)
    store_authentication_result(conn, result)
  end

  @doc "Handle the completion of a sign-in request"
  @spec sign_in_finish(Conn.t(), WebAuthn.t()) :: Conn.t()
  def sign_in_finish(conn, strategy) do
    Logger.debug("Handling WebAuthn sign-in finish")

    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :sign_in_finish, params, opts)
    store_authentication_result(conn, result)
  end

  # # #
  # ! Private functions
  # # #

  defp opts(conn) do
    with ctx when is_map(ctx) <- get_context(conn) || %{} do
      [actor: get_actor(conn), tenant: get_tenant(conn), context: ctx]
      |> Enum.reject(&is_nil(elem(&1, 1)))
    end
  end

  defp subject_params(conn, strategy) do
    subject_name =
      strategy.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    Map.get(conn.params, subject_name, %{})
  end
end
