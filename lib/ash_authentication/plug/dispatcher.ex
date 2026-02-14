# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Plug.Dispatcher do
  @moduledoc """
  Route requests and callbacks to the correct provider plugs.
  """

  @behaviour Plug

  alias AshAuthentication.Strategy

  alias Plug.Conn

  import AshAuthentication.Plug.Helpers,
    only: [
      # ash_authentication_request_context_key: 0,
      get_authentication_result: 1,
      put_strategy_context: 3,
      set_http_from_conn: 2
    ]

  import Strategy.RememberMe.Plug.Helpers, only: [maybe_put_remember_me_cookies: 2]

  @type config :: {atom, Strategy.t(), module} | module

  @unsent ~w[unset set set_chunked set_file]a

  @doc false
  @impl Plug
  @spec init([config]) :: config
  def init([config]), do: config

  @doc """
  Send the request to the correct strategy and then return the result.
  """
  @impl Plug
  @spec call(Conn.t(), config | any) :: Conn.t()
  def call(conn, {phase, strategy, return_to}) do
    activity = {Strategy.name(strategy), phase}

    conn =
      conn
      |> drop_params(["glob"])
      |> add_http_request_context()
      |> add_ash_request_context(strategy, %{name: strategy.name})

    strategy
    |> Strategy.plug(phase, conn)
    |> get_authentication_result()
    |> maybe_put_remember_me_cookies(return_to)
    |> case do
      {conn, _} when conn.state not in @unsent ->
        conn

      {conn, :ok} ->
        return_to.handle_success(conn, activity, nil, nil)

      {conn, {:ok, user}} when is_binary(user.__metadata__.token) ->
        return_to.handle_success(conn, activity, user, user.__metadata__.token)

      {conn, {:ok, user}} ->
        return_to.handle_success(conn, activity, user, nil)

      {conn, :error} ->
        return_to.handle_failure(conn, activity, nil)

      {conn, {:error, reason}} ->
        return_to.handle_failure(conn, activity, reason)

      conn when conn.state not in @unsent ->
        conn

      conn ->
        return_to.handle_failure(conn, activity, :no_authentication_result)
    end
  end

  def call(conn, return_to) do
    return_to.handle_failure(conn, {nil, nil}, :not_found)
  end

  # # #
  # ! Private functions
  # # #

  defp add_ash_request_context(conn, strategy, value) do
    context =
      conn
      |> get_context()
      |> put_strategy_context(strategy, value)

    set_context(conn, context)
  end

  defp add_http_request_context(conn) do
    context =
      conn
      |> get_context()
      |> set_http_from_conn(conn)

    set_context(conn, context)
  end

  defp get_context(conn) do
    Ash.PlugHelpers.get_context(conn) || %{}
  end

  defp set_context(conn, context) do
    Ash.PlugHelpers.set_context(conn, context)
  end

  defp drop_params(conn, keys), do: %{conn | params: Map.drop(conn.params, keys)}
end
