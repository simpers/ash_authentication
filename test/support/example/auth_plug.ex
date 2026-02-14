# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.AuthPlug do
  @moduledoc false

  use AshAuthentication.Plug, otp_app: :ash_authentication

  require Logger

  @impl AshAuthentication.Plug
  def handle_success(conn, {strategy, phase}, nil, nil) do
    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      200,
      Jason.encode!(%{status: :success, strategy: strategy, phase: phase})
    )
  end

  def handle_success(conn, {strategy, phase}, user, _token)
      when is_map(user) and not is_struct(user) do
    Logger.warning("We're here, actually?!")

    response =
      Map.merge(%{status: :success, strategy: strategy, phase: phase}, user)

    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      200,
      Jason.encode!(response)
    )
  end

  def handle_success(conn, {strategy, phase}, user, token) do
    conn
    |> store_in_session(user)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      200,
      Jason.encode!(%{
        status: :success,
        token: token,
        user: Map.take(user, ~w[username id email]a),
        strategy: strategy,
        phase: phase
      })
    )
  end

  @impl AshAuthentication.Plug
  def handle_failure(conn, {strategy, phase}, reason) do
    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      401,
      Jason.encode!(%{
        status: :failure,
        reason: inspect(reason),
        strategy: strategy,
        phase: phase
      })
    )
  end
end
