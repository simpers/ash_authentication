# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.WebAuthnSimpers do
  @moduledoc false

  alias Ash.Resource
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy
  alias AshAuthentication.Strategy.WebAuthnSimpers
  alias AshAuthentication.Strategy.WebAuthnSimpers.Actions
  alias Plug.Conn

  @type phase :: :register_begin | :register_finish | :sign_in_begin | :sign_in_finish

  @doc false
  @spec name(WebAuthnSimpers.t()) :: atom()
  def name(strategy), do: strategy.name

  @doc false
  @spec actions(WebAuthnSimpers.t()) :: [atom()]
  def actions(_strategy) do
    [:register_begin, :register_finish, :sign_in_begin, :sign_in_finish]
  end

  @doc false
  @spec phases(WebAuthnSimpers.t()) :: [atom()]
  def phases(_strategy) do
    [:register_begin, :register_finish, :sign_in_begin, :sign_in_finish]
  end

  @doc false
  @spec method_for_phase(WebAuthnSimpers.t(), phase) :: Strategy.http_method()
  def method_for_phase(_, _), do: :post

  @doc """
  Return a list of routes for use by the strategy.
  """
  @spec routes(WebAuthnSimpers.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)

    strategy
    |> phases()
    |> Enum.map(fn phase ->
      path =
        [subject_name, strategy.name, phase]
        |> Enum.map(&to_string/1)
        |> Path.join()

      {"/#{path}", phase}
    end)
  end

  @doc """
  Handle HTTP requests.
  """
  @spec plug(WebAuthnSimpers.t(), phase, Conn.t()) :: Conn.t()
  def plug(strategy, :register_begin, conn),
    do: WebAuthnSimpers.Plug.register_begin(conn, strategy)

  def plug(strategy, :register_finish, conn),
    do: WebAuthnSimpers.Plug.register_finish(conn, strategy)

  def plug(strategy, :sign_in_begin, conn), do: WebAuthnSimpers.Plug.sign_in_begin(conn, strategy)

  def plug(strategy, :sign_in_finish, conn),
    do: WebAuthnSimpers.Plug.sign_in_finish(conn, strategy)

  @doc """
  Perform actions.
  """
  @spec action(WebAuthnSimpers.t(), phase, map, keyword) ::
          {:ok, Resource.record()} | {:error, any}
  def action(strategy, :register_begin, params, options),
    do: Actions.register_begin(strategy, params, options)

  def action(strategy, :register_finish, params, options),
    do: Actions.register_finish(strategy, params, options)

  def action(strategy, :sign_in_begin, params, options),
    do: Actions.sign_in_begin(strategy, params, options)

  def action(strategy, :sign_in_finish, params, options),
    do: Actions.sign_in_finish(strategy, params, options)

  @doc false
  @spec tokens_required?(WebAuthnSimpers.t()) :: true
  def tokens_required?(_), do: true
end
