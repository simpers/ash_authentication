defmodule AshAuthentication.AddOn.Confirmation.Plug do
  @moduledoc """
  Handlers for incoming OAuth2 HTTP requests.
  """

  alias AshAuthentication.{AddOn.Confirmation, Info, Strategy}
  alias AshAuthentication.Errors.InvalidToken
  alias Plug.Conn
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]

  @doc """
  Attempt to perform a confirmation.
  """
  @spec confirm(Conn.t(), Confirmation.t()) :: Conn.t()
  def confirm(conn, strategy) do
    opts = opts(conn)

    result =
      case params(strategy, conn.params) do
        {:ok, params} ->
          strategy
          |> Strategy.action(:confirm, params, opts)

        :error ->
          {:error, InvalidToken.exception(type: :confirmation)}
      end

    conn
    |> store_authentication_result(result)
  end

  defp opts(conn) do
    [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn) || %{}]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end

  defp params(strategy, params) when strategy.require_interaction? do
    case params do
      %{"confirm" => _} ->
        {:ok, params}

      params ->
        strategy.resource
        |> Info.authentication_subject_name!()
        |> to_string()
        |> then(&Map.fetch(params, &1))
    end
  end

  defp params(_strategy, params) do
    {:ok, params}
  end
end
