# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithWebAuthn do
  defmodule Secret do
    @moduledoc false

    use AshAuthentication.Secret

    @origin_path [:authentication, :strategies, :web_authn, :origin]
    @relying_party_path [:authentication, :strategies, :web_authn, :relying_party]

    @impl AshAuthentication.Secret
    # Origin
    def secret_for(@origin_path, _resource, _opts, %{
          http_request: %{host: host, port: port, scheme: scheme}
        }) do
      {:ok, "#{scheme}://#{host}:#{port}"}
    end

    def secret_for(@origin_path, _resource, _opts, %{
          ash_authentication_request: %{host: host, port: port, scheme: scheme}
        }) do
      {:ok, "#{scheme}://#{host}:#{port}"}
    end

    def secret_for(@origin_path, _resource, _opts, _context) do
      case Application.get_env(:ash_authentication, DevServer) |> get_in([:port]) do
        port when is_integer(port) -> {:ok, "http://localhost:#{port}"}
        _ -> :error
      end
    end

    # Relying Party
    def secret_for(@relying_party_path, _resource, _opts, %{http_request: %{host: host}}) do
      {:ok, host}
    end

    def secret_for(@relying_party_path, _resource, _opts, %{
          ash_authentication_request: %{host: host}
        }) do
      {:ok, host}
    end

    def secret_for(@relying_party_path, _resource, _opts, _context) do
      {:ok, "localhost"}
    end
  end

  @moduledoc false

  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication]

  require Logger

  attributes do
    uuid_primary_key :id, writable?: true
    timestamps()

    attribute :email, :ci_string,
      allow_nil?: true,
      public?: true,
      description: """
      There are cases when we do not require an identity for an account, so an
      email is _not_ always required
      """
  end

  authentication do
    tokens do
      enabled? true
      store_all_tokens? true
      require_token_presence_for_authentication? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    add_ons do
      log_out_everywhere()
    end

    strategies do
      web_authn do
        key_resource Example.WebAuthnKey
        relying_party Secret
        origin Secret
        require_identity? false
      end
    end
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end

  identities do
    identity :email, [:email]
  end

  relationships do
    has_many :web_authn_keys, Example.WebAuthnKey do
      destination_attribute :user_id
    end
  end

  postgres do
    table "user_with_web_authn"
    repo(Example.Repo)
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
