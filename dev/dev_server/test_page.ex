# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule DevServer.TestPage do
  @moduledoc """
  Displays a very basic login form according to the currently configured providers.
  """
  @behaviour Plug

  require EEx

  import AshAuthentication.Plug.Helpers,
    only: [
      put_strategy_context: 3,
      set_http_from_conn: 2
    ]

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy

  alias Plug.Conn

  EEx.function_from_file(:defp, :render, String.replace(__ENV__.file, ".ex", ".html.eex"), [
    :assigns
  ])

  @doc false
  @impl true
  @spec init(keyword) :: keyword
  def init(opts), do: opts

  @doc false
  @spec call(Conn.t(), any) :: Conn.t()
  @impl true
  def call(conn, _opts) do
    resources =
      :ash_authentication
      |> AshAuthentication.authenticated_resources()
      |> Enum.map(
        &{&1, Info.authentication_options(&1),
         Info.authentication_strategies(&1) ++ Info.authentication_add_ons(&1)}
      )

    current_users =
      conn.assigns
      |> Stream.filter(fn {key, _value} ->
        key
        |> to_string()
        |> String.starts_with?("current_")
      end)
      |> Map.new()

    ctx =
      %{}
      |> set_http_from_conn(conn)
      |> put_strategy_context(:web_authn, %{})

    payload =
      render(
        context: ctx,
        current_users: current_users,
        resources: resources
      )

    Conn.send_resp(conn, 200, payload)
  end

  defp configured_webauthn_origin(strategy, ctx) do
    AshAuthentication.WebAuthn.Utils.fetch_origin_secret(strategy, ctx)
  end

  defp configured_webauthn_relying_party(strategy, ctx) do
    AshAuthentication.WebAuthn.Utils.fetch_relying_party_secret(strategy, ctx)
  end

  defp render_strategy(strategy, phase, options, _ctx)
       when strategy.provider == :password and phase == :register do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend>Register with <%= @strategy.name %></legend>
          <input type="text" name="<%= @options.subject_name %>[<%= @strategy.identity_field %>]" placeholder="<%= @strategy.identity_field %>" />
          <br />
          <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_field %>]" placeholder="<%= @strategy.password_field %>" />
          <br />
          <%= if @strategy.confirmation_required? do %>
            <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_confirmation_field %>]" placeholder="<%= @strategy.password_confirmation_field %>" />
            <br />
          <% end %>
          <input type="submit" value="Register" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options, _ctx)
       when strategy.provider == :password and phase == :sign_in do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend>Sign in with <%= @strategy.name %></legend>
          <input type="text" name="<%= @options.subject_name %>[<%= @strategy.identity_field %>]" placeholder="<%= @strategy.identity_field %>" />
          <br />
          <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_field %>]" placeholder="<%= @strategy.password_field %>" />
          <br />
          <input type="submit" value="Sign in" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options, _ctx)
       when strategy.provider == :password and phase == :reset_request do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend><%= @strategy.name %> reset request</legend>
          <input type="text" name="<%= @options.subject_name %>[<%= @strategy.identity_field %>]" placeholder="<%= @strategy.identity_field %>" />
          <br />
          <input type="submit" value="Request reset" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options, _ctx)
       when strategy.provider == :password and phase == :reset do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend><%= @strategy.name %> reset request</legend>
          <input type="text" name="reset_token" placeholder="reset_token" />
          <br />
          <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_field %>]" placeholder="<%= @strategy.password_field %>" />
          <br />
          <%= if @strategy.confirmation_required? do %>
            <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_confirmation_field %>]" placeholder="<%= @strategy.password_confirmation_field %>" />
            <br />
          <% end %>
          <input type="submit" value="Reset" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, _options, _ctx)
       when strategy.provider == :password and phase == :sign_in_with_token,
       do: ""

  defp render_strategy(strategy, phase, options, _ctx)
       when strategy.provider == :confirmation and phase == :accept do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
        <legend><%= @strategy.name %> <%= @phase %></legend>
          <input type="text" name="confirm" placeholder="confirmation token" />
          <br />
          <input type="submit" value="Confirm" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        phase: phase,
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options, _ctx)
       when strategy.provider == :confirmation and phase == :confirm do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend><%= @strategy.name %> <%= @phase %></legend>
          <input type="text" name="confirm" placeholder="confirmation token" />
          <br />
          <input type="submit" value="Confirm" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        phase: phase,
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, _options, _ctx)
       when strategy.provider in [:oauth2, :oidc] and phase == :request do
    EEx.eval_string(
      ~s"""
      <a href="<%= @route %>">Sign in with <%= @strategy.name %></a>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, :callback, _, _ctx) when strategy.provider in [:oauth2, :oidc],
    do: ""

  defp render_strategy(strategy, :sign_in, _options, _ctx)
       when is_struct(strategy, Example.OnlyMartiesAtTheParty) or
              is_struct(strategy, ExampleMultiTenant.OnlyMartiesAtTheParty) do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend>Sign in a Marty</legend>
          <input type="text" name="<%= @strategy.name_field %>" placeholder="<%= @strategy.name_field %>" />
          <br />
          <input type="submit" value="Sign in" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, :sign_in),
        method: Strategy.method_for_phase(strategy, :sign_in)
      ]
    )
  end

  defp render_strategy(strategy, phase, options, _ctx)
       when is_struct(strategy, Strategy.MagicLink) and phase == :request do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend><%= @strategy.name %> request</legend>
          <input type="text" name="<%= @options.subject_name %>[<%= @strategy.identity_field %>]" placeholder="<%= @strategy.identity_field %>" />
          <br />
          <input type="submit" value="Request" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, _options, _ctx)
       when is_struct(strategy, Strategy.MagicLink) and
              strategy.required_interaction? == true and
              phase == :accept do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
      <fieldset>
        <legend><%= @strategy.name %> accept</legend>
        <input type="text" name="token" placeholder="token" />
        <br />
        <input type="submit" value="Accept" />
      </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options, _ctx)
       when is_struct(strategy, Strategy.MagicLink) and phase == :sign_in do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend><%= @strategy.name %> sign in</legend>
          <input type="text" name="token" placeholder="token" />
          <br />
          <input type="submit" value="Sign in" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options, ctx)
       when is_struct(strategy, Strategy.WebAuthn) and phase == :register_begin do
    EEx.eval_string(
      ~s"""
      <section class="webauthn"
        data-subject-name="<%= @subject_name %>"
        data-identity-field="<%= @identity_field %>"
        data-display-name-field="<%= @display_name_field %>"
        data-register-begin="<%= @register_begin %>"
        data-register-finish="<%= @register_finish %>"
        data-sign-in-begin="<%= @sign_in_begin %>"
        data-sign-in-finish="<%= @sign_in_finish %>">
        <fieldset>
          <legend>WebAuthn (<%= @strategy.name %>)</legend>
          <p>
            <strong>Relying Party:</strong> <%= @relying_party %><br />
            <strong>Origin (configured):</strong> <%= @configured_origin || "(not set)" %><br />
            <strong>Origin (request):</strong>
            <span class="webauthn-request-origin">(loading...)</span>
          </p>
          <label>
            Identity (<%= @identity_field %>)
            <input class="webauthn-identity" type="text" placeholder="<%= @identity_field %>" />
          </label>
          <br />
          <label>
            Display name (optional)
            <input class="webauthn-display-name" type="text" placeholder="<%= @display_name_field %> (optional)" />
          </label>
          <br />
          <label>
            Sign-in mode
            <select class="webauthn-sign-in-mode">
              <option value="no_identity">No identity (passkey discovery)</option>
              <option value="require_identity">Require identity (later)</option>
            </select>
          </label>
          <br />
          <label>
            Authenticator attachment
            <select class="webauthn-authenticator-attachment">
              <option value="">Default</option>
              <option value="platform">Platform (built-in)</option>
              <option value="cross-platform">Cross-platform (USB/NFC)</option>
            </select>
          </label>
          <br />
          <label>
            Resident key
            <select class="webauthn-resident-key">
              <option value="">Default</option>
              <option value="required">required</option>
              <option value="preferred">preferred</option>
              <option value="discouraged">discouraged</option>
            </select>
          </label>
          <label>
            <input class="webauthn-require-resident-key" type="checkbox" /> requireResidentKey
          </label>
          <br />
          <label>
            User verification
            <select class="webauthn-user-verification">
              <option value="">Default</option>
              <option value="required">required</option>
              <option value="preferred">preferred</option>
              <option value="discouraged">discouraged</option>
            </select>
          </label>
          <br />
          <label>
            Attestation
            <select class="webauthn-attestation">
              <option value="">Default</option>
              <option value="none">none</option>
              <option value="indirect">indirect</option>
              <option value="direct">direct</option>
              <option value="enterprise">enterprise</option>
            </select>
          </label>
          <br />
          <button class="webauthn-register" type="button">Register passkey</button>
          <button class="webauthn-sign-in" type="button">Sign in with passkey</button>
          <pre class="webauthn-output"></pre>
        </fieldset>
      </section>
      """,
      assigns: [
        strategy: strategy,
        subject_name: to_string(options.subject_name),
        identity_field: "identity",
        display_name_field: "display_name",
        configured_origin: configured_webauthn_origin(strategy, ctx),
        relying_party: configured_webauthn_relying_party(strategy, ctx),
        register_begin: route_for_phase(strategy, :register_begin),
        register_finish: route_for_phase(strategy, :register_finish),
        sign_in_begin: route_for_phase(strategy, :sign_in_begin),
        sign_in_finish: route_for_phase(strategy, :sign_in_finish)
      ]
    )
  end

  defp render_strategy(strategy, _phase, _options, _ctx)
       when is_struct(strategy, Strategy.WebAuthn),
       do: ""

  defp render_strategy(strategy, phase, _options, _ctx) do
    unmatched_pair = inspect({strategy, phase})

    EEx.eval_string(
      ~s"""
      <section>
        <h3>Unmatched strategy-phase pair (<%= @strategy_name %>, <%= @phase %>):</h3>
        <h4><%= @pair %></h4>
      </section>
      """,
      assigns: [
        pair: unmatched_pair,
        phase: phase,
        strategy_name: strategy.name
      ]
    )
  end

  defp route_for_phase(strategy, phase) do
    Path.join("/auth", get_path_for_strat_phase!(strategy, phase))
  end

  defp get_path_for_strat_phase!(strategy, phase) do
    strategy
    |> Strategy.routes()
    |> Enum.find(&(elem(&1, 1) == phase))
    |> case do
      tuple when is_tuple(tuple) ->
        elem(tuple, 0)

      other ->
        raise """
        expected a tuple when extracting path for strategy phase:
        Strategy:
          #{inspect(strategy, pretty: true)}
        Phase:
          #{inspect(phase, pretty: true)}

        Found:
        #{inspect(other, pretty: true)}
        """
    end
  end
end
