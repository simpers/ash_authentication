#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.FullCycleTest do
  use DataCase, async: false

  @moduletag feature: :webauthn

  import Plug.Test

  alias AshAuthentication.{Info, Jwt}
  alias AshAuthentication.Strategy.WebAuthn.Plug, as: WebAuthnPlug

  @origin "https://example.com"
  @rp_id "example.com"

  defmodule TestWebAuthnAdapter do
    import ExUnit.Assertions

    @origin "https://example.com"
    @rp_id "example.com"
    @challenge <<1, 2, 3, 4>>

    def new_registration_challenge(opts) do
      assert Keyword.get(opts, :origin) == @origin
      assert Keyword.get(opts, :rp_id) == @rp_id

      {:ok,
       %{
         challenge: @challenge,
         public_key_credential_options: %{
           "challenge" => @challenge,
           "user" => %{"id" => "user-id"}
         }
       }}
    end

    def verify_registration(attestation_object, client_data_json, challenge, opts) do
      assert challenge == @challenge
      assert Keyword.get(opts, :origin) == @origin
      assert Keyword.get(opts, :rp_id) == @rp_id
      assert is_binary(attestation_object)
      assert is_binary(client_data_json)

      {:ok,
       %{
         credential_id: <<5, 6, 7>>,
         public_key: %{1 => 2, 3 => -7, -1 => 1, -2 => <<8, 9>>, -3 => <<10, 11>>},
         sign_count: 0
       }}
    end
  end

  setup do
    strategy = Info.strategy!(Example.UserWithWebAuthn, :web_authn)
    strategy = %{strategy | origin: nil}
    subject_name = Info.authentication_subject_name!(strategy.resource)
    previous_adapter = Application.get_env(:ash_authentication, :web_authn_adapter)

    Application.put_env(:ash_authentication, :web_authn_adapter, TestWebAuthnAdapter)

    on_exit(fn ->
      if is_nil(previous_adapter) do
        Application.delete_env(:ash_authentication, :web_authn_adapter)
      else
        Application.put_env(:ash_authentication, :web_authn_adapter, previous_adapter)
      end
    end)

    {:ok, strategy: strategy, subject_name: subject_name}
  end

  test "register_begin returns a state token with origin", %{
    strategy: strategy,
    subject_name: subject_name
  } do
    params = %{
      to_string(subject_name) => %{
        "webauthn_options" => %{
          "rp_id" => @rp_id,
          "user_verification" => "preferred"
        },
        "identity" => "user@example.com",
        "display_name" => "Example User"
      }
    }

    context = http_request_context()

    conn =
      :post
      |> conn("/auth", params)
      |> Ash.PlugHelpers.set_context(context)
      |> WebAuthnPlug.register_begin(strategy)

    assert {:ok, %{public_key: public_key, state_token: state_token}} =
             conn.private.authentication_result

    assert is_map(public_key)
    assert is_binary(state_token)

    assert {:ok, claims, _resource} = Jwt.verify(state_token, strategy.resource, [], context)
    assert claims["origin"] == @origin
    assert claims["rp_id"] == @rp_id
  end

  test "register_finish completes a full request cycle", %{
    strategy: strategy,
    subject_name: subject_name
  } do
    state_token = register_begin_state_token(strategy, subject_name)

    attestation_object = <<10, 11, 12>>
    client_data_json = <<13, 14, 15>>
    email = "user_#{System.unique_integer([:positive])}@example.com"

    params = %{
      to_string(subject_name) => %{
        "webauthn_options" => %{
          "rp_id" => @rp_id
        },
        "credential" => %{
          "response" => %{
            "attestationObject" => base64url(attestation_object),
            "clientDataJSON" => base64url(client_data_json)
          }
        },
        "state_token" => state_token,
        "email" => email
      }
    }

    conn =
      :post
      |> conn("/auth", params)
      |> Ash.PlugHelpers.set_context(http_request_context())
      |> WebAuthnPlug.register_finish(strategy)

    assert {:ok, user} = conn.private.authentication_result
    assert to_string(user.email) == email
    assert user.__metadata__.token
  end

  defp register_begin_state_token(strategy, subject_name) do
    params = %{
      to_string(subject_name) => %{
        "webauthn_options" => %{
          "rp_id" => @rp_id,
          "user_verification" => "preferred"
        },
        "identity" => "user@example.com",
        "display_name" => "Example User"
      }
    }

    conn =
      :post
      |> conn("/auth", params)
      |> Ash.PlugHelpers.set_context(http_request_context())
      |> WebAuthnPlug.register_begin(strategy)

    assert {:ok, %{state_token: state_token}} = conn.private.authentication_result

    state_token
  end

  defp http_request_context do
    %{http_request: %{scheme: :https, host: "example.com", port: 443}}
  end

  defp base64url(binary), do: Base.url_encode64(binary, padding: false)
end
