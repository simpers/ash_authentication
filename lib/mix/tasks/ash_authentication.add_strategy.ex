# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy password"

    @shortdoc "Adds the provided strategy or strategies to your user resource"

    @strategies [
      password: "Register and sign in with a username/email and a password.",
      magic_link: "Register and sign in with a magic link, sent via email to the user."
    ]

    @strategy_explanation Enum.map_join(@strategies, "\n", fn {name, description} ->
                            "  * `#{name}` - #{description}"
                          end)

    @strategy_names @strategies |> Keyword.keys() |> Enum.map(&to_string/1)

    @moduledoc """
    #{@shortdoc}

    This task will add the provided strategy or strategies to your user resource.

    The following strategies are available. For all others, see the relevant documentation for setup

    #{@strategy_explanation}

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` -  The user resource. Defaults to `YourApp.Accounts.User`
    * `--identity-field`, `-i` - The field on the user resource that will be used to identify
      the user. Defaults to `email`
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        # A list of environments that this should be installed in, only relevant if this is an installer.
        only: nil,
        # a ist of positional arguments, i.e `[:file]`
        positional: [
          strategies: [rest: true]
        ],
        schema: [
          user: :string
        ],
        aliases: [
          u: :user
        ]
      }
    end

    def igniter(igniter, argv) do
      {%{strategies: strategies}, argv} = positional_args!(argv)
      default_user = Igniter.Project.Module.module_name(igniter, "Accounts.User")

      options =
        argv
        |> options!()
        |> Keyword.update(:identity_field, :email, &String.to_atom/1)
        |> Keyword.update(:user, default_user, &Igniter.Project.Module.parse/1)

      if invalid_strategy = Enum.find(strategies, &(&1 not in @strategy_names)) do
        Mix.shell().error("""
        Invalid strategy provided: `#{invalid_strategy}`

        Not all strategies can be installed using `ash_authentication.add_strategy` yet.
        Want to see a strategy added? Open an issue (or even better, a PR!) on GitHub.

        See a list of strategies and how to install them here:

        https://hexdocs.pm/ash_authentication/get-started.html

        Available Strategies:

        #{@strategy_explanation}
        """)

        exit({:shutdown, 1})
      end

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          Enum.reduce(strategies, igniter, fn
            "password", igniter ->
              igniter
              |> password(options)
              |> Ash.Igniter.codegen("add_password_auth")

            "magic_link", igniter ->
              igniter
              |> magic_link(options)
              |> Ash.Igniter.codegen("add_magic_link_auth")
          end)

        {false, igniter} ->
          Igniter.add_issue(igniter, """
          User module #{inspect(options[:user])} was not found.

          Perhaps you have not yet installed ash_authentication?
          """)
      end
    end

    defp magic_link(igniter, options) do
      if options[:identity_field] != :email do
        Mix.shell().error("""
        Could not add magic link strategy with identity field #{inspect(options[:identity_field])}.

        Please run `mix ash_authentication.add_strategy magic_link` without specifying a default
        """)

        exit({:shutdown, 1})
      end

      sender = Module.concat(options[:user], Senders.SendMagicLinkEmail)

      igniter
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], options[:identity_field], """
      attribute :#{options[:identity_field]}, :ci_string do
        allow_nil? false
        public? true
      end
      """)
      |> make_hashed_password_optional(options)
      |> ensure_identity(options)
      |> ensure_get_by_action(options)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :sign_in_with_magic_link, """
      create :sign_in_with_magic_link do
        description "Sign in or register a user with magic link."

        argument :token, :string do
          description "The token from the magic link that was sent to the user"
          allow_nil? false
        end

        upsert? true
        upsert_identity :unique_#{options[:identity_field]}
        upsert_fields [:#{options[:identity_field]}]

        # Uses the information from the token to create or sign in the user
        change AshAuthentication.Strategy.MagicLink.SignInChange

        metadata :token, :string do
          allow_nil? false
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :request_magic_link, """
      action :request_magic_link do
        argument :#{options[:identity_field]}, :ci_string do
          allow_nil? false
        end

        run AshAuthentication.Strategy.MagicLink.Request
      end
      """)
      |> AshAuthentication.Igniter.add_new_strategy(options[:user], :magic_link, :magic_link, """
      magic_link do
        identity_field :#{options[:identity_field]}
        registration_enabled? true

        sender #{inspect(sender)}
      end
      """)
      |> create_new_magic_link_sender(sender, options)
    end

    defp make_hashed_password_optional(igniter, options) do
      Igniter.Project.Module.find_and_update_module!(igniter, options[:user], fn zipper ->
        with {:ok, zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 :attributes,
                 1
               ),
             {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper),
             {:ok, zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 :attribute,
                 [1, 2, 3],
                 &Igniter.Code.Function.argument_equals?(&1, 0, :hashed_password)
               ),
             {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper),
             {:ok, zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 :allow_nil?,
                 1,
                 &Igniter.Code.Function.argument_equals?(&1, 0, false)
               ) do
          {:ok, Sourceror.Zipper.remove(zipper)}
        else
          _ ->
            {:ok, zipper}
        end
      end)
    end

    defp password(igniter, options) do
      sender = Module.concat(options[:user], Senders.SendPasswordResetEmail)

      {igniter, _, zipper} =
        igniter
        |> Igniter.Project.Module.find_module!(options[:user])

      allow_nil_line =
        zipper
        |> Igniter.Code.Function.move_to_function_call(:magic_link, [1, 2])
        |> case do
          {:ok, _} -> ""
          _ -> "allow_nil? false"
        end

      igniter
      |> Igniter.Project.Deps.add_dep({:bcrypt_elixir, "~> 3.0"})
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], options[:identity_field], """
      attribute :#{options[:identity_field]}, :ci_string do
        allow_nil? false
        public? true
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], :hashed_password, """
      attribute :hashed_password, :string do
        #{allow_nil_line}
        sensitive? true
      end
      """)
      |> ensure_identity(options)
      |> AshAuthentication.Igniter.add_new_strategy(options[:user], :password, :password, """
      password :password do
        identity_field :#{options[:identity_field]}

        resettable do
          sender #{inspect(sender)}
          # these configurations will be the default in a future release
          password_reset_action_name :reset_password_with_token
          request_password_reset_action_name :request_password_reset_token
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :change_password, """
      update :change_password do
        # Use this action to allow users to change their password by providing
        # their current password and a new password.

        require_atomic? false
        accept []
        argument :current_password, :string, sensitive?: true, allow_nil?: false
        argument :password, :string, sensitive?: true, allow_nil?: false, constraints: [min_length: 8]
        argument :password_confirmation, :string, sensitive?: true, allow_nil?: false

        validate confirm(:password, :password_confirmation)
        validate {AshAuthentication.Strategy.Password.PasswordValidation, strategy_name: :password, password_argument: :current_password}

        change {AshAuthentication.Strategy.Password.HashPasswordChange, strategy_name: :password}
      end
      """)
      |> generate_sign_in_and_registration(options)
      |> generate_reset(sender, options)
      |> add_confirmation(options)
      |> Ash.Igniter.codegen("add_password_authentication")
    end

    defp ensure_identity(igniter, options) do
      Ash.Resource.Igniter.add_new_identity(
        igniter,
        options[:user],
        :"unique_#{options[:identity_field]}",
        """
        identity :unique_#{options[:identity_field]}, [:#{options[:identity_field]}]
        """
      )
    end

    defp ensure_get_by_action(igniter, options) do
      Ash.Resource.Igniter.add_new_action(
        igniter,
        options[:user],
        :"get_by_#{options[:identity_field]}",
        """
        read :get_by_#{options[:identity_field]} do
          description "Looks up a user by their #{options[:identity_field]}"
          get? true

          argument :#{options[:identity_field]}, :ci_string do
            allow_nil? false
          end

          filter expr(#{options[:identity_field]} == ^arg(:#{options[:identity_field]}))
        end
        """
      )
    end

    defp add_confirmation(igniter, options) do
      sender = Module.concat(options[:user], Senders.SendNewUserConfirmationEmail)

      if options[:identity_field] == :email do
        AshAuthentication.Igniter.add_new_add_on(
          igniter,
          options[:user],
          :confirm_new_user,
          :password,
          """
          confirmation :confirm_new_user do
            monitor_fields [:email]
            confirm_on_create? true
            confirm_on_update? false
            require_interaction? true
            confirmed_at_field :confirmed_at
            auto_confirm_actions [:sign_in_with_magic_link, :reset_password_with_token]
            sender #{inspect(sender)}
          end
          """
        )
        |> Ash.Resource.Igniter.add_new_attribute(options[:user], :confirmed_at, """
        attribute :confirmed_at, :utc_datetime_usec
        """)
        |> create_new_user_confirmation_sender(sender, options)
      else
        igniter
      end
    end

    defp generate_reset(igniter, sender, options) do
      igniter
      |> create_reset_sender(sender, options)
      |> Ash.Resource.Igniter.add_new_action(
        options[:user],
        :request_password_reset_token,
        """
        action :request_password_reset_token do
          description "Send password reset instructions to a user if they exist."

          argument :#{options[:identity_field]}, :ci_string do
            allow_nil? false
          end

          # creates a reset token and invokes the relevant senders
          run {AshAuthentication.Strategy.Password.RequestPasswordReset, action: :get_by_#{options[:identity_field]}}
        end
        """
      )
      |> ensure_get_by_action(options)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :reset_password_with_token, """
      update :reset_password_with_token do
        argument :reset_token, :string do
          allow_nil? false
          sensitive? true
        end

        argument :password, :string do
          description "The proposed password for the user, in plain text."
          allow_nil? false
          constraints [min_length: 8]
          sensitive? true
        end

        argument :password_confirmation, :string do
          description "The proposed password for the user (again), in plain text."
          allow_nil? false
          sensitive? true
        end

        # validates the provided reset token
        validate AshAuthentication.Strategy.Password.ResetTokenValidation

        # validates that the password matches the confirmation
        validate AshAuthentication.Strategy.Password.PasswordConfirmationValidation

        # Hashes the provided password
        change AshAuthentication.Strategy.Password.HashPasswordChange

        # Generates an authentication token for the user
        change AshAuthentication.GenerateTokenChange
      end
      """)
    end

    defp create_new_magic_link_sender(igniter, sender, options) do
      case Igniter.Libs.Swoosh.list_mailers(igniter) do
        {igniter, [mailer]} ->
          {_web_module_exists?, use_web_module, igniter} = create_use_web_module(igniter)

          Igniter.Project.Module.create_module(igniter, sender, ~s'''
          @moduledoc """
          Sends a magic link email
          """

          use AshAuthentication.Sender
          #{use_web_module}

          import Swoosh.Email
          alias #{inspect(mailer)}

          @impl true
          def send(user_or_email, token, _) do
            # if you get a user, its for a user that already exists.
            # if you get an email, then the user does not yet exist.

            email =
              case user_or_email do
                %{email: email} -> email
                email -> email
              end

            new()
            # TODO: Replace with your email
            |> from({"noreply", "noreply@example.com"})
            |> to(to_string(email))
            |> subject("Your login link")
            |> html_body(body([token: token, email: email]))
            |> #{List.last(Module.split(mailer))}.deliver!()
          end

          defp body(params) do
            url = url(~p"/auth/user/magic_link/?token=\#{params[:token]}")

            """
            <p>Hello, \#{params[:email]}! Click this link to sign in:</p>
            <p><a href="\#{url}">\#{url}</a></p>
            """
          end
          ''')

        _ ->
          create_example_new_magic_link_sender(igniter, sender, options)
      end
    end

    defp create_example_new_magic_link_sender(igniter, sender, options) do
      {web_module_exists?, use_web_module, igniter} = create_use_web_module(igniter)

      example_domain = example_domain(options[:user])

      real_example =
        if web_module_exists? do
          """
          # Example of how you might send this email
          # #{inspect(example_domain)}.Emails.send_magic_link_email(
          #   user_or_email,
          #   token
          # )
          """
        end

      url =
        if use_web_module do
          "\#{url(~p\"/auth/user/magic_link/?token=\#{token}\")}"
        else
          "/auth/user/magic_link/?token=\#{token}"
        end

      Igniter.Project.Module.create_module(
        igniter,
        sender,
        ~s'''
        @moduledoc """
        Sends a magic link email
        """

        use AshAuthentication.Sender
        #{use_web_module}

        @impl true
        def send(user_or_email, token, _) do
          # if you get a user, its for a user that already exists.
          # if you get an email, then the user does not yet exist.
          #{real_example}

          email =
            case user_or_email do
              %{email: email} -> email
              email -> email
            end

          IO.puts("""
          Hello, \#{email}! Click this link to sign in:

          #{url}
          """)
        end
        '''
      )
    end

    defp create_reset_sender(igniter, sender, options) do
      case Igniter.Libs.Swoosh.list_mailers(igniter) do
        {igniter, [mailer]} ->
          {_web_module_exists?, use_web_module, igniter} = create_use_web_module(igniter)

          Igniter.Project.Module.create_module(igniter, sender, ~s'''
          @moduledoc """
          Sends a password reset email
          """

          use AshAuthentication.Sender
          #{use_web_module}

          import Swoosh.Email

          alias #{inspect(mailer)}

          @impl true
          def send(user, token, _) do
            new()
            # TODO: Replace with your email
            |> from({"noreply", "noreply@example.com"})
            |> to(to_string(user.email))
            |> subject("Reset your password")
            |> html_body(body([token: token]))
            |> #{List.last(Module.split(mailer))}.deliver!()
          end

          defp body(params) do
            url = url(~p"/password-reset/\#{params[:token]}")

            """
            <p>Click this link to reset your password:</p>
            <p><a href="\#{url}">\#{url}</a></p>
            """
          end
          ''')

        _ ->
          create_example_reset_sender(igniter, sender, options)
      end
    end

    defp create_example_reset_sender(igniter, sender, options) do
      {web_module_exists?, use_web_module, igniter} = create_use_web_module(igniter)

      example_domain = example_domain(options[:user])

      real_example =
        if web_module_exists? do
          """
          # Example of how you might send this email
          # #{inspect(example_domain)}.Emails.send_password_reset_email(
          #   user,
          #   token
          # )
          """
        end

      url =
        if use_web_module do
          "\#{url(~p\"/password-reset/\#{token}\")}"
        else
          "/password-reset/\#{token}"
        end

      Igniter.Project.Module.create_module(
        igniter,
        sender,
        ~s'''
        @moduledoc """
        Sends a password reset email
        """

        use AshAuthentication.Sender
        #{use_web_module}

        @impl true
        def send(_user, token, _) do
          #{real_example}
          IO.puts("""
          Click this link to reset your password:

          #{url}
          """)
        end
        '''
      )
    end

    defp create_new_user_confirmation_sender(igniter, sender, options) do
      case Igniter.Libs.Swoosh.list_mailers(igniter) do
        {igniter, [mailer]} ->
          {_web_module_exists?, use_web_module, igniter} = create_use_web_module(igniter)

          Igniter.Project.Module.create_module(
            igniter,
            sender,
            ~s'''
            @moduledoc """
            Sends an email for a new user to confirm their email address.
            """

            use AshAuthentication.Sender
            #{use_web_module}

            import Swoosh.Email

            alias #{inspect(mailer)}

            @impl true
            def send(user, token, _) do
              new()
              # TODO: Replace with your email
              |> from({"noreply", "noreply@example.com"})
              |> to(to_string(user.email))
              |> subject("Confirm your email address")
              |> html_body(body([token: token]))
              |> #{List.last(Module.split(mailer))}.deliver!()
            end

            defp body(params) do
              url = url(~p"/auth/user/confirm_new_user?\#{[confirm: params[:token]]}")

              """
              <p>Click this link to confirm your email:</p>
              <p><a href="\#{url}">\#{url}</a></p>
              """
            end
            '''
          )

        _ ->
          create_example_new_user_confirmation_sender(igniter, sender, options)
      end
    end

    defp create_example_new_user_confirmation_sender(igniter, sender, options) do
      {web_module_exists?, use_web_module, igniter} = create_use_web_module(igniter)

      example_domain = options[:user] |> Module.split() |> :lists.droplast() |> Module.concat()

      real_example =
        if web_module_exists? do
          """
          # Example of how you might send this email
          # #{inspect(example_domain)}.Emails.send_new_user_confirmation_email(
          #   user,
          #   token
          # )
          """
        end

      url =
        if use_web_module do
          "\#{url(~p\"/auth/user/confirm_new_user?\#{[confirm: token]}\")}"
        else
          "/auth/user/confirm_new_user?confirm=\#{token}"
        end

      Igniter.Project.Module.create_module(
        igniter,
        sender,
        ~s'''
        @moduledoc """
        Sends an email for a new user to confirm their email address.
        """

        use AshAuthentication.Sender
        #{use_web_module}

        @impl true
        def send(_user, token, _) do
          #{real_example}
          IO.puts("""
          Click this link to confirm your email:

          #{url}
          """)
        end
        '''
      )
    end

    defp create_use_web_module(igniter) do
      web_module = Igniter.Libs.Phoenix.web_module(igniter)
      {web_module_exists?, igniter} = Igniter.Project.Module.module_exists(igniter, web_module)

      use_web_module =
        if web_module_exists? do
          "use #{inspect(web_module)}, :verified_routes"
        end

      {web_module_exists?, use_web_module, igniter}
    end

    defp example_domain(user) do
      user |> Module.split() |> :lists.droplast() |> Module.concat()
    end

    defp generate_sign_in_and_registration(igniter, options) do
      igniter
      |> Ash.Resource.Igniter.add_new_action(options[:user], :sign_in_with_password, """
      read :sign_in_with_password do
        description "Attempt to sign in using a #{options[:identity_field]} and password."
        get? true

        argument :#{options[:identity_field]}, :ci_string do
          description "The #{options[:identity_field]} to use for retrieving the user."
          allow_nil? false
        end

        argument :password, :string do
          description "The password to check for the matching user."
          allow_nil? false
          sensitive? true
        end

        # validates the provided #{options[:identity_field]} and password and generates a token
        prepare AshAuthentication.Strategy.Password.SignInPreparation

        metadata :token, :string do
          description "A JWT that can be used to authenticate the user."
          allow_nil? false
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :sign_in_with_token, """
      read :sign_in_with_token do
        # In the generated sign in components, we validate the
        # #{options[:identity_field]} and password directly in the LiveView
        # and generate a short-lived token that can be used to sign in over
        # a standard controller action, exchanging it for a standard token.
        # This action performs that exchange. If you do not use the generated
        # liveviews, you may remove this action, and set
        # `sign_in_tokens_enabled? false` in the password strategy.

        description "Attempt to sign in using a short-lived sign in token."
        get? true

        argument :token, :string do
          description "The short-lived sign in token."
          allow_nil? false
          sensitive? true
        end

        # validates the provided sign in token and generates a token
        prepare AshAuthentication.Strategy.Password.SignInWithTokenPreparation

        metadata :token, :string do
          description "A JWT that can be used to authenticate the user."
          allow_nil? false
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :register_with_password, """
      create :register_with_password do
        description "Register a new user with a #{options[:identity_field]} and password."
        argument :#{options[:identity_field]}, :ci_string do
          allow_nil? false
        end

        argument :password, :string do
          description "The proposed password for the user, in plain text."
          allow_nil? false
          constraints [min_length: 8]
          sensitive? true
        end

        argument :password_confirmation, :string do
          description "The proposed password for the user (again), in plain text."
          allow_nil? false
          sensitive? true
        end

        # Sets the #{options[:identity_field]} from the argument
        change set_attribute(:#{options[:identity_field]}, arg(:#{options[:identity_field]}))

        # Hashes the provided password
        change AshAuthentication.Strategy.Password.HashPasswordChange

        # Generates an authentication token for the user
        change AshAuthentication.GenerateTokenChange

        # validates that the password matches the confirmation
        validate AshAuthentication.Strategy.Password.PasswordConfirmationValidation

        metadata :token, :string do
          description "A JWT that can be used to authenticate the user."
          allow_nil? false
        end
      end
      """)
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy do
    @shortdoc "Adds the provided strategy or strategies to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
