# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Utils do
  @moduledoc false

  @doc false
  def fetch_secret(strategy, field_name, context) do
    path = [:authentication, :strategies, strategy.name, field_name]

    with {secret_module, secret_opts} when is_atom(secret_module) <- Map.get(strategy, field_name),
         {:ok, value} <-
           AshAuthentication.Secret.secret_for(
             secret_module,
             path,
             strategy.resource,
             secret_opts,
             context
           ) do
      value
    else
      _ -> nil
    end
  end
end
