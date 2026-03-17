# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

import Config

conf_env = config_env()

case conf_env do
  :dev ->
    port =
      System.get_env("PORT", "4000")
      |> String.to_integer()

    config :ash_authentication, DevServer,
      start?: true,
      port: port

  _ ->
    :ok
end
