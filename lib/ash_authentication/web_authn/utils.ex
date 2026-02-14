# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthn.Utils do
  @moduledoc false

  import AshAuthentication.Strategy.Utils,
    only: [
      fetch_secret: 3
    ]

  def fetch_origin_secret(strategy, context) do
    fetch_secret(strategy, :origin, context)
  end

  def fetch_relying_party_secret(strategy, context) do
    fetch_secret(strategy, :relying_party, context)
  end
end
