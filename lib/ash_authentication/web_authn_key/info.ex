# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnKey.Info do
  @moduledoc """
  Introspection functions for the `AshAuthentication.WebAuthnKey` Ash
  extension.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication.WebAuthnKey,
    sections: [:web_authn_key]
end
