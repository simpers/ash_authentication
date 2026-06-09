# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.SetAshAuthenticationContextChange do
  @moduledoc false

  use Ash.Resource.Change

  alias Ash.Changeset

  @impl true
  def change(changeset, _opts, _context) do
    Changeset.set_context(changeset, %{private: %{ash_authentication?: true}})
  end
end
