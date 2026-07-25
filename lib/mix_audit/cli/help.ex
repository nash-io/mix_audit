defmodule MixAudit.CLI.Help do
  @moduledoc false
  def run(_opts) do
    IO.puts("Usage: mix deps.audit [options]")
    IO.puts("")
    IO.puts("Example: $ mix deps.audit --path=/home/projects/my_app --format=json")
    IO.puts("")
    IO.puts("Options:")
    IO.puts("--path                  The root path of the project to audit")
    IO.puts("--format                The format of the report to generate (human, json)")
    IO.puts("--ignore-advisory-ids   A comma-separated list of advisory IDs to ignore")
    IO.puts("--ignore-package-names  A comma-separated list of package names to ignore")
    IO.puts("--ignore-file           Path of the ignore file")
    IO.puts("--ignore-unfixed        Ignore vulnerabilities that haven't been fixed yet")
    IO.puts("--fix                   Update vulnerable packages to a patched version and halts on failure")

    IO.puts(
      "--attempt-fix           Attempt to update vulnerable packages to a patched version and do not halt on failure"
    )

    IO.puts("")
    System.halt(0)

    true
  end
end
