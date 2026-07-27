defmodule MixAudit.Audit do
  def report(dependencies) do
    vulnerabilities =
      Enum.reduce(dependencies, [], fn dependency, memo ->
        dependency.advisories
        |> Enum.map(
          &%MixAudit.Vulnerability{
            advisory: &1,
            dependency: dependency
          }
        )
        |> (&(memo ++ &1)).()
      end)

    %MixAudit.Report{
      vulnerabilities: vulnerabilities,
      pass: Enum.empty?(vulnerabilities)
    }
  end
end
