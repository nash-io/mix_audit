defmodule MixAudit.Repo do
  alias MixAudit.Dependency

  @spec put_advisories([Dependency.t()]) :: [Dependency.t()]
  def put_advisories(dependencies) do
    hex_config = :hex_core.default_config()

    Enum.map(dependencies, fn %Dependency{} = dependency ->
      {:ok, {200, _, %{releases: releases} = result}} = :hex_repo.get_package(hex_config, dependency.package)
      pkg_advisories = result[:advisories] || []
      release = Enum.find(releases, &(&1.version == dependency.version))
      advisory_indexes = release[:advisory_indexes] || []

      release_advisories =
        Enum.map(advisory_indexes, fn advisory_index ->
          advisory = Enum.at(pkg_advisories, advisory_index)

          first_patched_release =
            Enum.find(
              releases,
              &(Version.compare(&1.version, dependency.version) == :gt and
                  advisory_index not in (&1[:advisory_indexes] || []))
            )

          first_patched_version = first_patched_release && first_patched_release.version

          %MixAudit.Advisory{
            id: advisory.id,
            package: dependency.package,
            url: advisory.html_url,
            title: advisory.summary,
            severity: translate_severity(advisory.severity),
            cvss_score: advisory.cvss_score,
            first_patched_version: first_patched_version
          }
        end)

      %{dependency | advisories: release_advisories}
    end)
  end

  defp translate_severity(:SEVERITY_HIGH), do: "high"
  defp translate_severity(:SEVERITY_MEDIUM), do: "medium"
  defp translate_severity(:SEVERITY_LOW), do: "low"
end
