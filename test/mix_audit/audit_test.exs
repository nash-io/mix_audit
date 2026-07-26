defmodule MixAudit.AuditTest do
  use ExUnit.Case
  doctest MixAudit.Audit

  alias MixAudit.Audit

  test "report/2 includes vulnerabilities based on vulnerable version ranges" do
    dependencies = [
      %MixAudit.Dependency{
        package: "foo",
        version: "0.7.4",
        lockfile: "mix.lock",
        advisories: [
          %MixAudit.Advisory{
            id: "ABC-123",
            title: "Foo",
            package: "foo",
            url: "https://example.com",
            severity: "high"
          }
        ]
      }
    ]

    report = Audit.report(dependencies)
    [first_vulnerability | _] = report.vulnerabilities

    refute report.pass
    assert first_vulnerability.advisory.id == "ABC-123"
    assert first_vulnerability.advisory.severity == "high"
    assert first_vulnerability.dependency.package == "foo"
    assert first_vulnerability.dependency.version == "0.7.4"
  end

  test "report/2 includes vulnerabilities based on complex vulnerable version ranges" do
    dependencies = [
      %MixAudit.Dependency{
        package: "foo",
        version: "0.7.4",
        lockfile: "mix.lock",
        advisories: [
          %MixAudit.Advisory{
            id: "ABC-123",
            title: "Foo",
            package: "foo",
            url: "https://example.com",
            severity: "high"
          }
        ]
      }
    ]

    report = Audit.report(dependencies)
    [first_vulnerability | _] = report.vulnerabilities

    refute report.pass
    assert first_vulnerability.advisory.id == "ABC-123"
    assert first_vulnerability.advisory.severity == "high"
    assert first_vulnerability.dependency.package == "foo"
    assert first_vulnerability.dependency.version == "0.7.4"
  end
end
