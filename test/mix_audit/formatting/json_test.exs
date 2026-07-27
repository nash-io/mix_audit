defmodule MixAudit.Formatting.JSONTest do
  use ExUnit.Case

  alias MixAudit.Formatting.JSON

  test "format/1 with vulnerabilities" do
    report = %MixAudit.Report{
      pass: false,
      vulnerabilities: [
        %MixAudit.Vulnerability{
          advisory: %MixAudit.Advisory{
            id: "ABC-123",
            title: "Foo",
            package: "foo",
            url: "https://example.com",
            severity: "high"
          },
          dependency: %MixAudit.Dependency{
            package: "foo",
            version: "0.7.4",
            lockfile: "mix.lock"
          }
        }
      ]
    }

    report = JSON.format(report)
    assert decoded_report = Jason.decode!(report)
    refute decoded_report["pass"]

    assert decoded_report["vulnerabilities"] == [
             %{
               "dependency" => %{
                 "package" => "foo",
                 "version" => "0.7.4",
                 "lockfile" => "mix.lock",
                 "advisories" => nil,
                 "repo" => nil
               },
               "advisory" => %{
                 "id" => "ABC-123",
                 "title" => "Foo",
                 "package" => "foo",
                 "url" => "https://example.com",
                 "severity" => "high",
                 "cvss_score" => nil,
                 "first_patched_version" => nil
               }
             }
           ]
  end

  test "format/1 without vulnerabilities" do
    report = %MixAudit.Report{
      pass: true,
      vulnerabilities: []
    }

    report = JSON.format(report)
    assert decoded_report = Jason.decode!(report)
    assert decoded_report["pass"]

    assert decoded_report["vulnerabilities"] == []
  end
end
