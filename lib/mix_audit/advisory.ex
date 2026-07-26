defmodule MixAudit.Advisory do
  @derive Jason.Encoder
  defstruct id: nil,
            package: nil,
            url: nil,
            title: nil,
            severity: nil,
            cvss_score: nil,
            first_patched_version: nil
end
