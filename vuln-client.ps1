param(
    [Parameter(Position = 0)]
    [string]$Command,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = 'Stop'
$baseUrl = if ($env:VULN_API_URL) { $env:VULN_API_URL.TrimEnd('/') } else { 'http://localhost:5095' }

function Show-Usage {
    Write-Output 'Commands:'
    Write-Output '  vuln add "Name" Low|Medium|High|Critical'
    Write-Output '  vuln get <vulnerability-id>'
    Write-Output '  vuln scan <gitlab-repository-url>'
    Write-Output '  vuln status <scan-id>'
    Write-Output '  vuln cancel <scan-id>'
}

function Assert-ArgumentCount([int]$Expected) {
    if ($Arguments.Count -ne $Expected) {
        Show-Usage
        exit 1
    }
}

try {
    switch ($Command) {
        'add' {
            Assert-ArgumentCount 2
            $body = @{ name = $Arguments[0]; severity = $Arguments[1] } | ConvertTo-Json -Compress
            $response = Invoke-RestMethod -Uri "$baseUrl/api/vulnerabilities" -Method Post `
                -ContentType 'application/json; charset=utf-8' -Body $body
            Write-Output "Vulnerability ID: $($response.id)"
        }
        'get' {
            Assert-ArgumentCount 1
            $response = Invoke-RestMethod -Uri "$baseUrl/api/vulnerabilities/$($Arguments[0])" -Method Get
            $response | ConvertTo-Json -Depth 10
        }
        'scan' {
            Assert-ArgumentCount 1
            $body = @{ repositoryUrl = $Arguments[0] } | ConvertTo-Json -Compress
            $response = Invoke-RestMethod -Uri "$baseUrl/api/scans" -Method Post `
                -ContentType 'application/json; charset=utf-8' -Body $body
            Write-Output "Scan ID: $($response.id)"
        }
        'status' {
            Assert-ArgumentCount 1
            $response = Invoke-RestMethod -Uri "$baseUrl/api/scans/$($Arguments[0])" -Method Get
            $response | ConvertTo-Json -Depth 10
        }
        'cancel' {
            Assert-ArgumentCount 1
            $response = Invoke-RestMethod -Uri "$baseUrl/api/scans/$($Arguments[0])" -Method Delete
            $response | ConvertTo-Json -Depth 10
        }
        default {
            Show-Usage
            exit 1
        }
    }
}
catch {
    $message = $_.Exception.Message

    if ($_.Exception.Response) {
        $response = $_.Exception.Response
        $message = "HTTP $([int]$response.StatusCode)"
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $body = $reader.ReadToEnd()
        $reader.Dispose()

        if ($body) {
            try {
                $details = $body | ConvertFrom-Json
                if ($details.error) {
                    $message += ": $($details.error)"
                }
            }
            catch {
                $message += ": $body"
            }
        }
    }

    [Console]::Error.WriteLine($message)
    exit 1
}
