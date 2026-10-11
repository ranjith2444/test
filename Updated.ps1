
# Full Key Vault URL, e.g. https://my-keyvault.vault.azure.net/
$KeyVaultUrl = "https://my-keyvault.vault.azure.net/"

# Key Vault secret name that stores the ServiceNow username
$UsernameSecretName = "servicenow-user"

# Key Vault secret name that stores the ServiceNow password
$PasswordSecretName = "servicenow-pass"

# ServiceNow instance base URL
$ServiceNowBaseUrl = "https://apmprod.service-now.com"

$ErrorActionPreference = 'Stop'

# Get-AzKeyVaultSecret expects the short vault name, so derive it from the URL.
$KeyVaultName = ([System.Uri]$KeyVaultUrl).Host.Split('.')[0]

function Invoke-ServiceNowRequest {
    <#
        Wraps Invoke-WebRequest for ServiceNow, enforces TLS 1.2, and validates the HTTP status
        code so a failed call throws instead of silently continuing.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][ValidateSet('Get', 'Post', 'Patch', 'Put')][string]$Method,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Headers,
        [string]$Body,
        [string]$ContentType,
        [int[]]$ExpectedStatusCodes = @(200, 201)
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Body'))     { $params.Body = $Body }
    if (-not [string]::IsNullOrEmpty($ContentType)) { $params.ContentType = $ContentType }

    try {
        $response = Invoke-WebRequest @params
    }
    catch {
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        throw "ServiceNow $Method '$Uri' failed (HTTP $status): $($_.Exception.Message)"
    }

    if ($ExpectedStatusCodes -notcontains [int]$response.StatusCode) {
        throw "ServiceNow $Method '$Uri' returned unexpected HTTP $([int]$response.StatusCode)."
    }

    return $response
}

# Connect to Azure using the managed identity, then exchange for a Microsoft Graph token.
Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    $AccessToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop 
   
   Connect-MgGraph -AccessToken ($AccessToken.Token | ConvertTo-SecureString -AsPlainText -Force) -ErrorAction Stop | Out-Null
   
 
# Connect to Microsoft Graph
#Connect-MgGraph -Scopes "Application.Read.All", "Application.ReadWrite.All"
 
# Get all applications
$applications = Get-MgApplication -All
 
# Initialize a list to store the data
$data = @()
 
# Get the current date, the date 30 days ago, and the date 30 days from now
$currentDate = Get-Date
$pastDate = $currentDate.AddDays(-30)
$futureDate = $currentDate.AddDays(30)
 
# Loop through each application and get details
foreach ($app in $applications) {
    $appId = $app.AppId
    $appName = $app.DisplayName
 
    # Get client secrets using the Microsoft Graph API
    $secrets = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)/passwordCredentials"
 
    foreach ($secret in $secrets.value) {
        $endDate = if ($secret.endDateTime) { [DateTime]::Parse($secret.endDateTime) } else { $null }
 
        # Check if the secret expired in the past 30 days or will expire in the next 30 days
        if ($endDate -and ($endDate -ge $pastDate -and $endDate -le $futureDate)) {
            $startDate = if ($secret.startDateTime) { [DateTime]::Parse($secret.startDateTime).ToString("yyyy-MM-dd") } else { "N/A" }
            $endDateFormatted = $endDate.ToString("yyyy-MM-dd")
 
            $data += [PSCustomObject]@{
                ApplicationName = $appName
                ApplicationId   = $appId
                SecretId        = $secret.KeyId
                StartDate       = $startDate
                EndDate         = $endDateFormatted
            }
        }
    }
}
#$null = Invoke-WebRequest -Uri 'https://advancedpersonnelmanagement.webhook.office.com/webhookb2/fc8f106b-048c-4253-a17a-15db3be307c2@fa7adf0d-de2d-4570-8f5f-4bca4772988f/IncomingWebhook/1daa09efe8f9434ca25edca5816630a9/3e552c92-97fc-4c0b-b257-a8407ddc6946/V2DtSCSNGb66hAme8rgcZdwLzeRSOgoh-l8ncwzwMsW1o1%27 ‑Method Post -Body %22test%22
#Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body '{"text":"Hello World!"}' -Uri 'https://advancedpersonnelmanagement.webhook.office.com/webhookb2/fc8f106b-048c-4253-a17a-15db3be307c2@fa7adf0d-de2d-4570-8f5f-4bca4772988f/IncomingWebhook/1daa09efe8f9434ca25edca5816630a9/3e552c92-97fc-4c0b-b257-a8407ddc6946/V2DtSCSNGb66hAme8rgcZdwLzeRSOgoh-l8ncwzwMsW1o1%27
$data
 
if (-not $data -or @($data).Count -eq 0) {
    Write-Output "No client secrets expiring within the monitored window. No ServiceNow incident created."
    return
}

#region APISetup
$cred = [System.Net.CredentialCache]::DefaultCredentials
[System.Net.WebRequest]::DefaultWebProxy.Credentials = $cred 
# Retrieve ServiceNow credentials from Key Vault using the managed identity
$user = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $UsernameSecretName -AsPlainText
$pass = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $PasswordSecretName -AsPlainText

if ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($pass)) {
    throw "Failed to retrieve ServiceNow credentials from Key Vault '$KeyVaultName'."
}
# Build auth header
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $pass)))
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Global:headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$Global:headers.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
$Global:headers.Add('Accept','text/xml')
$Global:headers.Add('Content-Type','text/xml')
#endregion
 
        $uri = "$ServiceNowBaseUrl/api/now/table/incident?sysparm_display_value=all"
 
        # Specify HTTP method
        $method = "post"
 
        # Specify request body
        $body = "<request>
                    <entry>
                        <u_type>Incident</u_type>
                        <short_description>ClientSecret expired past 30 days or expiring in next 30 days </short_description>
                        <contact_type>Self-Service</contact_type>
                        <u_business_service>5246ace5dba63e009d6575a9bf9619b6</u_business_service>
                        <u_requestor>infrastructurereport infrastructurereport</u_requestor>
                        
                    </entry>
                </request>"
 
        # Send HTTP request
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 
        $response = Invoke-ServiceNowRequest -Uri $uri -Method 'Post' -Body $body -Headers $Global:headers -ExpectedStatusCodes @(200, 201)
 
        # Get Response details
        $xmlcontent = [xml]$response.Content
        $sys_id = $xmlcontent.response.result.sys_id.value

        if ([string]::IsNullOrWhiteSpace($sys_id)) {
            throw "ServiceNow did not return a sys_id; incident creation could not be confirmed. Response: $($response.Content)"
        }

        Write-Output "Created ServiceNow incident (sys_id: $sys_id)."

        #Update content
        $WorkNotes = "[code]"
        $WorkNotes += $data|ConvertTo-Html  -Fragment -As List
        $WorkNotes += "[/code]"
        $Body = [pscustomobject]@{
            work_notes = $WorkNotes
        }        
 
        #Add Content
        $uri = "$ServiceNowBaseUrl/api/now/table/incident/$($sys_id)"
        $method = "patch"
        $body = $Body|ConvertTo-Json   
 
        $response = Invoke-ServiceNowRequest -Uri $uri -Method 'Patch' -Body $body -Headers $Global:headers -ContentType "application/json" -ExpectedStatusCodes @(200)
        
        # Get Response details after update
        $xmlcontent = [xml]$response.Content
        $sys_id = $xmlcontent.response.result.sys_id.value      
