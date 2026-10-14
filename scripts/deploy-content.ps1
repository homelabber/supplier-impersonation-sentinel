[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [string]$Location,

    [switch]$DeployWorkbook,

    [switch]$DeployAnalyticsRules,

    [switch]$EnableRules
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

if (-not $DeployWorkbook -and -not $DeployAnalyticsRules) {
    throw "Specify -DeployWorkbook, -DeployAnalyticsRules, or both."
}

$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
if (-not $Location) {
    $Location = $workspace.Location
}

if ($DeployWorkbook) {
    $seed = "$($workspace.ResourceId)|supplier-impersonation-monitoring"
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $workbookId = ([Guid]::new($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($seed)))).Guid
    $contentPath = Join-Path $root 'arm\workbook-content.json'
    $serializedData = Get-Content -LiteralPath $contentPath -Raw
    New-AzResourceGroupDeployment `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile (Join-Path $root 'arm\workbook.json') `
        -workbookDisplayName 'Supplier Impersonation Monitoring' `
        -workbookId $workbookId `
        -location $Location `
        -workspaceResourceId $workspace.ResourceId `
        -serializedData $serializedData
}

if ($DeployAnalyticsRules) {
    New-AzResourceGroupDeployment `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile (Join-Path $root 'arm\analytics-rules.json') `
        -workspaceName $WorkspaceName `
        -enableRules ([bool]$EnableRules)
}
