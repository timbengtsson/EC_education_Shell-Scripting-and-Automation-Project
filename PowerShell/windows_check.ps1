# ==========================================================
# Script name: windows_check 
#
# Purpose:
# - Check if there are any dangerous Windows services running.
# - Check if there are any new users since last run
# 
# ==========================================================

 
# ==================================================
# Global variables
# ================================================== 

[CmdletBinding()]
param( 
    [string[]] $RiskyServiceNames = @("TlntSvr","RemoteRegistry","Spooler")
)

$ScriptDir = $PSScriptRoot
$DataDir = Join-Path $ScriptDir "data"
$UsersDir = Join-Path $DataDir "users"
$ServicesDir = Join-Path $DataDir "services"
$LogPath = Join-Path $DataDir "windows_check.log" 


# Create DataDir if missing
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir | Out-Null
}

# Create UsersDir if missing
if (-not (Test-Path $UsersDir)) {
    New-Item -ItemType Directory -Path $UsersDir | Out-Null
}
  
# Create ServicesDir if missing
if (-not (Test-Path $ServicesDir)) {
    New-Item -ItemType Directory -Path $ServicesDir | Out-Null
}
 

$levelRank = @{ "INFO" = 1; "WARNING" = 2; "HIGH" = 3; "ERROR" = 4 }


# ==================================================
# Logging
# ==================================================
function Write-Log {
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet("INFO","WARNING","HIGH","ERROR")]
        [string] $Level = "INFO"
    )  
  
    $effectiveMin = if ($script:MinLogLevel) { $script:MinLogLevel } else { "INFO" }
 
    if (-not $levelRank.ContainsKey($Level)) { $Level = "INFO" }
    if (-not $levelRank.ContainsKey($effectiveMin)) { $effectiveMin = "INFO" }

    if ($levelRank[$Level] -lt $levelRank[$effectiveMin]) { return }


    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd_HHmmss"), $Level, $Message
    $line | Out-File -FilePath $LogPath -Append -Encoding utf8
    if ($Level -in @("WARNING","HIGH","ERROR")) { Write-Host $line }
}


function Get-Services {
    # return Get-Service | Select-Object Name, Status 
    return Get-Service
}


function Check-Risky-Services {  
    param(
        [Parameter(Mandatory)]
        [System.ServiceProcess.ServiceController[]] $Services,

        [Parameter(Mandatory)]
        [string[]] $RiskyServiceNames 
    ) 
   
    # Loop through the risky names and check if we got any, Log if they are running
    foreach ($svc in $Services) { 
        if ($RiskyServiceNames -contains $svc.Name -and $svc.Status -eq "Running") {
            Write-Log -Level "HIGH" -Message "VARNING - Riskabel Windows-tjänst upptäckt: $($svc.Name)"
        }
    }
}


function Save-Services {
    param(
        [Parameter(Mandatory)]
        [System.ServiceProcess.ServiceController[]] $Services,

        [Parameter(Mandatory)] 
        [string[]] $ServicesDir
    )  
  
    $Datetime = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $outFile = Join-Path $ServicesDir "$Datetime.json"
    $Services |
        Select-Object Name, DisplayName, Status, StartType |
        ConvertTo-Json -Depth 3 |
        Out-File -FilePath $outFile -Encoding utf8 
}
 

function Save-Users {
    param(
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.LocalUser[]] $Users,

        [Parameter(Mandatory)] 
        [string[]] $Dir
    ) 
  
    $Datetime = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $Users |
        Select-Object Name, Enabled, LastLogon, PasswordExpires, SID.Value |
        ConvertTo-Json -Depth 3 |
        Out-File -FilePath "$Dir/$Datetime.json" -Encoding utf8 
}


function Get-PreviousSnapshot {
    param([Parameter(Mandatory)][string] $Dir)

    $files = Get-ChildItem -Path $Dir -Filter "*.json" -File |
        Sort-Object LastWriteTime -Descending

    if ($files.Count -lt 2) { return $null }
 
    return Get-Content -Raw -Path $files[1].FullName | ConvertFrom-Json
}


function Find-Created-Deleted-Services{
    param( 
        [Parameter(Mandatory)]
        [System.ServiceProcess.ServiceController[]] $Services,

        [Parameter(Mandatory)] 
        [string[]] $Dir,  

        [Parameter()]
        [object[]] $OldServices
    )
 
    if ($OldServices) {
        $diffServices = Compare-Object `
            -ReferenceObject ($OldServices | Select-Object -ExpandProperty Name) `
            -DifferenceObject ($Services    | Select-Object -ExpandProperty Name)

        foreach ($d in $diffServices) {
            if ($d.SideIndicator -eq "=>") { Write-Log -Level "WARNING" -Message "Ny tjänst: $($d.InputObject)" }
            if ($d.SideIndicator -eq "<=") { Write-Log -Level "INFO" -Message "Tjänst borttagen: $($d.InputObject)" }
        }
    } 
    else {
        Write-Log -Level "WARNING" -Message "Ingen tidigare services-snapshot att jämföra mot. Är det första gången analysen körs är det helt normalt."
    }
}


function Find-Created-Deleted-Users {
    param(
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.LocalUser[]] $Users,

        [Parameter(Mandatory)] 
        [string[]] $Dir, 
 
        [Parameter()]
        [object[]] $OldUsers
    )   
    
    if ($OldUsers) {
        $diffUsers = Compare-Object `
            -ReferenceObject ($OldUsers | Select-Object -ExpandProperty Name) `
            -DifferenceObject ($Users   | Select-Object -ExpandProperty Name)

        foreach ($d in $diffUsers) {
            if ($d.SideIndicator -eq "=>") { Write-Log -Level "WARNING" -Message "Ny användare: $($d.InputObject)" }
            if ($d.SideIndicator -eq "<=") { Write-Log -Level "WARNING" -Message "Användare borttagen: $($d.InputObject)" }
        }
    }
    else {
        Write-Log -Level "WARNING" -Message "Ingen tidigare users-snapshot att jämföra mot. Är det första gången analysen körs är det helt normalt."
    }
}


# ==================================================
# Main script
# ================================================== 
try {
    Write-Log -Level "INFO" -Message "Startar Windows service-kontroll."

    # Services ========================================================================
    
    # Get all Services 
    Write-Log -Level "INFO" -Message "Hämtar windows tjänster."
    $services = Get-Services

    # Save Services to a file
    Write-Log -Level "INFO" -Message "Sparar windows tjänster till en fil."
    Save-Services -Services $services -ServicesDir $ServicesDir 

    # Check-Risky business services
    Write-Log -Level "INFO" -Message "Kontrollerar om några risky tjänster körs."
    Check-Risky-Services -Services $services -RiskyServiceNames $RiskyServiceNames  

    $oldServices = Get-PreviousSnapshot -Dir $ServicesDir 
     
    # Check for new services  
    Write-Log -Level "INFO" -Message "Kontrollerar om några tjänster tagits bort eller lagts till sen förra skanningen."
    Find-Created-Deleted-Services -Services $services -Dir $ServicesDir -OldServices $oldServices

    # Users =========================================================================

    # Get Users  
    Write-Log -Level "INFO" -Message "Hämtar lokala windows användare."
    $users = Get-LocalUser 

    # Save Users
    Write-Log -Level "INFO" -Message "Sparar Användare till en fil."
    Save-Users -Users $users -Dir $UsersDir 
 
    $oldUsers = Get-PreviousSnapshot -Dir $UsersDir 

    # Check if we got any new or removed users
    Write-Log -Level "INFO" -Message "Kontrollerar om vi har nya Användare eller om någon tagits bort."
    Find-Created-Deleted-Users -Users $users -Dir $UsersDir -OldUsers $oldUsers
       
    Write-Log -Level "INFO" -Message "Windows-kontroll klar." 
}
catch {
    Write-Log -Level "ERROR" -Message ("Fel: {0}" -f $_.Exception.Message)
    exit 1
}


