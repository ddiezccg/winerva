#Requires -Version 2

<#
.SYNOPSIS
    A PowerShell script that creates a local administrator account and enables
    WinRM, for remote administration via Ansible.

.NOTES
    PREREQUISITES
     * This script is only intended to be run within PowerShell on MS Windows
       machines (not cross-platform compatible).
     * This script can only be executed on MS Windows 7 SP1 or later.

    STYLE
     * This code adheres to the style guidelines published at
       https://poshcode.gitbooks.io/powershell-practice-and-style/

    LICENSE
    Copyright (c) 2018 David Passarelli <dpassarelli@camelotcg.com>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
#>

[CmdletBinding()]
param()

# https://blogs.technet.microsoft.com/heyscriptingguy/2014/12/03/enforce-better-script-practices-by-using-set-strictmode/
#
Set-StrictMode -Version Latest

###################################
##### DEFINE GLOBAL CONSTANTS #####
###################################

# The version of this script. This number follows the specification set by
# https://semver.org
#
# See CHANGELOG.MD for change history.
#
Set-Variable SCRIPT_VERSION -Option Constant -Value "1.2.1"

# The official "version" number reported by Windows 7 with Service Pack 1
# installed. Obtained from
# https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
#
Set-Variable WIN7SP1_VERSION_ID -Option Constant -Value "6.1.7601"

# The value of $ErrorActionPreference before it is changed by this script. It
# will be reset just before the script exits.
#
Set-Variable PREVIOUS_EAP -Option Constant -Value $ErrorActionPreference

# `$PSScriptRoot` was only added as a built-in special variable starting with PS
# version 3.
#
try {
    if ([System.String]::IsNullOrEmpty($PSScriptRoot)) {
        # Adapted from https://stackoverflow.com/a/3667376
        Set-Variable PSScriptRoot -Option ReadOnly -Value (Split-Path $MyInvocation.MyCommand.Path -Parent)
    }
}
catch {
    Set-Variable PSScriptRoot -Option ReadOnly -Value (Split-Path $MyInvocation.MyCommand.Path -Parent)
}

# This hashtable contains various pieces of system information used throughout
# the script.
#
Set-Variable SCRIPT_DATA -Option Constant -Value @{
    # Self-explanatory. The hostname is added to the inventory file for
    # future use by Ansible playbooks.
    #
    HOSTNAME = $Env:ComputerName

    # The location on disk where downloaded scripts will be saved.
    # When the script is about to exit, these will be deleted.
    #
    DOWNLOAD_TO = (Join-Path $Home "Downloads")

    # The currently installed version of Windows.
    #
    WIN_VERSION = (Get-WmiObject -Class Win32_OperatingSystem).Version

    # The latest version of .NET that appears to be installed on this
    # machine. Based on https://stackoverflow.com/a/1565454
    #
    NET_VERSION = (Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | `
                   Get-ItemProperty -Name Version,Release -ErrorAction SilentlyContinue | `
                   ? { $_.PSChildName -Match '^(?!S)\p{L}'} | `
                   Sort-Object -Property Version | `
                   Select-Object -Last 1).Version

    # The major version number for PowerShell.
    #
    PS_MAJOR_VERSION = $PSVersionTable.PSVersion.Major

    # The absolute path to the inventory file (which contains all of the
    # host names).
    #
    INVENTORY_FILE = (Join-Path $PSScriptRoot "hostnames")
}

###################################
#####     DEFINE FUNCTIONS    #####
###################################

function Write-LogMessage {
    <#
    .SYNOPSIS
        Displays a message on the console. Encapsulating this in a function
        provides an easy way to ensure that debug messages will stand out from
        other output.

    .PARAMETER Msg
        The message to display.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$Msg
    )

    Write-Host "[LOG]  $Msg"
}

function Verify-MinimumWindowsVersion {
    <#
    .SYNOPSIS
        Checks to see if the specified version number meets the minimum
        requirement for this script.

    .PARAMETER Version
        The version identifier for the current OS. Can be determined via
        (Get-WmiObject -Class Win32_OperatingSystem).Version

    .NOTES
        * Returns a boolean value.
        * See https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$Version
    )

    [Array]$versionParts = $Version.split(".")

    if ([Int]$versionParts[0] -gt 6) {
        return $true
    }

    if ([Int]$versionParts[0] -eq 6) {
        if ([Int]$versionParts[1] -gt 1) {
            return $true
        }

        if ([Int]$versionParts[1] -eq 1 -and [Int]$versionParts[2] -ge 7601) {
            return $true
        }
    }

    $false
}

function Verify-ElevatedShell {
    <#
    .SYNOPSIS
        Checks to see if the current execution context has Administrative
        privileges.

    .NOTES
        * Returns a boolean value.
        * Adapted from https://blogs.msdn.microsoft.com/virtual_pc_guy/2010/09/23/a-self-elevating-powershell-script/
    #>
    [CmdletBinding()]
    param()

    $CurrentUser = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    Return $CurrentUser.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Download-File {
    <#
    .SYNOPSIS
        Downloads the requested URL, and saves the file to the specified
        location.

    .PARAMETER Url
        The resource to download.

    .PARAMETER Destination
        The local path (including filename) that the download will be saved to.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$Url,

        [Parameter(Mandatory = $true)]
        [String]$Destination
    )

    (New-Object System.Net.WebClient).DownloadFile($Url, $Destination)
}

function Restart-Computer {
    <#
    .SYNOPSIS
        Initiates a restart sequence.
    #>
    [CmdletBinding()]
    param()

    Write-LogMessage "********* MACHINE WILL NOW REBOOT IN 30 SECONDS *********"
    Write-LogMessage "Re-run this script after the machine has come back up."
    shutdown /r /t 30
}

function PrepareFor-Exit {
    <#
    .SYNOPSIS
        Performs general clean-up immediately preceding the end of this script.

    .PARAMETER DownloadLocation
        The location where any files downloaded by this script were saved.

    .PARAMETER PreviousSettingForEAP
        The previous value for `$ErrorActionPreference`.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$DownloadLocation,

        [Parameter(Mandatory = $true)]
        [String]$PreviousSettingForEAP
    )

    ##### CLEAN UP
    Write-LogMessage "Removing downloaded scripts..."
    Get-ChildItem -Path $DownloadLocation -Include "__winerva__*.ps1" -Recurse | % { Remove-Item $_.Fullname }
    Write-LogMessage "done!"

    Write-LogMessage "Restoring previous value of ErrorActionPreference..."
    $ErrorActionPreference = $PreviousSettingForEAP
    Write-LogMessage "...done!"

    Write-LogMessage "END OF LINE"

    # If this script was launched via a "double-click", then keep the console
    # window open so that the user has a chance to review any output before it
    # suddenly disappears. Adapted from
    # http://blog.danskingdom.com/allow-others-to-run-your-powershell-scripts-from-a-batch-file-they-will-love-you-for-it/
    #
    Write-Host "Press any key to exit..."

    try {
        $Host.UI.RawUI.FlushInputBuffer()
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null
    }
    catch {
        # ignore
    }
}

###################################
#####     MAIN ALGORITHM      #####
###################################

##### SET ERRORACTIONPREFERENCE

# The reason for setting this value is to ensure that all unhandled
# exceptions cause the script to throw a terminating error (instead of
# non-terminating).
#
Write-LogMessage "Setting ErrorActionPreference to 'Stop'..."
$ErrorActionPreference = "Stop"
Write-LogMessage "...done!"

try {
    Write-LogMessage "++++++ BEGIN INSTALLATION ++++++"
    Write-LogMessage "++++++++ WINERVA v$SCRIPT_VERSION ++++++++"

    # Echo the collected data back out to the console. This should help with
    # debugging problems in the field.
    #
    Write-LogMessage "Printing script data..."
    Format-List -InputObject $SCRIPT_DATA
    Write-LogMessage "...done!"

    ##### CHECK PREREQUISITES

    Write-LogMessage "Checking prerequisites..."

    if (Verify-ElevatedShell) {
        Write-LogMessage "  * running in elevated shell"
    }
    else {
        throw "This script requires administrative privileges!"
    }

    if (Verify-MinimumWindowsVersion $SCRIPT_DATA.WIN_VERSION) {
        Write-LogMessage "  * OS is at least Windows 7 SP1"
    }
    else {
        throw "This script can only be run on Windows 7 SP1 or later."
    }

    Write-LogMessage "...done!"

    ##### INSTALL CHOCOLATEY

    Write-LogMessage "Checking for Chocolatey..."
    [Boolean]$upgradeChocolatey = $false

    try {
        Get-Command "choco.exe" | Out-Null
        Write-LogMessage "...found."
        $upgradeChocolatey = $true
    }
    catch {
        Write-LogMessage "...not found. Downloading installation script..."

        [String]$pathToChocolateyScript = (Join-Path $SCRIPT_DATA.DOWNLOAD_TO "__winerva__InstallChocolatey.ps1")
        Download-File -Url "https://chocolatey.org/install.ps1" -Dest $pathToChocolateyScript

        Write-LogMessage "...done!"

        Write-LogMessage "Executing..."
        . $pathToChocolateyScript
        Write-LogMessage "...done!"

        # On Windows 7, the machine must be restarted after installing
        # Chocolatey.
        #
        if ($SCRIPT_DATA.WIN_VERSION -eq $WIN7SP1_VERSION_ID) {
            Restart-Computer
            PrepareFor-Exit -DownloadLocation $SCRIPT_DATA.DOWNLOAD_TO -PreviousSettingForEAP $PREVIOUS_EAP
            Exit
        }
    }

    if ($upgradeChocolatey) {
        Write-LogMessage "Ensuring latest version is installed..."
        choco upgrade -y chocolatey
        Write-LogMessage "...done!"
    }

    refreshenv

    ##### UPDATE .NET

    if ($SCRIPT_DATA.NET_VERSION -lt "4.5") {
        Write-LogMessage "Installing .NET 4.5..."
        choco install -y dotnet4.5
        Write-LogMessage "...done!"

        Restart-Computer
        PrepareFor-Exit -DownloadLocation $SCRIPT_DATA.DOWNLOAD_TO -PreviousSettingForEAP $PREVIOUS_EAP
        Exit
    }

    ##### UPDATE POWERSHELL

    if ($SCRIPT_DATA.PS_MAJOR_VERSION -lt 5) {
        Write-LogMessage "Ensuring latest version of PowerShell is installed..."
        choco install -y powershell
        Write-LogMessage "...done!"

        Restart-Computer
        PrepareFor-Exit -DownloadLocation $SCRIPT_DATA.DOWNLOAD_TO -PreviousSettingForEAP $PREVIOUS_EAP
        Exit
    }

    ##### CARBON

    Write-LogMessage "Ensuring PS Carbon is installed..."

    choco install -y carbon
    Import-Module "Carbon"

    Write-LogMessage "...done!"

    ##### READ LOCAL CONFIG

    Write-LogMessage "Reading local configuration file..."
    [Hashtable]$configData = Import-PowerShellDataFile (Join-Path $PSScriptRoot "config.psd1")
    Write-LogMessage "...done!"

    ##### CREATE LOCAL USER

    Write-LogMessage "Ensuring local user is present..."

    [SecureString]$passwordAsSecureString = ConvertTo-SecureString $configData.LocalAdmin.Password -AsPlainText -Force
    [PSCredential]$adminCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $configData.LocalAdmin.Username, $passwordAsSecureString

    Install-User `
        -Credential  $adminCredentials `
        -Description $configData.LocalAdmin.Description `
        -UserCannotChangePassword

    Write-LogMessage "...done!"

    Write-LogMessage "Ensuring local user is added to Administrators group..."

    Add-GroupMember `
        -Name Administrators `
        -Member $configData.LocalAdmin.Username

    Write-LogMessage "...done!"

    ##### ENABLE WINRM FOR ANSIBLE
    Write-LogMessage "Downloading script to enable WinRM for Ansible..."

    [String]$pathToAnsibleScript = (Join-Path $SCRIPT_DATA.DOWNLOAD_TO "__winerva__ConfigureRemotingForAnsible.ps1")
    Download-File -Url "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1" -Dest $pathToAnsibleScript

    Write-LogMessage "...done!"

    Write-LogMessage "Executing..."
    . $pathToAnsibleScript
    Write-LogMessage "...done!"

    ##### ADD HOSTNAME TO INVENTORY FILE

    Write-LogMessage "Checking if computer name is already included in inventory for Ansible..."

    try {
        $inventory = (Get-Content -Path $SCRIPT_DATA.INVENTORY_FILE)
        if ($inventory -eq $null) {
            $inventory = ""
        }
   }
    catch {
        $inventory = ""
    }

    if ($inventory.Contains($SCRIPT_DATA.HOSTNAME)) {
        Write-LogMessage "...present."
    }
    else {
        Write-LogMessage "not found, adding..."
        Add-Content -Path $SCRIPT_DATA.INVENTORY_FILE -Value "$([System.Environment]::NewLine)$($SCRIPT_DATA.HOSTNAME)"
        Write-LogMessage "...done!"
    }

    # The following was adapted from https://stackoverflow.com/a/11002660
    Write-LogMessage "Removing extraneous blank lines from inventory file..."
    (Get-Content $SCRIPT_DATA.INVENTORY_FILE) | ? { -not [System.String]::IsNullOrWhiteSpace($_) } | Set-Content $SCRIPT_DATA.INVENTORY_FILE
    Write-LogMessage "...done!"

    Write-LogMessage "+++++ INSTALLATION COMPLETE ++++"
}
catch {
    Write-LogMessage "****** ERROR ******"
    Write-LogMessage $_.Exception.Message
    Write-LogMessage $_.InvocationInfo.PositionMessage
    Write-LogMessage "*******************"
}
finally {
    PrepareFor-Exit -DownloadLocation $SCRIPT_DATA.DOWNLOAD_TO -PreviousSettingForEAP $PREVIOUS_EAP
}
