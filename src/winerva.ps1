#Requires -Version 2

#
# .SYNOPSIS
#
# A PowerShell script that creates a local administrator account and enables
# WinRM, for remote administration via Ansible.
#
# .NOTES
#
# Copyright (c) 2018 David Passarelli
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# The following attribute enables this script to implement common parameters.
# See https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters
#
[CmdletBinding()]
Param()

# https://blogs.technet.microsoft.com/heyscriptingguy/2014/12/03/enforce-better-script-practices-by-using-set-strictmode/
#
Set-StrictMode -Version Latest

###################################
#####     DEFINE FUNCTIONS    #####
###################################

# Displays a message on the console. Encapsulating this in a function provides
# an easy way to ensure that debug messages will stand out from other output.
#
Function Write-LogMessage {
    Param(
        [string]$msg
    )

    Write-Host "[LOG]  $msg"
}

# Checks to see if the current execution context has Administrative privileges.
# Returns a boolean value.
#
Function Verify-ElevatedShell {
    # Adapted from https://blogs.msdn.microsoft.com/virtual_pc_guy/2010/09/23/a-self-elevating-powershell-script/
    $CurrentUser = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    Return $CurrentUser.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Downloads the requested URL, and saves the file to the specified location.
#
Function Download-File {
    Param(
        [string]$url,
        [string]$dest
    )
    (New-Object System.Net.WebClient).DownloadFile($url, $dest)
}

# Initiates a restart sequence.
#
Function Restart-Computer {
    Write-LogMessage "********* MACHINE WILL NOW REBOOT IN 30 SECONDS *********"
    Write-LogMessage "Re-run this script after the machine has come back up."
    shutdown /r /t 30
}

# Performs general clean-up immediately preceding the end of this script.
#
Function PrepareFor-Exit {
    ##### CLEAN UP
    Write-LogMessage "Removing downloaded scripts..."
    Get-ChildItem $DownloadTo -Include "__winerva__*.ps1" -Recurse | % { Remove-Item $_.Fullname }
    Write-LogMessage "done!"

    Write-LogMessage "Restoring previous value of ErrorActionPreference..."
    $ErrorActionPreference = $CONST_PREV_EAP
    Write-LogMessage "...done!"

    Write-LogMessage "END OF LINE"

    # If this script was launched via a "double-click", then keep the console
    # window open so that the user has a chance to review any output before it
    # suddenly disappears. Adapted from
    # http://blog.danskingdom.com/allow-others-to-run-your-powershell-scripts-from-a-batch-file-they-will-love-you-for-it/
    #
    Write-Host "Press any key to exit..."
    $Host.UI.RawUI.FlushInputBuffer()
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null
}

###################################
##### DEFINE GLOBAL CONSTANTS #####
###################################

# The value of $ErrorActionPreference before it is changed by this script. It
# will be reset just before the script exits.
#
[string]$CONST_PREV_EAP = $ErrorActionPreference

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

Try {
    Write-LogMessage "++++++ BEGIN INSTALLATION ++++++"
    Write-LogMessage "++++++ +++++ v1.2.0 +++++ ++++++"

    ##### GET DOWNLOAD FOLDER FOR CURRENT USER
    Write-LogMessage "Getting download folder..."

    $DownloadTo = (Join-Path $Home "Downloads")
    Write-LogMessage $DownloadTo

    Write-LogMessage "...done!"

    ##### CHECK PREREQUISITES

    Write-LogMessage "Checking prerequisites..."

    If (Verify-ElevatedShell) {
        Write-LogMessage "  * running in elevated shell"
    }
    Else {
        Throw "This script requires administrative privileges!"
    }

    Write-LogMessage "...done!"

    ##### SYSTEM INFORMATION

    # A boolean value indicating if this script should attempt to upgrade
    # Chocolatey. This should only be true if Chocolatey is already installed.
    #
    $UpgradeChocolatey = $false

    # A string value indicating the version of Windows. Refer to
    # https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
    # for more information.
    #
    $WindowsVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version

    # A string value indicating the latest version of .NET that appears to be
    # installed on this machine. Based on https://stackoverflow.com/a/1565454
    $LatestVersionOfNET = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | `
                           Get-ItemProperty -Name Version,Release -ErrorAction SilentlyContinue | `
                           ? { $_.PSChildName -Match '^(?!S)\p{L}'} | `
                           Sort-Object -Property Version | `
                           Select-Object -Last 1).Version

    # A object containing the major and minor version numbers for PowerShell.
    $PowerShellVersion = $PSVersionTable.PSVersion

    Write-LogMessage "Windows version is $WindowsVersion"
    Write-LogMessage "Latest version of .NET is $LatestVersionOfNET"
    Write-LogMessage "PowerShell version is $($PowerShellVersion.Major).$($PowerShellVersion.Minor)"

    ##### CHOCOLATEY
    Write-LogMessage "Checking for Chocolatey..."
    Try {
        Get-Command "choco.exe" | Out-Null
        Write-LogMessage "...found."
        $UpgradeChocolatey = $true
    }
    Catch {
        Write-LogMessage "...not found. Downloading installation script..."

        [string]$PathToChocolateyScript = (Join-Path $DownloadTo "__winerva__InstallChocolatey.ps1")
        Download-File "https://chocolatey.org/install.ps1" $PathToChocolateyScript

        Write-LogMessage "...done!"

        Write-LogMessage "Executing..."
        . $PathToChocolateyScript
        Write-LogMessage "...done!"

        # On Windows 7, the machine must be restarted after installing
        # Chocolatey.
        If ($WindowsVersion -lt "6.2" -And $LatestVersionOfNET -lt "4.0") {
            Restart-Computer
            PrepareFor-Exit
            Exit
        }

        $UpgradeChocolatey = $false
    }

    If ($UpgradeChocolatey) {
        Write-LogMessage "Ensuring latest version is installed..."
        choco upgrade -y chocolatey
        Write-LogMessage "...done!"
    }

    refreshenv

    ##### UPDATE .NET

    If ($LatestVersionOfNET -lt "4.5") {
        Write-LogMessage "Installing .NET 4.5..."
        choco install -y dotnet4.5
        Write-LogMessage "done!"

        Restart-Computer
        PrepareFor-Exit
        Exit
    }

    ##### UPDATE POWERSHELL

    If ($PowerShellVersion.Major -lt 5) {
        Write-LogMessage "Ensuring latest version of PowerShell is installed..."
        choco install -y powershell
        Write-LogMessage "...done!"

        Restart-Computer
        PrepareFor-Exit
        Exit
    }

    ##### CARBON
    Write-LogMessage "Ensuring PS Carbon is installed..."

    choco install -y carbon
    Import-Module "Carbon"

    Write-LogMessage "...done!"

    ##### READ LOCAL CONFIG

    Write-LogMessage "Reading local configuration file..."
    [PSCustomObject]$ConfigData = Import-PowerShellDataFile (Join-Path $PSScriptRoot "config.psd1")
    Write-LogMessage "...done!"

    ##### CREATE LOCAL USER

    Write-LogMessage "Ensuring local user is present..."

    [SecureString]$PasswordAsSecureString = ConvertTo-SecureString $ConfigData.LocalAdmin.Password -AsPlainText -Force
    [PSCredential]$AdminCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ConfigData.LocalAdmin.Username, $PasswordAsSecureString

    Install-User `
        -Credential  $AdminCredentials `
        -Description $ConfigData.LocalAdmin.Description `
        -UserCannotChangePassword

    Write-LogMessage "...done!"

    Write-LogMessage "Ensuring local user is added to Administrators group..."

    Add-GroupMember `
        -Name Administrators `
        -Member $ConfigData.LocalAdmin.Username

    Write-LogMessage "...done!"

    ##### ENABLE WINRM FOR ANSIBLE
    Write-LogMessage "Downloading script to enable WinRM for Ansible..."

    [string]$PathToAnsibleScript = (Join-Path $DownloadTo "__winerva__ConfigureRemotingForAnsible.ps1")
    Download-File "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1" $PathToAnsibleScript

    Write-LogMessage "...done!"

    Write-LogMessage "Executing..."
    . $PathToAnsibleScript
    Write-LogMessage "...done!"

    ##### ADD HOSTNAME TO INVENTORY FILE
    Write-LogMessage "Checking if computer is already included in inventory for Ansible..."

    $PathToInventoryFile = (Join-Path $PSScriptRoot "hostnames")

    Try {
        $Inventory = (Get-Content -Path $PathToInventoryFile)
    }
    Catch {
        $Inventory = ""
    }

    If ($Inventory.Contains($Env:ComputerName)) {
        Write-LogMessage "present."
    }
    Else {
        Write-LogMessage "not found, adding..."
        Add-Content -Path $PathToInventoryFile -Value "$([System.Environment]::NewLine)$Env:ComputerName"
        Write-LogMessage "done!"
    }

    # The following was adapted from https://stackoverflow.com/a/11002660
    Write-LogMessage "Removing extraneous blank lines from inventory file..."
    (Get-Content $PathToInventoryFile) | ? { -not [System.String]::IsNullOrWhiteSpace($_) } | Set-Content $PathToInventoryFile
    Write-LogMessage "done!"

    Write-LogMessage "++++++ PROCESS COMPLETE ++++++"
}
Catch {
    Write-LogMessage "****** ERROR ******"
    Write-LogMessage $_.Exception.Message
    Write-LogMessage $_.InvocationInfo.PositionMessage
    Write-LogMessage "*******************"
}
Finally {
    PrepareFor-Exit
}
