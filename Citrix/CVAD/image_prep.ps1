<#
.SYNOPSIS
    Image Prep Script for XenDesktop 7.x Bupa Estate
.DESCRIPTION
    Image Prep Script for XenDesktop 7.x Bupa Estate
.PARAMETER 
    None
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    Current Version:        1.2
    Creation Date:          06/11/2017
.CHANGE CONTROL
    Name                                            Version         Date                Change Detail
    David Brett / Ed Lawson / Andy Mallins          1.0             16/10/2017          Script Creation
    David Brett                                     1.1             10/11/2017          Added code to remove McAfee Agent Guid
    David Brett                                     1.2             10/11/2017          Added Try and Catch Module for Task Removal to prevent errors

.EXAMPLE
    ./xendesktop-7x-image-prep.ps1
.FEATURE REQUESTS
    Error with deleting c:\windows\temp files - need rights
    LocalGpoSaving: Verbose Logging
#>

# Get old Verbose Preference and storeit, change Verbose Preference to Continue
$OldVerbosePreference = $VerbosePreference
$VerbosePreference = "Continue"

# Clear out Temp Folder
Write-Verbose "Clearing out the Temp and Windows\Temp Folders"
Write-Verbose "Backing Up XenDesktop Windows 7 Specific Files"
Copy-Item "C:\Temp\reassign-cdrom.cmd" -Destination "C:\Windows\Temp\reassign-cdrom.cmd" -ErrorAction SilentlyContinue
Copy-Item "C:\Temp\reassign-cdrom.txt" -Destination "C:\Windows\Temp\reassign-cdrom.txt" -ErrorAction SilentlyContinue
Get-ChildItem C:\Temp | Remove-Item -Force -Recurse 
Write-Verbose "Restore XenDesktop Windows 7 Specific Files"
Copy-Item "C:\Windows\Temp\reassign-cdrom.cmd" -Destination "C:\Temp\reassign-cdrom.cmd" -ErrorAction SilentlyContinue
Copy-Item "C:\Windows\Temp\reassign-cdrom.txt" -Destination "C:\Temp\reassign-cdrom.txt" -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\Temp | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

# Remove App-V Client Packages
Write-Verbose "Removing the App-V Packages"
$Product = "Microsoft AppV Client"
$servicename1 = Get-Service -Name appvclient -ErrorAction SilentlyContinue

if ($servicename1.Status -ne "Running") {
    Write-Verbose "The client service is not running.The Script cannot clean up package files."
}
ELSE {
    $HKLM_Path = "HKLM:\Software\Microsoft\AppV\Client"
    $Installpath = Get-ItemProperty -path "$HKLM_Path" | % {$_.InstallPath}
    $ModuleFile = "AppvClient.psd1"
    $ModulePath = "$Installpath\AppvClient\$ModuleFile"
    $PckInstRoot = Get-ItemProperty -path "$HKLM_Path\Streaming" | % {$_.PackageInstallationRoot}
    $PckInstRoot = [Environment]::ExpandEnvironmentVariables($PckInstRoot)

    if (!$PckInstRoot) {
        Write-Verbose "PackageInstallationRoot is required for removing packages" -Type E       
    }
    IF (Test-Path $PckInstRoot) {
        $packageFiles = Get-ChildItem ([System.Environment]::ExpandEnvironmentVariables($PckInstRoot));
        if (!$packageFiles -or $packageFiles.Count -eq 0) {
            Write-Host "No package files found, nothing to clean up." -Type W
        }
        ELSE {
            Write-Verbose "Removing all App-V packages"
            $error.clear();
            # load the client
            import-module $ModulePath;
            # shutdown all active Connection Groups
            Write-Verbose "Stopping all connection groups.";
            Get-AppvClientConnectionGroup -all | Stop-AppvClientConnectionGroup -Global;

            # shutdown all active Connection Groups
            Write-Verbose "Stopping all connection groups.";
            Get-AppvClientConnectionGroup -all | Stop-AppvClientConnectionGroup -Global;

            # poll while there are still active connection groups
            $connectionGroups = Get-AppvClientConnectionGroup -all
            $connectionGroupsInUse = $FALSE;
            do {
                $connectionGroupsInUse = $FALSE;
                ForEach ($connectionGroup in $connectionGroups) {
                    if ($connectionGroup.InUse -eq $TRUE) {
                        $connectionGroupsInUse = $TRUE;
                        Write-Verbose "Stopping connection group " $connectionGroup.Name;
                        Stop-AppvClientConnectionGroup $connectionGroup -Global;
                                
                        # allow 1 second for the VE to tear down before we continue polling
                        sleep 1;
                    }
                }
            } while ($connectionGroupsInUse);

            # shutdown all active Packages
            Write-Verbose "Stopping all packages.";
            Get-AppvClientPackage -all | Stop-AppvClientPackage -Global;

            # poll while there are still active packages
            $packages = Get-AppvClientPackage -all;
            $packagesInUse = $FALSE;
            do {
                $packagesInUse = $FALSE;
                ForEach ($package in $packages) {
                    if ($package.InUse -eq $TRUE) {
                        $packagesInUse = $TRUE;
                        Write-Verbose "Stopping package " $package.Name;
                        Stop-AppvClientPackage $package -Global;

                        # allow 1 second for the VE to tear down before we continue polling
                        sleep 1;
                    }
                }
            } while ($packagesInUse);
    
            Write-Verbose "Removing all App-V Connection Groups";
            ForEach ($connectionGroup in Get-AppvClientConnectionGroup -all) {
                Remove-AppvClientConnectionGroup $connectionGroup;
            }

            Write-Verbose "Removing all App-V Packages";
            ForEach ($package in Get-AppvClientPackage -all) {
                Remove-AppvClientPackage $package;
            }
        }
        $Error.Clear();
        Get-ChildItem $PckInstRoot | Remove-Item -Force -Recurse 
    }
    ELSE {
        Write-Verbose "The AppV PackageInstallationRoot $PckInstRoot Folder not exist, nothing to clean up." -Type W
    }
}

# Reset Windows Update Agent GUID
Write-Verbose "Resetting the Windows Update Agent GUID"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientIdValidation" -ErrorAction SilentlyContinue
Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue

# Clear all Citrix Cache
Write-Verbose "Clearing all the Citrix Cache Folders"
$CTX_SYS32_CACHE_PATH = "C:\Program Files (x86)\Citrix\System32\Cache\*"
Remove-Item -Path $CTX_SYS32_CACHE_PATH -Recurse -ErrorAction SilentlyContinue

# Clear Software Distribution Folder
Write-Verbose "Clearing out the Software Distribution Folders"
$Dir_SwDistriPath = "C:\Windows\SoftwareDistribution\Download\*"
Remove-Item -Path $Dir_SwDistriPath -Recurse -ErrorAction SilentlyContinue

# Delete Windows Update Log File
Write-Verbose "Deleting the Windows Update Log Files"
$File_WindowsUpdateLog = "C:\Windows\WindowsUpdate.log"
Remove-Item $File_WindowsUpdateLog -ErrorAction SilentlyContinue

# Flush DNS Cache
Write-Verbose "Flushing the DNS Cache"
ipconfig /flushdns

# Clear Arp Cache
Write-Verbose "Clearing the ARP Cache"
arp -d *

# Reset Performance Counters
Write-Verbose "Resetting the Performance Counters"
lodctr.exe /r

# Clear out Event Logs
Write-Verbose "Clearing out the Event Logs"
wevtutil cl Application
wevtutil cl System
wevtutil cl Security

# AppSense Clean Up
Write-Verbose "Cleaning up the AppSense EM and PM Agent Cache"
$Product = "AppSense Client Communications Agent"
$servicename1 = Get-Service -Name appvclient -ErrorAction SilentlyContinue

if ($servicename1.Status -ne "Running") {
    Write-Verbose "AppSense is not installed on this XenDesktop Image"
}
ELSE {
    Write-Verbose "AppSense is installed on this XenDesktop Image"
    wevtutil cl AppSense
    Stop-Service -displayname "AppSense Client Communications Agent"
    Stop-Service -displayname "AppSense Performance Manager Agent"
    Stop-Service -displayname "AppSense User Virtualization Manager"
    Stop-Service -displayname "AppSense Watchdog Service"
    $path = "C:\appsensevirtual"
    $files = Get-ChildItem C:\appsensevirtual -recurse -force 
    foreach ($file in $files) {
        $extn = [IO.Path]::GetExtension($file)
        if ($extn -eq ".xml" ) {
            remove-item $file.fullname
        }

    }
    Remove-Item C:\appsensevirtual -Recurse -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\AppSense Technologies\Communications Agent" -Name "group id" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\AppSense Technologies\Communications Agent" -Name "machine id" -ErrorAction SilentlyContinue
}

# Sync Time with DC
Write-Verbose "Syncing time with the Domain Controller"
w32tm /resync

# Clean out the User Profiles
Write-Verbose "Clearing out the User Profiles"
Copy-Item "\\gb.bupagroup.com\citrix\deploy\Applications\DelProf\delprof2.exe" -Destination "C:\Temp\delprof2.exe" -ErrorAction SilentlyContinue
cd\
cd temp
.\delprof2.exe /u
Start-Sleep -s 3

# Clear Citrix Group Policy History
Write-Verbose "Clearing out the Citrix Group Policy History Folders"
Get-ChildItem $env:Programdata\Citrix\GroupPolicy | Remove-Item -Force -Recurse 
Get-ChildItem HKLM:\SOFTWARE\Policies\Citrix\ | Remove-Item -Recurse -Force
Add-PSSnapin Citrix.Common.GroupPolicy -ErrorAction SilentlyContinue 

# Rebuild NGEN Librarys
Write-Verbose "Rebuilding the NGEN Librarys"
$NgenPath = Get-ChildItem -Path 'c:\windows\Microsoft.NET' -Recurse "ngen.exe" | % {$_.FullName}
foreach ($element in $NgenPath) {
    start-process -filepath $element -ArgumentList "update /force" -wait
}

# Optimise Scheduled Tasks out Scheduled Tasks
Write-Verbose "Delete unused Scheduled Tasks"
$TaskScheduler = New-Object -ComObject Schedule.Service
$TaskScheduler.Connect($Env:ComputerName)
$TaskRootFolder = $TaskScheduler.GetFolder('\')

# Delete Adobe PPAPI Notifier
Try {
    $Task = $TaskRootFolder.GetTask("Adobe Flash Player PPAPI Notifier")
}
Catch {
    $Task = "NotFound"
}
if ($task -eq "NotFound") {
    Write-Verbose "Adobe Flash Player PPAPI Notifier Not Found"
}
else {
    schtasks /delete /tn "Adobe Flash Player PPAPI Notifier" /f
    Write-Verbose "Adobe Flash Player PPAPI Notifier Removed"
}

# Delete Adobe Flash Updater
Try {
    $Task = $TaskRootFolder.GetTask("Adobe Flash Player Updater")
}
Catch {
    $Task = "NotFound"
}
if ($task -eq "NotFound") {
    Write-Verbose "Adobe Flash Player Updater Not Found"
}
else {
    schtasks /delete /tn "Adobe Flash Player Updater" /f
    Write-Verbose "Adobe Flash Player Updater"
}

# Delete Citrix Management Agent Auto-Updater
Try {
    $Task = $TaskRootFolder.GetTask("Citrix Management Agent Auto-Updater")
}
Catch {
    $Task = "NotFound"
}
if ($task -eq "NotFound") {
    Write-Verbose "Citrix Management Agent Auto-Updater Not Found"
}
else {
    schtasks /delete /tn "Citrix Management Agent Auto-Updater" /f
    Write-Verbose "Citrix Management Agent Auto-Updater Removed"
}

# Delete GoogleUpdateTaskMachineCore
Try {
    $Task = $TaskRootFolder.GetTask("GoogleUpdateTaskMachineCore")
}
Catch {
    $Task = "NotFound"
}
if ($task -eq "NotFound") {
    Write-Verbose "GoogleUpdateTaskMachineCore Not Found"
}
else {
    schtasks /delete /tn "GoogleUpdateTaskMachineCore" /f
    Write-Verbose "GoogleUpdateTaskMachineCore Removed"
}

# Delete GoogleUpdateTaskMachineUA
Try {
    $Task = $TaskRootFolder.GetTask("GoogleUpdateTaskMachineUA")
}
Catch {
    $Task = "NotFound"
}
if ($task -eq "NotFound") {
    Write-Verbose "GoogleUpdateTaskMachineUA Not Found"
}
else {
    schtasks /delete /tn "GoogleUpdateTaskMachineUA" /f
    Write-Verbose "GoogleUpdateTaskMachineUA Removed"
}

# Remove McAfee Agent GUID
Write-Verbose "Remove McAfee Agent GUID"
cd\
cd "C:\Program Files\McAfee\Agent"
.\maconfig.exe -enforce -noguid

# Display Remaining Tasks Message to User
Write-Verbose "Script Finished - Shutdown the XenDesktop VDA and Promote to Production"

# Set the old Verbose Preference back to original value
$VerbosePreference = $OldVerbosePreference