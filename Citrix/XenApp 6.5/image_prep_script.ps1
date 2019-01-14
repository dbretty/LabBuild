<#
.SYNOPSIS
    Image Prep Script for XenApp 6.5 Bupa Estate
.DESCRIPTION
    Image Prep Script for XenApp 6.5 Bupa Estate
.PARAMETER 
    None
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    Current Version:        1.1
    Creation Date:          16/10/2017
.CHANGE CONTROL
    Name                                Version         Date                Change Detail
    David Brett / Pete Ruxton           1.0             16/10/2017          Script Creation
    David Brett                         1.1             23/10/2017          Added Verbose Logging and Script Header
    David Brett / Pete Ruxton           1.2             25/10/2017          Changed Clear Event Logs to only clear App, Security, System and Appsense
                                                                            Fixed Errors in Script with wrong commands
.EXAMPLE
    ./xenapp-65-image-pres.ps1
.FEATURE REQUESTS
    Error with deleting c:\windows\temp files - need rights
    LocalGpoSaving: Verbose Logging
#>

# Get old Verbose Preference and storeit, change Verbose Preference to Continue
$OldVerbosePreference = $VerbosePreference
$VerbosePreference = "Continue"

# Clear out Temp Folder
Write-Verbose "Clearing out the Temp and Windows\Temp Folders"
Get-ChildItem C:\Temp | Remove-Item -Force -Recurse 
Get-ChildItem C:\Windows\Temp | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

# Clear Citrix Group Policy History
Write-Verbose "Clearing out the Citrix Group Policy History Folders"
Get-ChildItem $env:Programdata\Citrix\GroupPolicy | Remove-Item -Force -Recurse 
Get-ChildItem HKLM:\SOFTWARE\Policies\Citrix\ | Remove-Item -Recurse -Force
Add-PSSnapin Citrix.Common.GroupPolicy -ErrorAction SilentlyContinue 
Get-ChildItem LocalGPO:\Computer -Recurse | Clear-Item -ErrorAction SilentlyContinue 

# Rebuild NGEN Librarys
Write-Verbose "Rebuilding the NGEN Librarys"
$NgenPath = Get-ChildItem -Path 'c:\windows\Microsoft.NET' -Recurse "ngen.exe" | % {$_.FullName}
foreach ($element in $NgenPath) {
    start-process -filepath $element -ArgumentList ExecuteQueuedItems -wait
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
wevtutil cl AppSense

# Remove App-V Client Packages
Write-Verbose "Removing the App-V Packages"
$Product = "Microsoft AppV Client"
$servicename1 = Get-Service -Name appvclient -ErrorAction SilentlyContinue

if ($servicename1.Status -ne "Running")
    {
        Write-Verbose "The client service is not running.The Script cannot clean up package files."
    } ELSE {
        $HKLM_Path = "HKLM:\Software\Microsoft\AppV\Client"
        $Installpath = Get-ItemProperty -path "$HKLM_Path" | % {$_.InstallPath}
        $ModuleFile = "AppvClient.psd1"
        $ModulePath  = "$Installpath\AppvClient\$ModuleFile"
        $PckInstRoot = Get-ItemProperty -path "$HKLM_Path\Streaming" | % {$_.PackageInstallationRoot}
        $PckInstRoot = [Environment]::ExpandEnvironmentVariables($PckInstRoot)
        if (!$PckInstRoot)
        {
            Write-Verbose "PackageInstallationRoot is required for removing packages" -Type E       
        }
        IF (Test-Path $PckInstRoot)
        {
            $packageFiles = Get-ChildItem ([System.Environment]::ExpandEnvironmentVariables($PckInstRoot));
            if (!$packageFiles -or $packageFiles.Count -eq 0)
            {
                    Write-Host "No package files found, nothing to clean up." -Type W
            } ELSE {
                Write-Verbose "Removing all App-V packages" -ShowConsole -Color DarkGreen 
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
                do
                {
                    $connectionGroupsInUse = $FALSE;
                    ForEach ($connectionGroup in $connectionGroups)
                    {
                        if ($connectionGroup.InUse -eq $TRUE)
                        {
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
                do
                {
                    $packagesInUse = $FALSE;
                    ForEach ($package in $packages)
                    {
                        if ($package.InUse -eq $TRUE)
                        {
                            $packagesInUse = $TRUE;
                            Write-Verbose "Stopping package " $package.Name;
                            Stop-AppvClientPackage $package -Global;

                           # allow 1 second for the VE to tear down before we continue polling
                            sleep 1;
                        }
                    }
                } while ($packagesInUse);
    
                Write-Verbose "Removing all App-V Connection Groups";
                ForEach ($connectionGroup in Get-AppvClientConnectionGroup -all) 
                {
                    Remove-AppvClientConnectionGroup $connectionGroup;
                }

                Write-Verbose "Removing all App-V Packages";
                ForEach ($package in Get-AppvClientPackage -all)
                {
                    Remove-AppvClientPackage $package;
                }
            }
            $Error.Clear();
        } ELSE {
            Write-Verbose "The AppV PackageInstallationRoot $PckInstRoot Folder not exist, nothing to clean up." -Type W
        }
    }

Get-ChildItem $PckInstRoot | Remove-Item -Force -Recurse 

# Run McAfee DAT Update
Write-Verbose "Running a McAfee DAT File Update"
$Product = "McAfee VirusScan Enterprise"
$reg_VSE_string = "HKLM:\Software\wow6432Node\Network Associates\ePolicy Orchestrator\Agent"
$VSE_path = "C:\Program Files (x86)\McAfee\VirusScan Enterprise"

Write-Verbose "Updating Virus Definitions... please Wait"
Start-Process -FilePath "$VSE_path\mcupdate.exe" -ArgumentList "/update /quiet"
Start-Sleep -s 3

# AppSense Clean Up
Write-Verbose "Cleaning up the AppSense EM and PM Agent Cache"
Stop-Service -displayname "AppSense Client Communications Agent"
Stop-Service -displayname "AppSense Performance Manager Agent"
Stop-Service -displayname "AppSense User Virtualization Manager"
Stop-Service -displayname "AppSense Watchdog Service"
$path = "C:\appsensevirtual"
$files = Get-ChildItem C:\appsensevirtual -recurse -force 
foreach($file in $files){
    $extn = [IO.Path]::GetExtension($file)
    if ($extn -eq ".xml" )
    {
        remove-item $file.fullname
    }

}
Remove-Item C:\appsensevirtual -Recurse -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\AppSense Technologies\Communications Agent" -Name "group id" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\AppSense Technologies\Communications Agent" -Name "machine id" -ErrorAction SilentlyContinue

# Clear Out Memory Management Used Space
Write-Verbose "Clearing out the Memory Management Space"
Get-ChildItem "C:\Program Files (x86)\Citrix\Server Resource Management\Memory Optimization Management\Data\Archive" | Remove-Item -Force -Recurse 
$files = Get-ChildItem "C:\Program Files (x86)\Citrix\Server Resource Management\Memory Optimization Management\Data" -recurse -force 
foreach($file in $files){
    $extn = [IO.Path]::GetExtension($file)
    if ($extn -eq ".tmp" )
    {
        remove-item $file.fullname
    }

}

# Recreate the Local Host Cache
Write-Verbose "Recreating the Local Host Cache"
Stop-Service IMAService
dsmaint recreatelhc
Start-Service IMAService

# Sync Time with DC
Write-Verbose "Syncing time with the Domain Controller"
net time \\gbstadc01 /set /y

# Clean out the User Profiles
Write-Verbose "Clearing out the User Profiles"
$UsrParentFolder = "C:\Users\"
$SpecUsrAcc = @(".NET v4.5",".NET v4.5 Classic","svc_citrix","svc_appsense_config","Administrator","Public")
$ChkUsrFolder = $UsrParentFolder + "*"
$UsrProfs = Get-WmiObject -Class Win32_UserProfile | Where {$_.LocalPath -like $ChkUsrFolder}
$count = 0
$err = 0
ForEach ($u in $UsrProfs) {
    $UsrProfPath = $u.LocalPath.split("\")
    $UsrProfPathCnt = ($UsrProfPath.Count) - 1
    If ($SpecUsrAcc -notcontains $UsrProfPath[$UsrProfPathCnt]) {
        If ($u.Loaded -like "False") {
            try {
                $u.Delete()
                Write-host "DELETED PROFILE:" $u.LocalPath
                $count++
            }
            catch {
                $err = 1
                Write-Host $([DateTime]::Now.toString("yyyy-MM-dd_HHmmss") + ": ERROR: could not delete profile folder") | out-file $LogFile -Append
            }
        }
    }
}

# Display Remaining Tasks Message to User
Write-Verbose "Script Finished - please remove Mcafee Agent GUID and Remove Server from Farm then shutdown"

# Set the old Verbose Preference back to original value
$VerbosePreference = $OldVerbosePreference