# This script will configure a Windows Server 1709 Core Server to run as the DC in my lab
# DO NOT run this unless you are happy with what it is doing
# This enables me to quickly stand up a new Domain and have it configured how I want for my lab
# Feel free to hack / edit / copy this script and use for your own environments
# For too long I have had all my scripts on USB keys etc - hence me putting it up on GitHub

# Disable IPv6
$Adapter = Get-NetAdapter
$NICName = $Adapter.Name
Disable-NetAdapterBinding -InterfaceAlias $NICName -ComponentID ms_tcpip6
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters -Name DisabledComponents -PropertyType DWord -Value 0xffffffff

# Rename Adapter
$VLANName
rename-netadapter -name $NICName -newname $VLANName

# Set Timezone
$TimeZone = "GMT Standard Time"
set-timezone -name $TimeZone

# Set Up New Domain
$DomainName = "bretty.me.uk"
$Password = "ReallySecure"

Install-WindowsFeature AD-Domain-Services -includemanagementtools
$SecurePassword = ConvertTo-SecureString -AsPlainText $Password -Force
Install-ADDSforest -DomainName $DomainName -InstallDNS -safemodeadministratorpassword $SecurePassword -force

# Configure Reverse Lookup Zones
Add-DNSServerPrimaryZone -networkid "192.168.100.0/24" -replicationscope "Forest"
Add-DNSServerPrimaryZone -networkid "192.168.101.0/24" -replicationscope "Forest"
Add-DNSServerPrimaryZone -networkid "192.168.1.0/24" -replicationscope "Forest"
Add-DNSServerPrimaryZone -networkid "192.168.0.0/24" -replicationscope "Forest"

# Add DNS Forwarder A Record
$DNSForwarderIP = "192.168.100.1"
Add-DNSServerResourceRecordA -name "dnsforwarder" -zonename $DomainName -allowupdateany -ipv4address $dnsforwarderip -timetolive 01:00:00 -createptr

# Configure DNS Forwarder
Get-DNSServerForwarder | Remove-DNSServerForwarder
set-dnsserverforwarder -ipaddress $dnsforwarderip

# Set up DHCP Server
Install-WindowsFeature DHCP -IncludeManagementTools
Add-DhcpServerv4Scope -Name "vlan_100" -StartRange 192.168.100.100 -EndRange 192.168.100.200 -SubnetMask 255.255.255.0 -Description "vlan_100"
Set-DhcpServerv4OptionValue -ScopeID 192.168.100.0 -DNSServer 192.168.100.10 -DNSDomain bretty.me.uk -Router 192.168.100.1
Add-DhcpServerInDC -DNSName bretty.me.uk

# Set Up DFS and DFS-R
Install-WindowsFeature -Name FS-DFS-Namespace,FS-DFS-Replication -IncludeManagementTools 
New-Item -ItemType Directory -Path C:\dfs
New-SmbShare -Name dfs$ -Path C:\dfs -FullAccess Administrators -ReadAccess Users
New-DfsnRoot -Path \\$DomainName\public -TargetPath \\dc\dfs$  -Type DomainV2 -EnableSiteCosting $true
New-Item -ItemType Directory -Path C:\infrastructure
New-SmbShare -Name infrastructure$ -Path C:\infrastructure -FullAccess Administrators -ReadAccess Users
New-DfsnFolder -Path \\$DomainName\public\infrastructure -TargetPath \\dc\infrastructure$

# Set Up Certificate Authority
Install-WindowsFeature AD-Certificate -IncludeManagementTools 
Install-AdcsCertificationAuthority -CACommonName "Bretty Root CA" -CAType EnterpriseRootCa -HashAlgorithmName SHA256 -KeyLength 4096 -ValidityPeriod Years -ValidityPeriodUnits 10 -Force
Install-WindowsFeature ADCS-Web-Enrollment
Install-AdcsWebEnrollment -Force

# Generate Wildcard Certificate and put in DFS Share
# Thanks to Martin for this script - slightly edited to suite my initial DC Build
# http://citrixlab.dk/archives/544

New-Item -ItemType Directory -Path C:\infrastructure\certificates
New-Item -ItemType Directory -Path C:\infrastructure\certificates\internal
New-Item -ItemType Directory -Path C:\infrastructure\certificates\internal\wildcard
$SSLIni = "C:\infrastructure\certificates\internal\wildcard\wildcard.ini"
"[Version]" | out-file $sslini -append
"Signature=""`$Windows NT`$""" | out-file $sslini -append
"" | out-file $sslini -append
"[NewRequest]"  | out-file $sslini -append
"Subject = ""CN=*.bretty.me.uk""" | out-file $sslini -append
"Exportable = TRUE" | out-file $sslini -append
"KeyLength = 4096" | out-file $sslini -append
"KeySpec = 1" | out-file $sslini -append
"KeyUsage = 0xA0" | out-file $sslini -append
"MachineKeySet = True" | out-file $sslini -append
"ProviderName = ""Microsoft Enhanced RSA and AES Cryptographic Provider""" | out-file $sslini -append
"ProviderType = 12"  | out-file $sslini -append
"SMIME = FALSE"  | out-file $sslini -append
"RequestType = PKCS10" | out-file $sslini -append
"HashAlgorithm=Sha256" | out-file $sslini -append
"" | out-file $sslini -append
"[Strings] " | out-file $sslini -append
"szOID_SUBJECT_ALT_NAME2 = ""2.5.29.17""" | out-file $sslini -append
"szOID_ENHANCED_KEY_USAGE = ""2.5.29.37""" | out-file $sslini -append
"szOID_PKIX_KP_SERVER_AUTH = ""1.3.6.1.5.5.7.3.1""" | out-file $sslini -append
"szOID_PKIX_KP_CLIENT_AUTH = ""1.3.6.1.5.5.7.3.2""" | out-file $sslini -append
"" | out-file $sslini -append
"[RequestAttributes]" | out-file $sslini -append
"CertificateTemplate= WebServer" | out-file $sslini -append

$CA = New-Object -ComObject CertificateAuthority.Config
$CAName = $CA.GetConfig(0) 
c:
cd\
cd .\infrastrcucture\certificates\internal\wildcard

& c:\windows\system32\certreq.exe -new "wildcard.ini" "wildcard.req"
& c:\windows\system32\certreq.exe -config "$CAName" -submit "wildcard.req" "wildcard.cer"
& c:\windows\system32\certreq.exe -accept "wildcard.cer"
$Password = "ReallySecure"
$PFXPassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match "\*.bretty.me.uk"}
Get-item cert:\localmachine\my\$($cert.Thumbprint) | Export-PfxCertificate -FilePath "wildcard.pfx" -Password $PFXPassword 
Remove-Item -Path wildcard.cer -Force
Remove-Item -Path wildcard.req -Force
Remove-Item -Path wildcard.rsp -Force
Remove-Item -Path wildcard.ini -Force
        
# Create OU Structure
New-ADOrganizationalUnit -Name bretty -passthru
New-ADOrganizationalUnit -Name "infrastructure" -Path "ou=bretty,dc=bretty,dc=me,dc=uk" -PassThru
New-ADOrganizationalUnit -Name "users" -Path "ou=bretty,dc=bretty,dc=me,dc=uk" -PassThru
New-ADOrganizationalUnit -Name "groups" -Path "ou=bretty,dc=bretty,dc=me,dc=uk" -PassThru
New-ADOrganizationalUnit -Name "workers" -Path "ou=bretty,dc=bretty,dc=me,dc=uk" -PassThru

# Set up Sites and Services
Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter "objectclass -eq 'site'" | Set-ADObject -DisplayName Liphook
Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter "objectclass -eq 'site'" | Rename-ADObject -NewName Liphook
New-ADReplicationSubnet -Name "192.168.0.0/24" -Site Liphook
New-ADReplicationSubnet -Name "192.168.1.0/24" -Site Liphook
New-ADReplicationSubnet -Name "192.168.100.0/24" -Site Liphook
New-ADReplicationSubnet -Name "192.168.101.0/24" -Site Liphook

# Add UPN Suffix for Domain
Get-ADForest | Set-ADForest -UPNSuffixes @{add="bretty.local"}

# Install and Configure WSUS
# Thanks Eric of XenApp Blog for this
# https://xenappblog.com/2017/automate-wsus-on-windows-2016-server-core/

Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
New-Item -Path E: -Name WSUS -ItemType Directory
New-SmbShare -Name wsus$ -Path e:\wsus -FullAccess Administrators -ReadAccess Users
New-DfsnFolder -Path \\$DomainName\public\wsus -TargetPath \\dc\wsus$
CD "C:\Program Files\Update Services\Tools"
.\wsusutil.exe postinstall CONTENT_DIR=E:\WSUS

$wsus = Get-WSUSServer
$wsusConfig = $wsus.GetConfiguration()
Set-WsusServerSynchronization -SyncFromMU
$wsusConfig.AllUpdateLanguagesEnabled = $false           
$wsusConfig.SetEnabledUpdateLanguages("en")           
$wsusConfig.Save()

$subscription = $wsus.GetSubscription()
$subscription.StartSynchronizationForCategoryOnly()

Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Office" } | Set-WsusProduct -Disable
Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Windows" } | Set-WsusProduct -Disable
Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Windows Server 2016" } | Set-WsusProduct
Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Language Packs" } | Set-WsusProduct -Disable

Get-WsusClassification | Where-Object {$_.Classification.Title -in ('Critical Updates','Definition Updates','Feature Packs','Security Updates','Service Packs','Update Rollups','Updates')} | Set-WsusClassification

$subscription.SynchronizeAutomatically=$true
$subscription.SynchronizeAutomaticallyTimeOfDay= (New-TimeSpan -Hours 0)
$subscription.NumberOfSynchronizationsPerDay=1
$subscription.Save()
$subscription.StartSynchronization()

# Add CName for WSUS
Add-DnsServerResourceRecordCName -Name "wsus" -HostNameAlias "dc.bretty.me.uk" -ZoneName "bretty.me.uk"

# Stop First Run Wizard
$wsusconfig.OobeInitialized = $true
$wsusConfig.Save()

# Create GPO to force WSUS to Domain
New-GPO -Name bretty_wsus
Set-GPRegistryValue -Name "bretty_wsus" -key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName WUServer -Type String -value http://wsus.bretty.me.uk:8530
Set-GPRegistryValue -Name "bretty_wsus" -key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName WUStatusServer -Type String -value http://wsus.bretty.me.uk:8530
Set-GPRegistryValue -Name "bretty_wsus" -key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName AUOptions -Type Dword -value 4
Set-GPRegistryValue -Name "bretty_wsus" -key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName ScheduledInstallDay -Type Dword -value 1
Set-GPRegistryValue -Name "bretty_wsus" -key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName ScheduledInstallTime -Type Dword -value 1

New-GPLink -Name "bretty_wsus" -Target "dc=bretty,dc=me,dc=uk" -LinkEnabled Yes
