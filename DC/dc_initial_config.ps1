# Disable IPv6
$Adapter = Get-NetAdapter
$NICName = $Adapter.Name
Disable-NetAdapterBinding -InterfaceAlias $NICName -ComponentID ms_tcpip6
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters -Name DisabledComponents -PropertyType DWord -Value 0xffffffff

# Rename Adapter
rename-netadapter -name $NICName -newname "vlan_100"

# Set Timezone
set-timezone -name "GMT Standard Time"

# Set Up New Domain
$DomainName = "bretty.me.uk"
Install-WindowsFeature AD-Domain-Services -includemanagementtools
$Password = "ReallySecure"
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
        
