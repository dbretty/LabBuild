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
