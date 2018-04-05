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
Install-WindowsFeature AD-Domain-Services -includemanagementtools
$Password = "ReallySecure"
$SecurePassword = ConvertTo-SecureString -AsPlainText $Password -Force
Install-ADDSforest -DomainName bretty.me.uk -InstallDNS -safemodeadministratorpassword $SecurePassword -force
