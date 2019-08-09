# Determine where to do the logging
$logPS = "C:\Windows\Temp\configure_fas.log"

# Set the start Date and Time
Write-Verbose "Setting Script Parameters" -Verbose
$StartDTM = (Get-Date)

# Start the transcript for the install
Start-Transcript $LogPS

# Configure Script Variables
Write-Verbose "Configure Script Variables" -Verbose
$CertAuthority = "dc.bretty.me.uk"

# Import the FAS Powershell SDK
Write-Verbose "Import the FAS Powershell SDK" -Verbose
Add-PSSnapin Citrix.Authentication.FederatedAuthenticationService.V1

# Change to the FAS Template Location
Write-Verbose "Change to the FAS Template Location" -Verbose
Set-Location "C:\Program Files\Citrix\Federated Authentication Service\CertificateTemplates"

# Add Smartcard Logon Template
Write-Verbose "Add Smartcard Logon Template" -Verbose
$template = [System.IO.File]::ReadAllBytes("$Pwd\Citrix_SmartcardLogon.certificatetemplate")
$CertEnrol = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyWebService
$CertEnrol.InitializeImport($template)
$comtemplate = $CertEnrol.GetTemplates().ItemByIndex(0)
$writabletemplate = New-Object -ComObject X509Enrollment.CX509CertificateTemplateADWritable
$writabletemplate.Initialize($comtemplate)
$writabletemplate.Commit(1, $NULL)  

# Add Citrix_RegistrationAuthority_ManualAuthorization Template
Write-Verbose "Add Citrix_RegistrationAuthority_ManualAuthorization Template" -Verbose
$template = [System.IO.File]::ReadAllBytes("$Pwd\Citrix_RegistrationAuthority_ManualAuthorization.certificatetemplate")
$CertEnrol = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyWebService
$CertEnrol.InitializeImport($template)
$comtemplate = $CertEnrol.GetTemplates().ItemByIndex(0)
$writabletemplate = New-Object -ComObject X509Enrollment.CX509CertificateTemplateADWritable
$writabletemplate.Initialize($comtemplate)
$writabletemplate.Commit(1, $NULL)  

# Add Citrix_RegistrationAuthority Template
Write-Verbose "Add Citrix_RegistrationAuthority Template" -Verbose
$template = [System.IO.File]::ReadAllBytes("$Pwd\Citrix_RegistrationAuthority.certificatetemplate")
$CertEnrol = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyWebService
$CertEnrol.InitializeImport($template)
$comtemplate = $CertEnrol.GetTemplates().ItemByIndex(0)
$writabletemplate = New-Object -ComObject X509Enrollment.CX509CertificateTemplateADWritable
$writabletemplate.Initialize($comtemplate)
$writabletemplate.Commit(1, $NULL)  

# Register Templates
Write-Verbose "Register Templates" -Verbose
Invoke-Command -ComputerName $CertAuthority -ScriptBlock { Add-CATemplate -Name Citrix_SmartcardLogon -Force }
Invoke-Command -ComputerName $CertAuthority -ScriptBlock { Add-CATemplate -Name Citrix_RegistrationAuthority_ManualAuthorization -Force }
Invoke-Command -ComputerName $CertAuthority -ScriptBlock { Add-CATemplate -Name Citrix_RegistrationAuthority -Force }

# Authorize FAS Server
Write-Verbose "Authorize FAS Server" -Verbose
$CitrixFasAddress = (Get-FasServer)[0].Address
$DefaultCA=(Get-FasMsCertificateAuthority -Default).Address
New-FasAuthorizationCertificate -CertificateAuthority $DefaultCA -CertificateTemplate "Citrix_RegistrationAuthority" -AuthorizationTemplate "Citrix_RegistrationAuthority_ManualAuthorization" -Address $CitrixFasAddress


# Stop Logging
Write-Verbose "Stop logging" -Verbose
$EndDTM = (Get-Date)
Write-Verbose "Elapsed Time: $(($EndDTM-$StartDTM).TotalSeconds) Seconds" -Verbose
Write-Verbose "Elapsed Time: $(($EndDTM-$StartDTM).TotalMinutes) Minutes" -Verbose
Stop-Transcript