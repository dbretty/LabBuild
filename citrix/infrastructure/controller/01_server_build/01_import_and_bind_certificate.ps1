# Determine where to do the logging
$logPS = "C:\Windows\Temp\import_and_bind_controller_certificate.log"
 
# Set the start Date and Time
Write-Verbose "Setting Script Parameters" -Verbose
$StartDTM = (Get-Date)

# Setting up script variables
Write-Verbose "Setting up script variables" -Verbose
$Passphrase = "password"
$CertificateFileName = "controller.pfx"
$SecurePassphrase = ConvertTo-SecureString $Passphrase -AsPlainText -Force

# Start the transcript for the install
Start-Transcript $LogPS

# Import Certificate
Write-Verbose "Import Certificate" -Verbose
If (Test-Path $PSScriptRoot\custom\controller) 
{
    Write-Verbose "File Found - Importing Certificate File To Server" -Verbose
    Import-PfxCertificate -FilePath $PSScriptRoot\custom\storefront\$CertificateFileName -CertStoreLocation Cert:\LocalMachine\My -Password $SecurePassphrase
} 
Else 
{
    Write-Verbose "File(s) Not Found - Skipped" -Verbose
}

# Stop Logging
Write-Verbose "Stop logging" -Verbose
$EndDTM = (Get-Date)
Write-Verbose "Elapsed Time: $(($EndDTM-$StartDTM).TotalSeconds) Seconds" -Verbose
Write-Verbose "Elapsed Time: $(($EndDTM-$StartDTM).TotalMinutes) Minutes" -Verbose
Stop-Transcript