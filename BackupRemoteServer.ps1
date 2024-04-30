Get-PSSession | Remove-PSSession

#Unsure if this setting now helps this script?
#Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value 'JOII-UW-HV01, JOII-UW-HV02, JOII-UW-SQL01' -Force

# Run this on each Server this script is connecting to: Register-PSSessionConfiguration -Name BackupHV01 -RunAsCredential 'joii\a-chris.diphoorn' -Force 

$Session = New-PSSession -ComputerName "joii-uw-hv01" -Authentication Default -ConfigurationName BackupHV01
Invoke-Command -Session $Session -ScriptBlock {c:\Scripts\RunBackup.ps1}
