# Run-As Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
#Set-ExecutionPolicy Unrestricted

$backupDirectory = "D:\MSSQL\BACKUP"
$daysToStoreBackups = 16

start-transcript -Path d:\scripts\CleanupOldFiles.log

Get-ChildItem "$backupDirectory\*.bak" |? { $_.lastwritetime -le (Get-Date).AddDays(-$daysToStoreBackups)} |% {Remove-Item $_ -force }
write-host "removed all previous backups older than $daysToStoreBackups days"

Get-ChildItem "D:\Scripts\*.log" |? { $_.lastwritetime -le (Get-Date).AddDays(-$daysToStoreBackups)} |% {Remove-Item $_ -force }
write-host "removed all log files older than $daysToStoreBackups days"

stop-transcript
