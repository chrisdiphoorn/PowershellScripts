
# Remove the Current User's Outlook Offline Address Book folders.
# Outlook will Download them again after it has Synced all Folders again.

# Check if outlook is currently running and force it to quit!
$outlook = Get-Process outlook -ErrorAction SilentlyContinue
$outlookRunning= $False

if ($outlook) {
    $outlookRunning= $True
    $olApp = New-Object -ComObject Outlook.Application
    $olApp.Quit()
	
    Remove-Variable olApp
	
    Sleep 15

	if (!$outlook.HasExited) {
		$force=($outlook | Stop-Process -Force)
		
	}
}

# Remove all Users Outlook Offline Address Book folders - Outlook will Download them again after it starts back up.
$Folders = "$($env:USERPROFILE)\AppData\Local\Microsoft\Outlook\Offline Address Books"
if($Folders) {
  $GetFolders = (Get-ChildItem -Path $Folders -Directory -Force -ErrorAction SilentlyContinue | Select-Object FullName | foreach {$_.FullName})
  if($GetFolders) {
    foreach($folder in $GetFolders) {
      Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

# Run Outlook again, if it was running previously.
if($outlookRunning -eq $True) {

    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE\'

    if (!(Test-Path -Path $key)) {
        # throw 'Path to Outlook executable not found.'
    } else {
        $exe = (Get-ItemProperty -Path $key).'(default)'
        if (Test-Path -Path $exe) {
            Invoke-Item -Path  $exe
        } else {
            # throw 'Outlook executable not found.'
        }
    }
}
