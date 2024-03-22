$restartTeams = $False
$processName = ""

$teamsprocess=(Get-Process -Name "*teams*")


# If Teams is currently running then we need to stop it first, then we have access to delete the files.

if($teamsprocess) {
  
  # Detect if Teams is currently in a call? - If it is then we cant stop it.
  If (((Get-NetUDPEndpoint -OwningProcess (get-process | where {$_.Name -match "teams$"}).Id -ErrorAction SilentlyContinue | Where {$_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne '::'}  | measure).count) -gt 0) {
      write-debug "Teams is currently connected in a call and cant be terminated."
      exit
  }

  $processName = ($teamsprocess.ProcessName)
  $exe = "$($processName).exe"
  $path = Get-Process -Name $processName | Select-Object Path
  
  try{
    Stop-Process -Name $processName -ErrorAction SilentlyContinue
  } catch {}

  $restartTeams = $True  
  Start-Sleep -Seconds 2
}



# Check if the New Teams App is installed

$Teamsfolder= "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache"  

if ((Test-Path $Teamsfolder)) {

   $filelisting = (Get-ChildItem -Path "$($Teamsfolder)" -recurse  | Get-ChildItem -File | Select -ExpandProperty FullName)
   
   # Exclude this folder from being deleted as it contains a database of the users current settings.
   $exclude ="WV2Profile_tfw\Local Storage"   

    foreach($file in $filelisting) {
        if($file -notlike "*$($exclude)*") {
            try {
                remove-Item -Path $file -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
    Start-Sleep -Seconds 1
} 


# Check if the Old Teams App is installed

$Teamsfolder= "$($env:APPDATA)\Microsoft\Teams\"
if ((Test-Path $Teamsfolder)) {
    try {
        Get-ChildItem -Path "$($Teamsfolder)" -File -recurse | Select -ExpandProperty FullName | remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch {}

    Start-Sleep -Seconds 1
}


# Restart Teams if it was orignially running

if($restartTeams -eq $True ) {
  Start-Process $exe
}
