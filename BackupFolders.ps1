#if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
#Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value 'JOII-UW-HV01, JOII-UW-HV02, JOII-UW-SQL01' -Force

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 
# See https://www.powershellgallery.com/ for module and version info
Function Install-ModuleIfNotInstalled(
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [string] $minimalVersion
) {
    $module = Get-Module -Name $moduleName -ListAvailable |`
        Where-Object { $null -eq $minimalVersion -or $minimalVersion -lt $_.Version } |`
        Select-Object -Last 1
    if ($null -ne $module) {
        Write-Verbose ('Module {0} (v{1}) is available.' -f $moduleName, $module.Version)
    }
    else {
        Import-Module -Name 'PowershellGet'
        $installedModule = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue
        if ($null -ne $installedModule) {
            Write-Verbose ('Module [{0}] (v {1}) is installed.' -f $moduleName, $installedModule.Version)
        }
        if ($null -eq $installedModule -or ($null -ne $minimalVersion -and $installedModule.Version -lt $minimalVersion)) {
            Write-Verbose ('Module {0} min.vers {1}: not installed; check if nuget v2.8.5.201 or later is installed.' -f $moduleName, $minimalVersion)
            #First check if package provider NuGet is installed. Incase an older version is installed the required version is installed explicitly
            if ((Get-PackageProvider -Name NuGet -Force).Version -lt '2.8.5.201') {
                Write-Warning ('Module {0} min.vers {1}: Install nuget!' -f $moduleName, $minimalVersion)
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
            }        
            $optionalArgs = New-Object -TypeName Hashtable
            if ($null -ne $minimalVersion) {
                $optionalArgs['RequiredVersion'] = $minimalVersion
            }  
            Write-Warning ('Install module {0} (version [{1}]) within scope of the current user.' -f $moduleName, $minimalVersion)
            Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -Force -Verbose
        } 
    }
}

Function GetDiskDriveFree() {
    [CmdletBinding()] Param ([Parameter(Mandatory)] [ValidateSet('C:', 'D:', 'E:', 'F:', 'G:', 'H:')][string]$DriveLetter)

    [long]$FreeSpace = 0
    Start-Sleep -milliseconds 500

    $Device = (Get-WmiObject Win32_LogicalDisk | Where { $_.DeviceID -eq "$($DriveLetter)" } )

    if ($Device) {
        $FreeSpace = $Device.FreeSpace
    }

    return $FreeSpace
}

Function Format-Size() {
    Param ([long]$size)

    If ($size -gt 1TB) { [string]::Format("{0:0.00}Tb", $size / 1TB) }
    ElseIf ($size -gt 1GB) { [string]::Format("{0:0.00}Gb", $size / 1GB) }
    ElseIf ($size -gt 1MB) { [string]::Format("{0:0.00}Mb", $size / 1MB) }
    ElseIf ($size -gt 1KB) { [string]::Format("{0:0.00}Kb", $size / 1KB) }
    ElseIf ($size -gt 0) { [string]::Format("{0:0.00}Bytes", $size) }
    Else { "0" }
}

Function Get-Time() {
    Return [string]"$(Get-Date -Format("HH:mm"))"
}


Function GetRightPathName() {
    Param ([string]$FullPath)

    $a = $FullPath.Split("\")
    $found = ""
    if ($a) {
        $index = $a.count - 1
        $found = $a.GetValue($index)
    }
    return $found
}

Function AddMissingBackSlash() {
    Param ([string]$FullPath)
    
    $found = $FullPath
    if (-Not $found.EndsWith('\')) {
        $found += '\'
    }
	
    return $found
}

Function IfGreaterThan1AddChar() { 
    Param(
        [int] $greaterThan, 
        [string] $aString, 
        [string] $aChar
    ) 
	
    if ($greaterThan -gt 1) {
        $ReturnValue = "$($aString)$($aChar)"  
    }
    else {
        $ReturnValue = $aString
    }

    return $ReturnValue
}

function GetDirectory {
    param( 
        [string] $Path, 
        [string[]] $ExcludePathName, 
        [string[]] $ExcludeFileName, 
        [switch] $Directory, 
        [switch] $Files
    )

    if ($Path -notmatch '\\$') { $Path += '\' }
		
    $Selectprop = @{'Property' = 'Name', 'FullName', @{name = 'PathName'; expression = { $_.FullName.Replace($Path, "") } }, 'Length', 'LastWriteTime', 'PSIsContainer' }
		
    $global:ExcludedFiles = 0
    $global:ExcludedFolders = 0
    
    $Found = @()
    $FoundCount = 0
		
    # If Getting Directories then get the Name, FullName, PathName, LastwriteTime
    if ($Directory.IsPresent) {
			
        # Enumerate though the path recursively and grab all the Folders
        $array = @(Get-ChildItem -path $Path -recurse -ea 0 -force | select-object @SelectProp)
			
        if ($array) {
				
            $Found = @($array | Where-Object { $_.PSIsContainer -eq $True } | Select Name, FullName, PathName, LastWriteTime) 
				
            if ($Found) {
					
                $FoundCount = $Found.Count

                if ($ExcludePathName.count -gt 0) {
						
                    for ($j = 0; $j -lt $ExcludePathName.count; $j++) {
							
                        if ($ExcludePathName[$j].Contains("\") ) {
                            $Found = $Found | ? { -NOT($_.PathName.StartsWith("$($ExcludePathName[$j])")) }
                        }
                        else {
                            $Found = $Found | ? { -NOT($_.PathName.Contains("$($ExcludePathName[$j])")) }
                        }
							
                    } # FOR
						
                    $global:ExcludedFolders = $FoundCount - $Found.Count
						
                } # IF

            } # IF Found
				
        } # IF array
			
        $Files = $False # ensure that Files are not run in the next statement.
			
    } # IF Directory
		
    # If Getting Files then only get the Name, FullName, PathName, Length (size), LastwriteTime
    if ($Files.isPresent) {
				
        # Enumerate though the path recursively and grab all the Files
        $array = @(Get-ChildItem -path $Path -recurse -ea 0 -force | Where-Object { $_.PSIsContainer -eq $False } | select-object @SelectProp)
			
        if ($array) {
            #$Found = @($array | Where-Object {$_.PSIsContainer -eq $False | Select Name, FullName, PathName, Length, LastWriteTime})
            $Found = @($array | Select Name, FullName, PathName, Length, LastWriteTime)
				
            if ($Found) {
					
                $FoundCount = $Found.Count
		
                # Run through the array and exclude the Files using the Path as the base of the FullName
                if ($ExcludeFileName.count -gt 0) {
						
                    for ($j = 0; $j -lt $ExcludeFileName.count; $j++) {
							
                        if ($ExcludeFileName[$j].Contains("\") ) {
                            $Found = $Found | ? { $_.FullName -ne "$($Path)$($ExcludeFileName[$j])" }
                        }
                        else {
                            $Found = $Found | ? { $_.Name -ne "$($ExcludeFileName[$j])" }
                        }
							
                    } # FOR
						
                    $global:ExcludedFiles = $FoundCount - $Found.Count
						
                } # IF 
			
                # Now Exlude any Files in the Excludedfolders
                if ($ExcludePathName.count -gt 0) {
						
                    for ($j = 0; $j -lt $ExcludePathName.count; $j++) {
							
                        if ($ExcludePathName[$j].Contains("\") ) {
                            $Found = $Found | ? { -NOT($_.PathName.StartsWith("$($ExcludePathName[$j])")) }
                        }
                        else {
                            $Found = $Found | ? { -NOT($_.PathName.Contains("$($ExcludePathName[$j])")) }
                        }
							
                    } # FOR
						
                    $global:ExcludedFiles = $FoundCount - $Found.Count
						
                } # IF
					
            } # IF  Found
				
        } #IF Array
			
    } # IF Files
		
    write-output $()$Found
}
	
# ***************************************************************************************************************************************************************************

Install-ModuleIfNotInstalled 'GetSTFolderSize'
Install-ModuleIfNotInstalled '7Zip4Powershell' '2.3.0'

$firstarg = $args[0]

# *********************************************************************************************************************************************************************************
$test = $false                    		# Set this to True for testing 7ZIP archiving in this script.
$testsync = $false                    		# Set this to True for testing Syncing of File / Folders in this script.
  
$backupWarning = $True                     	# This is set as an argument when the script is run. a Warning TXT File is created in the backup folder to indicate that the backup maybe Corrupt.

$Run7ZipFolder = $True                     	# Set this to False to have the script run but not actually create the zip file - makes this script run faster for debug purposes.  
$Run7ZipFiles = $True                     	# Set this to False to have the script run but not create the zip file. - Used for testing.
  
$SerialNumbers = @('20210520018043F')      	# Use USB drives with these signatures only.
$Offline = $True                     		# Turn drive offline after completed.
$ReadOnly = $True                     		# Turn Drive readonly after completed.

$SyncFolders = @('Disk\Path1', 'Disk\Path2', 'Disk\Path3', 'Disk\Path14', 'Disk\Path5')
    
$BackupFolders = @('Disk\Path2\WindowsImageBackup', 'Disk\Path1')	# Source backup folders to archive.
$ZipFileNames = @('SERVER-NAME', 'APP-NAME')	# File Names to use when archiving the backup folders.

$BackupFiles = @('Server\Sare\Path\Database1-Backup.bak', 'Server\Sare\Path\Database2-Backup.bak', 'Server\Sare\Path\Database3-Backup.bak')
  
$DestinationDrive = "DRIVE"
$ComputerName = "SERVER-NAME"	        	# The Server name running the script. (Used in an Invoke-Command process)

$DestinationFolder = "$($DestinationDrive)\"  	# The folder name on the destination drive to save the backups into.

$LogFolder = "C:\TEMP"		        	# The folder where the log files are stored.
$LogFileAge = 14  #Max Days old	        	# The maxiumum number of days to keep the log files for.

$ZipFileExt = ".7z"		                # The extension to create the archive files with.
$ZIPFormat = "SevenZIP"                		# SevenZip, Zip, #GZip, BZip2, Tar, XZ, Auto
$ZIPCompression = "Fast"                    	# None, Fast, Low, Normal, High, Ultra
$ZIPtmp = "C:\Temp"                 		# Temporary file creation folder
	
$MinimumFreeSpace = 800				# Gigabytes
  
# The Init Script used with 7zip to ensure that multi threading is enabled. 
$initScript = {
    param ($compressor)
    $compressor.CustomParameters.Add("mt", "on")
}
  
# Create the Array variables used to contain statistics information
[long[]]$Foldersizes = @()
[long[]]$Filesizes = @()
[long[]]$Syncsizes = @()

$ReadSerialNumber = @()
$ReadUniqueID = @()
$ReadModel = @()
$ReadModelSerial = @()

# Stats on GetDirectory
$global:ExcludedFiles = 0
$global:ExcludedFolders = 0
  
$ErrorOccured = $False

# The warning argument has been passwed so set the Warning flag to True
if ($firstarg -eq "WARN") {
    $backupWarning = $True
}

# Start Transcript
try { start-transcript -Path "$($LogFolder)\Backup_$(get-date -format "ddMMyyyy").log" | out-null } catch [System.InvalidOperationException] {}

# Get all diskdrives connected via USB to the computer
$Disks = Get-WmiObject -Class win32_diskdrive
Start-Sleep -milliseconds 500
foreach ($Disk in $Disks) {
		
    if ($Disk.InterfaceType -eq "USB") {
        
        $ReadModel += $Disk.Model
        $ReadModelSerial += $Disk.SerialNumber
    } # IF
		
} # FOR

# Check all diskdrives Serialnumbers
foreach ($SerialNo in $SerialNumbers) {
		
    $GetSig = (Get-Disk | Where { $_.SerialNumber -eq $SerialNo })
    if ($GetSig) { 
        $ReadUniqueID += $GetSig.UniqueId
        $ReadSerialNumber += $GetSig.SerialNumber
    } # IF
} # FOR
  
# Display all the USB drives found and their serialnumbers
For ($i = 0; $i -lt $ReadModel.Length; $i++) {
    Write-Host "Found USB Disk - Model: $($ReadModel[$i])  SerialNumber: $($ReadModelSerial[$i]) "
}

# Making all disks with these IDs online - These IDs are matched from the serialnumbers
For ($i = 0; $i -lt $ReadUniqueID.Length; $i++) {
    $Disk = Get-Disk | Where { $_.UniqueID -eq $ReadUniqueID[$i] -And $_.HealthStatus -eq 'Healthy' }
    if ($Disk) {
        if ($Offline -eq $True) { 
            $Disk | Where { $_.OperationalStatus -eq 'Offline' } | Set-Disk -IsOffline $False 
        }
        if ($Readonly -eq $True) { 
            $Disk | Where { $_.IsReadOnly -eq $True } | Set-Disk -IsReadonly $False 
        }
    }
    else {
        Write-Host "Disk $ReadUniqueID[$i] is Unhealthy and cannot br reliably mounted."
    } # IF Disk
		
} # FOR

# New backup folder name
$Folder = (Get-Date -Format "yyyyMMdd")

# Only run if the destination folder EG: F:\ (Drive F: + \) exists
if (Test-Path -Path $DestinationFolder) {

    [long]$diskfree = GetDiskDriveFree($DestinationDrive)

    [long]$need = 0				#calculated bytes needed to be available otherwise space is created.
    [long]$foldersize = 0

    For ($i = 0; $i -lt $BackupFolders.Length; $i++) {
        [long]$foldersize = (Get-STFolderSize -Path "$($BackupFolders[$i])").TotalBytes    #This is not the compressed Size?
        [long]$need += $foldersize
        $Foldersizes += [long]$foldersize
        Start-Sleep -milliseconds 1500
    }
        
    $FolderSTRSize = "FOLDER"
    ##if ($BackupFolders.Length -gt 1) { $FolderSTRSize = "$($FolderSTRSize)S" }
        
    $FolderSTRSize = IfGreaterThan1AddChar $BackupFolders.Length $FolderSTRSize "S"

    WRITE-HOST "$(Get-Time) $($BackupFolders.Length) $FolderSTRSize - Need: $(Format-Size($need)) Destination: $($DestinationFolder) Available: $(Format-Size($diskfree))"

    if ($diskfree -lt $need ) {

        Write-host "$(Get-Time) WARNING - Not Enough Disk Space Available."

        do {
                
            $All = (Get-ChildItem -Path $DestinationFolder -Depth 0 -Directory)
            Start-Sleep -milliseconds 500
                
            $oldest = (Get-Date)
            $oldestWARN = $oldest
            $oldfolder = ""
            $oldfolderWARN = ""

            # Find the oldest backup on the drive
            foreach ($F in $All) {
                if ($F) {

                    $lwt = $F.LastWriteTime
                    if ($lwt -lt $oldest) {
                        $oldest = $lwt
                        $oldfolder = "$DestinationDrive\$($F.Name)"
                    }
                        
                    # Test for a warning file in the backup folder
                    if ($lwt -lt $oldestWARN) {
                        if (Test-Path -Path "$DestinationDrive\$($F.Name)\WARNING.txt") { 
                            $oldestWARN = $lwt
                            $oldfolderWARN = "$DestinationDrive\$($F.Name)"
                        }
                    }

                }

            }
                
            # Delete the oldest backup with warning messages first... (Its the right thing to do???? Rendra?)
            if ($oldfolderWARN) {
                $oldfolder = $oldfolderWARN
                $oldest = $oldestWARN
            }

            # Remove the oldest backup to free up some space for the new backup to succeed!
            if ($oldfolder) {
                [long]$used = (Get-STFolderSize -Path "$oldfolder").TotalBytes
                $WarnFlag = ""
                if ($oldfolderWARN) { $WarnFlag = "FLAG: Warning" }

                Write-host "$(Get-Time) Removing Oldest Backup: $oldfolder Dated: $oldest Size: $(Format-Size($used)) $WarnFlag"

                if (-NOT($test -eq $True)) { 
                    Remove-Item -Path $oldfolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null 
                    Start-Sleep -Milliseconds 1500
                }

            } #// IF a folder was found
                
            # Get the Free Space Again!
            [long]$diskfree = GetDiskDriveFree($DestinationDrive)

        } until($diskfree -gt $need -Or $All.length -lt 3 -Or $Test -eq $True)

    } ## IF $DiskFree < $Needed

    ###################################################################### ARCHIVE FOLDERS #########################################################################################

    $i = 0
    foreach ($BackupFolder in $BackupFolders) {

        $ZipFile = "$($ZipFileNames[$i])$($ZipFileExt)"
			
        $DestinationName = GetRightPathName($BackupFolder)
        $CheckFolder = "$($DestinationFolder)$($Folder)"
        $Destination = "$($CheckFolder)\$($DestinationName)"
        $DestinationFile = "$($Destination)\$($ZipFile)"
			
        #// Checkfolder is Missing - OK - Created It.
        if (-Not (Test-Path -Path "$($CheckFolder)")) { 
            if (-NOT($test -eq $True)) { 
                New-Item -Path "$($CheckFolder)" -ItemType Directory -Force | Out-Null
                Start-Sleep -milliseconds 500
            }
				
        }
        #// Destinationfolder is Missing - OK - Create It.
        if (-Not (Test-Path -Path "$($Destination)")) { 
            if (-NOT($test -eq $True)) { 
                New-Item -Path "$($Destination)" -ItemType Directory -Force | Out-Null
                Start-Sleep -milliseconds 500
            }
				
        }

        #// Source Exists - OK
        if (Test-Path -Path "$($BackupFolder)") { 
                
            # // Destination Folder Exists - OK
            if (Test-Path -Path "$($Destination)") { 
              
                #Remove any existing 7zip Backup files before running again... incase the backup was run more than once on the same day.
                if (Test-Path -Path "$($DestinationFile)") {
                    if (-NOT($test -eq $True)) { 
                        Remove-Item -Path "$($DestinationFile)" -Force -ErrorAction SilentlyContinue | Out-Null
                        Start-Sleep -Milliseconds 500
                    }
                }
                
                $StartTime = (GET-DATE)
                WRITE-HOST "$(Get-Time) 7ZIP Archive: $($DestinationFile) - Uncompressed Size: $(Format-Size($FolderSizes[$i])) "

                if ($Run7ZipFolder -eq $True) {
                    try { 
                        if (-NOT($test -eq $True)) {
                            
                            # Compress/Archive the folder to the backup location.
                            $result = (Compress-7Zip -Path $BackupFolder -ArchiveFileName $DestinationFile -Format $ZIPformat -CompressionLevel $ZIPCompression -TempFolder $ZIPtmp -CustomInitialization $initScript)
                            
                            if ($result) { Write-Host "$(Get-Time) $result" }

                            # Create a warning message in the backup folder - to indicate that this backup may not be reliable.
                            if ($backupWarning -eq $True) {
                                $warnMessage = AddMissingBackSlash("$($BackupFolder)")
                                Set-Content "$($warnMessage)WARNING.txt" 'This Backup has completed, but may have issues. Some backup contents may not have fully succeded. This Backup may not be a fully reliable Source.'
                            }

                        }
                        Start-Sleep -milliseconds 500
                    }
                    catch {
                        Write-Host "$(Get-Time) POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                        $ErrorOccured = $True
                    }
                }
				
                [long]$FileSize = (Get-Item "$($DestinationFile)").Length 
				  
                $FinishTime = (GET-DATE)
                $diff = $FinishTime - $StartTime
                $h = $diff.Hours.ToString().PadLeft(2, '0')
                $m = $diff.Minutes.ToString().PadLeft(2, '0')
                $s = $diff.Seconds.ToString().PadLeft(2, '0')
                $DurationTime = "$($h):$($m):$($s)"

                Write-Host "$(Get-Time) Compress Duration: $DurationTime - Compressed Size: $(Format-Size($FileSize))"

            }
            else {
                # Test-Path $Destination Missing

                if (-NOT($test -eq $True)) { 
                    WRITE-HOST "$(Get-Time) ERROR - Missing Destination Directory $($Destination)"
                    $ErrorOccured = $True
                }

            } # Test-Path $Destination

        }
        else {
            # Test-Path $BackupFolder Missing
            if (-NOT($test -eq $True)) { 
                WRITE-HOST "$(Get-Time) ERROR - Missing Source Directory $($BackupFolder)" 
                $ErrorOccured = $True
            }
        } # Test-Path $BackupFolder
		  
        $i++
		
    } #// Foreach $BackupFolder
    
} # // Test_path $Destination Folder

###################################################################### BACKUP FILES #########################################################################################

# Get the Destinatination File. 
# If the file contains * then get the latest file in the folder that has a size greater than 0 bytes
	
$Destination = "$($DestinationFolder)$($Folder)"
[long]$need = 0
[long]$filesize = 0
[long]$diskfree = GetDiskDriveFree($DestinationDrive)
$BackupFilesNew = @()
	
$i = 0
foreach ($BackupFile in $BackupFiles) {
        
    $Newestfile = $BackupFile
    # Get The newest File from a List of them.
    if ($BackupFile.Contains("*")) {
                
        $lookup = "*.*"
        $a = $BackupFile.Split("\")
        if ($a) {
            $index = $a.count - 1
            $lookup = $a.GetValue($index)
        }
                
        $Back = (Split-Path -Path $BackupFile)
        if ($Back.StartsWith('\\')) {
            $ServerName = $a.GetValue(2)
            $Drive = $a.GetValue(3)
            $Drive = $Drive.Replace('$', ':')
            $aPath = ""
            For ($i = 4; $i -lt $a.count - 1; $i++)
            { $aPath += "$($a[$i])\" }
            $NewPath = "$($Drive)\$($aPath)"
                   
            # Need to pre-register a runspace configuration on the destination Server for the Invoke-Command to run as its run as a Double-hop Session.
            # Register-PSSessionConfiguration -Name BackupHV01 -RunAsCredential 'joii\a-chris.diphoorn' -Force
            $All = (Invoke-Command -ComputerName "$ServerName" -ScriptBlock { Get-ChildItem -Path "$($Using:NewPath)" -Filter "$($Using:lookup)" -File } -ConfigurationName BackupHV01)

        }
        else {                   
            $All = (Get-ChildItem -Path "$($Back)" -Filter "$($lookup)" -File )
        }
        if (-not $All) {
            write-host "      Cant Find Any Backup Files: $Back $lookup"
            $ErrorOccured = $True
        }
        Start-Sleep -milliseconds 500
        $newest = (Get-Date).AddDays(-365)
        $Newestfile = ""
                
        # Find the newest file in the folder
        foreach ($F in $All) { 
            if ($F) {
                $lwt = $F.LastWriteTime
                [long]$FileSize = (Get-Item "$($Back)\$($F.Name)").Length
                if ($lwt -gt $newest -AND $FileSize -gt 0) {
                    $newest = $lwt
                    $Newestfile = "$($Back)\$($F.Name)"
                }
            }
        }
        if ($Newestfile) {
            Write-host "      Found Latest File $Newestfile"
            Start-Sleep -milliseconds 500
        }

    }

    if ($Newestfile) {
        $BackupFilesNew += $Newestfile
        [long]$FileSize = (Get-Item $Newestfile).Length
        [long]$need += [long]$FileSize 
        $Filesizes += [long]$FileSize 
        $i ++
    }

}
    
$FileSTRSize = "FILE"
##if ($BackupFilesNew.Length -gt 1) { $FileSTRSize = "$($FileSTRSize)S" }
$FileSTRSize = IfGreaterThan1AddChar $BackupFilesNew.Length $FileSTRSize "S"

WRITE-HOST "$(Get-Time) $($BackupFilesNew.Length) $FileSTRSize - Size: $(Format-Size($need))  Drive: $DestinationDrive  Destination: $($Destination)  Available: $(Format-Size($diskfree))"

$DiskFull = $False
$i = 0
foreach ($BackupFile in $BackupFilesNew) {
    if ($DiskFull -eq $False) {
        if (Test-Path -Path "$($BackupFile)") {
            if (Test-Path -Path "$($Destination)") {

                [long]$diskfree = GetDiskDriveFree($DestinationDrive)
                Start-Sleep -milliseconds 500
                [long]$need = (Get-Item -Path "$($BackupFile)").Length

                if ($diskfree -gt $need ) {

                    $DestinationFileName = GetRightPathName($BackupFile)
                    $DestinationFile = "$($Destination)\$($DestinationFileName).7z"
    
                    if (Test-Path -Path "$($DestinationFile)") {
                        if (-NOT($test -eq $True)) { 
                            Remove-Item -Path "$($DestinationFile)" -Force -ErrorAction SilentlyContinue | Out-Null 
                            Start-Sleep -milliseconds 500
                        }
                    }
                        
                    $StartTime = (GET-DATE)
                    WRITE-HOST "$(Get-Time) 7ZIP Archive: $($DestinationFile) - Uncompressed Size: $(Format-Size($Filesizes[$i]))"

                    if (-NOT($test -eq $True)) { 
                        if ($Run7ZipFiles -eq $True) {
                            try { 
                                $result = (Compress-7Zip -Path "$($BackupFile)" -ArchiveFileName $DestinationFile -Format $ZIPformat -CompressionLevel $ZIPCompression -TempFolder $ZIPtmp -CustomInitialization $initScript)
                                if ($result) { Write-Host "$(Get-Time) $result" }
                                Start-Sleep -milliseconds 500
                            }
                            catch {
                                Write-Host "$(Get-Time) POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                                $ErrorOccured = $True
                            }
                        }
                    }

                    $FinishTime = (GET-DATE)
                    $diff = $FinishTime - $StartTime
                    $h = $diff.Hours.ToString().PadLeft(2, '0')
                    $m = $diff.Minutes.ToString().PadLeft(2, '0')
                    $s = $diff.Seconds.ToString().PadLeft(2, '0')
                    $DurationTime = "$($h):$($m):$($s)"

                    Write-Host "      Compress Duration: $DurationTime"

                }
                else {

                    Write-Host "$(Get-Time) WARNING - Not Enough Space Available on $($DestinationDrive) - Need: $(Format-Size($need))"
                    $DiskFull = $True

                } # //IF DiskFree > need

            } # //IF Test-Path Destination

        }
        else {

            Write-Host "$(Get-Time) WARNING - Missing Backup File: $($BackupFile)"
            $ErrorOccured = $True

        } # // Missing BackupFile
    }
    $i ++
}
    
###################################################################### SYNC #########################################################################################
$i = 0
[long]$diskfree = GetDiskDriveFree($DestinationDrive)
[long]$need = 0
[long]$foldersize = 0
For ($i = 0; $i -lt $SyncFolders.Length; $i++) {
    [long]$foldersize = (Get-STFolderSize -Path "$($SyncFolders[$i])").TotalBytes    
    [long]$need += $foldersize
    $Syncsizes += [long]$foldersize
    Start-Sleep -milliseconds 500
}

$i = 0
$SyncSTRSize = "SYNC FOLDER"
#if ($SyncFolders.Length -gt 1) { $SyncSTRSize = "$($SyncSTRSize)S" }
$SyncSTRSize = IfGreaterThan1AddChar $SyncFolders.Length  $SyncSTRSize "S"

WRITE-HOST "$(Get-Time) $($SyncFolders.Length) $SyncSTRSize - Requires: $(Format-Size($need))  Drive: $($DestinationDrive)  Available: $(Format-Size($diskfree))"

[long]$filebytestotal = 0
	
foreach ($SyncFolder in $SyncFolders) {
    [int]$filesremoved = 0
    [int]$folderscreated = 0
    [int]$filesupdated = 0
    [int]$foldersremoved = 0
    [int]$filescreated = 0
    [long]$bytesremoved = 0
    [long]$bytesadded = 0

    $SourceFolder = $SyncFolder
    $DesFolder = (Split-Path -Path "$SyncFolder" -NoQualifier)
    $DestinationFolder = "$($DestinationDrive)$($DesFolder)"

    WRITE-HOST "      Syncing to $($DestinationFolder) - Size: $(Format-Size($Syncsizes[$i]))" -NoNewLine
        
    #// Destinationfolder is Missing - OK - Create It
    if (-Not (Test-Path -Path "$($DestinationFolder)")) { 
        if (-NOT($testsync -eq $True)) { 
            try {
                New-Item -Path "$($DestinationFolder)" -ItemType Directory -Force -ea SilentlyContinue | Out-Null 
                Start-Sleep -milliseconds 500
            }
            catch {
                Write-Host "$(Get-Time) POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                $ErrorOccured = $True
            }
        }
    }

    # Create any NEW Subfolders if they dont currently exist in the destination.
    $Sourcefolders = GetDirectory -Path "$($SourceFolder)" -Directory -ExcludePathName @("_OLD")

    if ($Sourcefolders) {
        foreach ($directory in $Sourcefolders) {
           
            $newfolder = "$($DestinationFolder)\$($directory.PathName)"
            if (-not(Test-Path "$($newfolder)")) {
                if ($Testsync -eq $False) { 
                    try {
                        New-Item -Path "$($newfolder)" -ItemType Directory -Force -ea SilentlyContinue | Out-Null 
                        Start-Sleep -milliseconds 500
                    }
                    catch {
                        Write-Host "$(Get-Time) POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                        $ErrorOccured = $True 
                    }
                } # Change '-ea Stop' for trycatch to work
                $folderscreated++
            }
        }
    }
        
    # Copy any Files if the Lastwritten Date/time is different that what exists - or the file does not exist        
    $FromFiles = GetDirectory -Path $SourceFolder -Files -ExcludeFileName @("Thumbs.db", "desktop.ini") -ExcludePathName @("_OLD")

    foreach ($file in $FromFiles) {
        if ($file) {
            $copyfile = $False
            $fileName = $file.Name
            $Sourcetime = $file.LastWriteTime
            $newdestinationfolder = "$($DestinationFolder)\$($file.PathName)"
            $checkdestinationfile = "$($newdestinationfolder)"
          
            #destination file does not exist so set flag to copy it.
            if (-not(Test-Path "$($checkdestinationfile)")) { 
                $copyfile = $True
                $filescreated++
                $bytesadded = $bytesadded + $file.length

            }
            else {
                $Destinationfile = Get-ChildItem -Path "$($checkdestinationfile)"
                $Destinationtime = $Destinationfile.LastWriteTime
                if ($Destinationtime -ne $Sourcetime) { 
                    $copyfile = $True
                    $filesupdated++
				
                    if ($file.length -gt $Destinationfile.length) {
                        $bytesadded = $bytesadded + ($file.length - $Destinationfile.length)
                    }
                    if ($file.length -lt $Destinationfile.length) {
                        $bytesremoved = $bytesremoved + ($Destinationfile.length - $file.length )
                    }
                }
            }
            if ($copyfile) {
                try { 
                    if ($Testsync -eq $False) { 
                        Copy-Item -Path "$($file.FullName)" -Destination "$($newdestinationfolder)" -ea SilentlyContinue # Change '-ea Stop' for trycatch to work
                    } 
					 
                }
                catch {
                    Write-Host ""
                    Write-Host "$(Get-Time) POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                    $ErrorOccured = $True
                }
				 
                $filebytestotal = $filebytestotal + $file.length
				 
            } #// If Copyfile

        } # // If File
    } # // For each
        
    # Remove any Files in the Destination which are not in the Source
    $ToFiles = GetDirectory -Path "$($DestinationFolder)" -Files -ExcludeFileName @("Thumbs.db", "desktop.ini") -ExcludePathName @("_OLD")

    foreach ($file in $ToFiles) {
        if ($file) {            
            $deletefile = $False
            $fileName = $file.Name
            $olddestinationfolder = "$($SourceFolder)\$($file.PathName)"
            $checksourcefile = "$($olddestinationfolder)"
            if (-not(Test-Path "$($checksourcefile)")) { 
                try { 
                    if ($Testsync -eq $False) { Remove-Item -Path "$($file.FullName)" -ea SilentlyContinue | Out-Null } # Change '-ea Stop' for trycatch to work
                    $filesremoved++
                }
                catch { 
                    Write-Host ""
                    Write-Host "$(Get-Time) POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                    $ErrorOccured = $True
                }
            }
        }
    }
        
    # Remove any Directories in the Destination which are not in the Source
    $Destinationfolders = GetDirectory -Path "$($DestinationFolder)" -Directory -ExcludePathName @("_OLD")

    if ($Destinationfolders) {
        foreach ($folder in $Destinationfolders) {
            $olddestinationfolder = "$($SourceFolder)\$($folder.PathName)"
            $checksourcefolder = "$($olddestinationfolder)"
            if (-not(Test-Path "$($checksourcefolder)")) { 
                try { 
                    if ($Testsync -eq $False) { Remove-Item -Path "$($folder.FullName)" -ea SilentlyContinue | Out-Null }  # Change '-ea Stop' for trycatch to work
                    $foldersremoved++
                }
                catch {
                    Write-Host ""
                    Write-Host "$(Get-Time) POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                    $ErrorOccured = $True
                }
            }
        }
    }

    $outcome = "OK "
    if ($folderscreated -gt 0) { 
        $outcome = "$($outcome)$folderscreated New Folder" 
        $outcome = IfGreaterThan1AddChar $folderscreated  $outcome "s"
        if ($filescreated -gt 0 -OR $filesupdated -gt 0 -OR $filesremoved -gt 0 -OR $foldersremoved -gt 0) { $outcome = "$($outcome), " }
			
    }
        
    if ($filescreated -gt 0 ) { 
        $outcome = "$($outcome)$filescreated New File" 
        $outcome = IfGreaterThan1AddChar $filescreated $outcome "s"
        if ($filesupdated -gt 0 -OR $filesremoved -gt 0 -OR $foldersremoved -gt 0) { $outcome = "$($outcome), " }
			
    }
    if ($filesupdated -gt 0 ) { 
        $outcome = "$($outcome)$filesupdated File" 
        $outcome = IfGreaterThan1AddChar $filesupdated $outcome  "s"
        $outcome = "$($outcome) Updated"
        if ($filesremoved -gt 0 -OR $foldersremoved -gt 0) { $outcome = "$($outcome), " }
			
    }
    if ($filesremoved -gt 0 ) { 
        $outcome = "$($outcome)$filesremoved File"
        $outcome = IfGreaterThan1AddChar $filesremoved $outcome "s"
        $outcome = "$($outcome) Removed" 
        if ($foldersremoved -gt 0) { $outcome = "$($outcome), " }
    }
    if ($foldersremoved -gt 0) {
        $outcome = "$($outcome)$foldersremoved Folder"
        $outcome = IfGreaterThan1AddChar $foldersremoved $outcome "s"
        $outcome = "$($outcome) Removed" 
    }
        
    if ($ErrorOccured -eq $True) { $outcome = "FAILED" }

    if ($outcome -ne "OK ") {
        if ($bytesadded -gt 0 -or $bytesremoved -gt 0) {
            WRITE-HOST " - $($outcome) ($bytesadded Bytes Added, $bytesremoved Bytes Removed)"
        }
        else {
            WRITE-HOST " - $($outcome)"
        }
    }
    else {
        if ($bytesadded -gt 0 -or $bytesremoved -gt 0) {
            WRITE-HOST " - OK ($bytesadded Bytes Added, $bytesremoved Bytes Removed)"
        }
        else {
            WRITE-HOST " - OK"
        }
    }
		
    $i++
}
if ($filebytestotal -gt 0) {
    $formatedBT = Format-Size $filebytestotal
    Write-Host "TOTAL of $formatedBT copied to backup sync folder"
}
	
# Reset Each Disk Being Used
For ($i = 0; $i -lt $ReadUniqueID.Length; $i++) {
    Get-Disk | Where { $_.UniqueID -eq $ReadUniqueID[$i] } | Set-Disk -IsReadonly $ReadOnly
    Get-Disk | Where { $_.UniqueID -eq $ReadUniqueID[$i] } | Set-Disk -IsOffline $Offline 
        
}

# Remove Old Log Files
$LogFileAgeDescription = "$($LogFileAge) day"
##if($LogFileAge -gt 1) {$LogFileAgeDescription = "$($LogFileAgeDescription)s" } 
$LogFileAgeDescription = IfGreaterThan1AddChar $LogFileAge $LogFileAgeDescription  "s"
Write-Host "$(Get-Time) CLEAN - Removing log files older than $($LogFileAgeDescription) from folder: $($LogFolder)"
	
if (-NOT($test -eq $True)) { 
    Get-ChildItem "$($LogFolder)\Backup_*.log" | ? { $_.lastwritetime -le (Get-Date).AddDays(-$LogFileAge) } | % { Remove-Item $_ -force }
}
    
if ($ErrorOccured -eq $True) { 
    $Completed = "- FAILED"
}
else {
    $Completed = "- OK"
}
    
Write-Host "$(Get-Time) Completed $($Completed)"

# Ending a transcript log file, Catch error if transcript was not running.
try { stop-transcript | out-null }
catch [System.InvalidOperationException] {}


