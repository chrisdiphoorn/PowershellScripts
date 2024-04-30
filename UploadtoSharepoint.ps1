# Run-As Administrator
#if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Unrestricted -Force -File `"$PSCommandPath`"" -Verb RunAs; exit }

<#
Configuring an application in Azure AD
Below steps will help you create and configure an application in Azure Active Directory:

Go to Azure AD Portal via https://aad.portal.azure.com
Select Azure Active Directory and on App registrations in the left navigation
Select New registration
Enter a name for your application and select Register
Go to API permissions to grant permissions to your application, select Add a permission, choose SharePoint, Delegated permissions and select for example AllSites.Manage
Select Grant admin consent to consent the application's requested permissions
Select Authentication in the left navigation
Change Allow public client flows from No to Yes
Select Overview and copy the application ID to the clipboard (you'll need it later on)
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Load SharePoint CSOM Assemblies
Try{
	Add-Type -Path "C:\Program Files\SharePoint Online Management Shell\Microsoft.Online.SharePoint.PowerShell\Microsoft.SharePoint.Client.dll"
	Add-Type -Path "C:\Program Files\SharePoint Online Management Shell\Microsoft.Online.SharePoint.PowerShell\Microsoft.SharePoint.Client.Runtime.dll"
}
catch  {
	Write-host "Microsoft.Sharepoint.Online.Powershell DLLs Found."
}

#User Name Password to connect
$AdminUserName = "svc-sqlserver@joii.org"
$AdminPassword = ""                    # Application password created via https://aka.ms/createapppassword use to bypass 2nd authentication

#Prepare the Credentials
$SecurePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force

#Parameters -  https://{server_name}/sites/{sub_site} - GetFolderByServerRelativeUrl('/sites/sub_site/Shared%20Documents')/Files
$URL= "https://joiicommunity.sharepoint.com"
$Site = "/sites/JoiiTech66/"
$SiteURL = "$($URL)$($Site)"
$library="Shared Documents/HR3Backups"

$TargetFolderRelativeURL="/sites/JoiiTech66/Shared Documents/HR3Backups"
$SPFullTarget="$($SiteURL)$($library)"

$FilePath =  "D:\MSSQL\BACKUP"
$OkToDelete = $false
$failed = $false

$CalcTransfer = 0
$CalcTransferTotal = 0
$AVGCalcTransfer = 0
$AVGCalcTotal = 0
$AVGCalcTimes = 0

$MaxRetries = 5

#Function to Upload Large File to SharePoint Online Library
 Function UploadFileInSlice ($ctx,  $libraryName, $fileName, $FolderRelativeURL )  {

    # Reset Values
    $CalcTransfer = 0
    $CalcTransferTotal = 0
    $AVGCalcTimes = 0
    $AVGCalcTotal = 0
    $AVGCalcTransfer = 0
	$ErrRetries = 0

    $targetURL =  "$($FolderRelativeURL.Replace('  ','%20'))"
    $StartTime=(GET-DATE)

	$fileChunkSizeInMB = 10
	# Each sliced  upload requires a unique ID.
	$UploadId =  [GUID]::NewGuid()

	# Get the name of the  file.
	$UniqueFileName =  [System.IO.Path]::GetFileName($fileName)

	#  Get the folder to upload into.
    $web = $ctx.web
    $folder =  $web.GetFolderByServerRelativeUrl($targetURL)
    $ctx.Load($folder)
    $ctx.ExecuteQuery()
	
	#  File  object.
	[Microsoft.SharePoint.Client.File]  $Upload
	
    # convert chunksize into bytes.
	$BlockSize = $fileChunkSizeInMB *  1024 * 1024
	
    # Get the size of the  file.
	$FileSize = (Get-Item  $fileName).length
    $FSz = DisplayHumanReadable($FileSize)
	
    if ($FileSize -le  $BlockSize)
	{
        Write-Progress -Activity "Uploading: $UniqueFileName"
        Start-Sleep -Milliseconds 250

        try {
		    # Use regular  approach.
		    $FileStream = New-Object  IO.FileStream($fileName,[System.IO.FileMode]::Open,  [System.IO.FileAccess]::Read)
		    $FileCreationInfo  = New-Object  Microsoft.SharePoint.Client.FileCreationInformation
		    $FileCreationInfo.Overwrite  = $true
		    $FileCreationInfo.ContentStream  = $FileStream
		    $FileCreationInfo.URL =  $UniqueFileName
		    $folder =  $web.GetFolderByServerRelativeUrl($TargetFolderRelativeURL)
		    $folder.Files.Add($FileCreationInfo)
		    $ctx.Load($folder)
		    $ctx.ExecuteQuery()
            $failed = $false
        } catch {
            Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
            return $null
        }

	} else 	{
		#  Use large file upload  approach.

		$BytesUploaded = $null
		$Fs =  $null
        Write-Progress -Activity "Uploading: $fileName"
        Start-Sleep -Milliseconds 250

		
        try {
			$Fs =  [System.IO.File]::Open($fileName,  [System.IO.FileMode]::Open,  [System.IO.FileAccess]::Read)
			$br =  New-Object  System.IO.BinaryReader($Fs)
			$buffer =  New-Object  System.Byte[]($BlockSize)
			$lastBuffer =  $null
			$fileoffset = 0
			$totalBytesRead =  0
			$bytesRead
			$first = $true
			$last =  $false
        } catch {
            Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
            return $null
        }
			# Read data from file system in  blocks.
			while(($bytesRead =  $br.Read($buffer, 0, $buffer.Length))  -gt 0) {

				$totalBytesRead =  $totalBytesRead + $bytesRead
                $AVGCalcTimes++
                $AVGCalcTotal = $AVGCalcTotal + $CalcTransferTotal
                $AVGCalcTransfer= ($AVGCalcTotal / $AVGCalcTimes)

				# You've  reached the end of the  file.
				if($totalBytesRead -eq $FileSize)  {

					$last = $true
					# Copy to a new buffer  that has the correct size.
					$lastBuffer =  New-Object  System.Byte[]($bytesRead)
					[array]::Copy($buffer,  0, $lastBuffer, 0,  $bytesRead)

				}

				If($first)
				{
                    Write-Progress -Activity "Uploading: $UniqueFileName  Size: $FSz" -Status "Starting new content stream" 
                    Start-Sleep -Milliseconds 250

                    try {
					    $ContentStream  = New-Object System.IO.MemoryStream
					    #  Add an empty file.
					    $fileInfo =  New-Object  Microsoft.SharePoint.Client.FileCreationInformation
					    $fileInfo.ContentStream  = $ContentStream
					    $fileInfo.Url =  $UniqueFileName
					    $fileInfo.Overwrite =  $true
					    $folder =  $web.GetFolderByServerRelativeUrl($TargetFolderRelativeURL)

                        $Upload = $folder.Files.Add($fileInfo)
					    $ctx.Load($folder)
					    $ctx.ExecuteQuery()
                    } catch {
                        Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                        return $null
                    }

                    Write-Progress -Activity "Uploading: $UniqueFileName  Size: $FSz" -Status "Started"
                    Start-Sleep -Milliseconds 250

                    try {
					    #  Start upload by uploading the first  slice.
					    $s =  [System.IO.MemoryStream]::new($buffer)

					    #  Call the start upload method on the  first slice.
					    $BytesUploaded =  $Upload.StartUpload($UploadId,  $s)
					    $ctx.ExecuteQuery()

					    # fileoffset is  the pointer where the next slice will be  added.
					    $fileoffset =  $BytesUploaded.Value

					    # You can only  start the upload once.
					    $first =  $false
                     } catch {
                        Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                        return $null
                     }

				} Else 	{

					# Get a reference to  your file.
					## $Upload =  $ctx.Web.GetFileByServerRelativeUrl($Docs.RootFolder.ServerRelativeUrl  +  [System.IO.Path]::AltDirectorySeparatorChar  + $UniqueFileName);
                    try {
                        $Upload =  $ctx.Web.GetFileByServerRelativeUrl($folder.ServerRelativeUrl  +  [System.IO.Path]::AltDirectorySeparatorChar  + $UniqueFileName);
                    } catch {
                        $ErrRetries = 0
							do {
                                Write-host "FAILED: Connecting to '$($folder.ServerRelativeUrl  +  [System.IO.Path]::AltDirectorySeparatorChar  + $UniqueFileName)' Retry $ErrRetries" -f Red
								#Wait 20 Secs and retry again
								Start-Sleep -Milliseconds 20000
								try {
									$Upload =  $ctx.Web.GetFileByServerRelativeUrl($folder.ServerRelativeUrl  +  [System.IO.Path]::AltDirectorySeparatorChar  + $UniqueFileName);
									$failed = $false
								} catch {
									$failed = $true
								}
								$ErrRetries++
							} until(($ErrRetries -ge $MaxRetries) -OR ($failed -eq $false))
                    }
					If($last) {
                        Write-Progress -Activity "Uploading: $UniqueFileName  Size: $FSz" -Status "100% Completed" -PercentComplete 100
                        Start-Sleep -Milliseconds 250

						# Is  this the last slice of data?
						$s =  [System.IO.MemoryStream]::new($lastBuffer)
                        try {

						    #  End sliced upload by calling  FinishUpload.
						    $Upload =  $Upload.FinishUpload($UploadId,  $fileoffset,  $s)
						    $ctx.ExecuteQuery()

                        } catch {
                            $failed = $true
                        }

                        $FinishTime=(GET-DATE)
                        $diff = $FinishTime - $StartTime
                        $DiffMins = [Math]::Round([int]$diff.TotalMinutes,2)
                        $tbr = DisplayHumanReadable($totalBytesRead)
                        $tbt = DisplayHumanReadableSpeed($AVGCalcTransfer)

                        if ($failed -ne $true) {
						    #Write-host " - OK ($DiffMins Mins) ($tbt)" -f Green
                        } else {
                            Write-host "UPLOAD: $(get-date -format "HH:mm:ss")  File: $SourceFileName  Dated: $datecreated  Size: $size (After $DiffMins Mins)- FAILED" -f Red
		    				#Write-host " - FAILED after $tbr duration of $DiffMins Mins " -f Red
                            Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                        }

						# Return the file  object for the uploaded file.
						return  $Upload

					} else {

                        $i = [int](($totalBytesRead / $FileSize) * 100)
                        Write-Progress -Activity "Uploading: $UniqueFileName  Size: $FSz  Speed: $CalcTransfer" -Status "$i% Completed" -PercentComplete $i
                        Start-Sleep -Milliseconds 250

						$CalcTransferTimeSTART=(GET-DATE)
													
                        try {

                            $s =  [System.IO.MemoryStream]::new($buffer)
						    #  Continue sliced upload.
						    $BytesUploaded =  $Upload.ContinueUpload($UploadId,  $fileoffset, $s)
						    $ctx.ExecuteQuery()

                        } catch {
							
							$tbr = DisplayHumanReadable($totalBytesRead)
							$EMessage = $PSItem.ToString()
							$ErrRetries = 0
							
							do {
                                Write-host "FAILED: Sending Data at $($tbr)/$($FSz) - Retrying Now $($ErrRetries)/$($MaxRetries) Times after 20 Seconds." -f Red
								#Wait 20 Secs and retry again
								Start-Sleep -Milliseconds 20000
							
								try {
									$ctx.ExecuteQuery()
									$failed = $false
								} catch {
									$failed = $true
								}
								$ErrRetries++
							} until(($ErrRetries -ge $MaxRetries) -OR ($failed -eq $false))
								
							if ($failed -eq $true) {
								$FinishTime=(GET-DATE)
								$diff = $FinishTime - $StartTime
								$DiffMins = [Math]::Round([int]$diff.TotalMinutes,2)
								Write-host " ERROR after $tbr duration of $DiffMins Mins and $ErrRetries Retries." -f Red
								Write-host " ORIGINAL ERROR: $EMessage" -f Red
								Write-Host " Line: $($PSItem.InvocationInfo.ScriptLineNumber) Message: $_.Exception.Message" -f Red
								$failed = $true
							}
                        }

						#  Update fileoffset for the next  slice.
						$fileoffset =  $BytesUploaded.Value

                        #Calculate the Last Transfer Speed in bytes / sec
                        $CalcTransferTimeEND=(GET-DATE)
                        $CalcTransferTime = ($CalcTransferTimeEND - $CalcTransferTimeSTART).TotalSeconds
                        $CalcTransferTotal = ($BlockSize * 8) / $CalcTransferTime
                        $CalcTransfer = DisplayHumanReadableSpeed($CalcTransferTotal)
                        
					} #// last

				} #// First

			} #// while  ((bytesRead = br.Read(buffer, 0,  buffer.Length)) > 0)

		
		if ($Fs -ne  $null) { $Fs.Dispose() }

        
    }
	return  $null
}


function DisplayHumanReadable($num) 
{
    $suffix = "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"
    $index = 0
    while ($num -gt 1kb) 
    {
        $num = $num / 1kb
        $index++
    } 
    return "{0:n2}{1}" -f $num, $suffix[$index]
}

Function DisplayHumanReadableSpeed($num) 
{
    $suffix = "Bps", "KBps", "MBps", "GBps", "TBps", "PBps"
    $index = 0
    while ($num -gt 1kb) 
    {
        $num = $num / 1kb
        $index++
    } 
    return "{0:n2} {1}" -f $num, $suffix[$index]
}

Function DeleteOldFiles([Microsoft.SharePoint.Client.Folder] $fld, [Microsoft.SharePoint.Client.ClientContext] $Ctx, [int] $cdays)
{
    $today=(GET-DATE).Date
    $diff= (([datetime]$today).Date).AddDays(-$cdays).ToString(‘dd/MM/yyyy’)
	Write-Output ""
    Write-Output "Deleting files older than $cdays days from $($fld.Name) (Older than $($diff) )"

    # keep track of the oldest file.
    $maxDays = 0 

    #check if any files were deleted.
    $deletedfile = $false 

    # Get a list of files in the sharpoint folder.
    $files = $fld.Files
    $Ctx.Load($fld.Files)
    #### $Ctx.Load($fld.Folders)
    $Ctx.ExecuteQuery()

    foreach($file in $files)
    {

        $dte = ($file.TimeCreated).ToString(‘yyyy/MM/dd’)
        $diff= $today - ([datetime]$dte).Date
        $diffdays = $diff.TotalDays
        $itemID = $TargetFolderRelativeURL+ "/"+$file.Name
		$size = DisplayHumanReadable($file.Length)

        # keep track of the oldest file.
        if ($diffdays -gt $maxDays) { $maxDays = $diffdays }

        if ($diffdays -gt $cdays) {
            try {
                    Write-Host "DELETE: $($file.name) ($size) ($diffdays days old) - OK " -f Green
                    $DFile = $Ctx.web.GetFileByServerRelativeUrl($itemID)
                    $Ctx.Load($DFile)
                    $Ctx.ExecuteQuery()
                    Start-Sleep -Milliseconds 500
                    $DFile.DeleteObject()
                    $Ctx.ExecuteQuery()
                    Start-Sleep -Milliseconds 500
                    $deletedfile = $true
            } Catch {
                    Write-Host "RETRYING: $($_.Exception.Message)" -f Red
                    Start-Sleep -Milliseconds 1000
                    try {
                            $Ctx.Load($DFile)
                            $Ctx.ExecuteQuery()
                            Start-Sleep -Milliseconds 500
                            $DFile.DeleteObject()
                            $Ctx.ExecuteQuery()
                            Start-Sleep -Milliseconds 500
               	            $deletedfile = $true		
                    } catch {
                            Write-Host "Deleting File $($file.name) - FAILED " -f Red
                            Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                    }
             }
        } else {
            # Write-Host "$($file.name) $diffdays"
        }
    }
    if ($deletedfile -eq $false) { write-host "No files were deleted. The oldest file is currently $maxDays days old." -f Green }
}


# Use a transcript log file if running from the powershell file. Catch error if transcript cant run.
try { start-transcript -Path "d:\scripts\Sharepoint_$(get-date -format "ddMMyyyy").log" |out-null } catch [System.InvalidOperationException]{}

$StartDate=(GET-DATE)

$Files = Get-ChildItem $FilePath

Write-Host "$(get-date -format "ddd dd MMM yyyy HH:mm:ss") Backup Task for SQL database files $FilePath\*.* --> $($SPFullTarget)"
Write-Host ""

Try	{
		#Setup the new Connection
		write-host "Authenticating to Sharepoint using $($AdminUserName) credentails." 
		$Ctx = New-Object Microsoft.SharePoint.Client.ClientContext($SiteURL)
		$Creds = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($AdminUserName, $SecurePassword)
		$Ctx.Credentials = $Creds
        write-host ""
		
        #But you only have 30mins to upload a file or part of a file!
        $Ctx.RequestTimeout = [System.Threading.Timeout]::Infinite         
                
		# Copy the files to Sharepoint if they dont already exist
		foreach($File in $Files) {

			$SourceFileName = Split-path $File -leaf
			$TargetFileURL = $TargetFolderRelativeURL.Replace('  ','%20')+[System.IO.Path]::AltDirectorySeparatorChar+$SourceFileName
			$FileExists = $false
            $failed = $false
			$datecreated = $File.LastWriteTime.ToString('dd/MM/yyyy')
			$size = DisplayHumanReadable($File.Length)
			$ssize = 0
            $lsize = $File.length
            #Try to see if the file already exists If the file does not exist then and error will occur - this is the way to see if a file exists.
            #write-host "FILE: $SourceFileName $datecreated $size"
			Try {
                      $web = $ctx.web
			    	  $CheckFile = $web.GetFileByServerRelativeUrl($TargetFileURL)
                      
                      Try {
                           $Ctx.Load($CheckFile)
			               $Ctx.ExecuteQuery()
                           Start-Sleep -Milliseconds 500

                           $ssize = $CheckFile.Length
                           $FileExists = $true
                      } Catch {
                                $FileExists = $false
                                if ($($PSItem.ToString()) -NotMatch "The sign-in name or password does not match one in the Microsoft account system" ) {
                                    if ($($PSItem.ToString()) -NotMatch "File Not Found" ) {
                                        Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                                    }
                                } else {
                                    Write-Host "AUTH: Password or Username is wrong?" -f Red
                                    $failed = $true
                                    break
                                }
                      } #End Try/Catch
			} Catch {
            	        $FileExists = $true
				        Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red

            } #End Try/Catch

			if ($FileExists -eq $false -AND $failed -eq $false) {
				$failed = $false
				$UpFile = UploadFileInSlice -ctx $Ctx -libraryName $library -fileName "$FilePath\$File" -FolderRelativeURL $TargetFolderRelativeURL
                if ($failed -eq $false) {
                    Write-host "UPLOAD: $(get-date -format "HH:mm:ss")  File: $SourceFileName  Dated: $datecreated  Size: $size - OK" 
                }
                $OKToDelete= $true
			}
			
            if ($FileExists -eq $true) {
                $sizeOK ="- OK"
                $deletefile = $false
                $dssize = DisplayHumanReadable($ssize)
                $dlsize = DisplayHumanReadable($lsize)
                if ($ssize -ne $lsize) {
                    $SizeOK="- FAILED: (Local File: $($dlsize) Sharepoint File: $($dsize))"
                    if ($ssize -eq 0) {
                        $deletefile = $true
                    }
                   
                }
                Write-host "FILE: $SourceFileName Already Exists. $sizeOK" -f Green

                # Remove the Sharepoint file if it does not have a Size (0 bytes) - as this was a uploaded file which was never completly uploaded. The next time this script runs it can attempt to upload it again.
                if($deletefile -eq $true) {
                     Write-host "REMOVE: $TargetFolderRelativeURL/$SourceFileName - Uncompleted Upload " -f Green -NoNewline 
                     try {
                        $Ctx.Load($CheckFile)
                        $Ctx.ExecuteQuery()
                        Start-Sleep -Milliseconds 500
                        $CheckFile.DeleteObject()
                        $Ctx.ExecuteQuery()
                        Write-host " - OK"
                    Start-Sleep -Milliseconds 50
                    } catch {
                        Write-host " - FAILED" -f Red
                        Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
                    } #End Try/Catch
                }
            }
		    #Write-Host "Ran into an issue: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
			#Write-Host ""
		}
	}
Catch {
		write-host "Error Connecting to Sharepoint" -f Red
        Write-Host "POWERSHELL: $($PSItem.ToString()) Line: $($PSItem.InvocationInfo.ScriptLineNumber)" -f Red
        write-host $TargetFileURL -f Red
        $OKToDelete= $false
}


if ($Failed -eq $false) {
	if ($OKToDelete -eq $true) {

		#Only Delete if something was uploaded. This way if uploading does fail, then at least some backups will still exist in Sharepoint
		$Ctx = New-Object Microsoft.SharePoint.Client.ClientContext($SiteURL)
		$Creds = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($AdminUserName, $SecurePassword)
		$Ctx.Credentials = $Creds
		$web = $Ctx.Web
		$Ctx.ExecuteQuery() 

		$folder = $web.GetFolderByServerRelativeUrl($web.ServerRelativeUrl + $TargetFolderRelativeURL)
		$Ctx.Load($folder)
		$Ctx.ExecuteQuery()

		DeleteOldFiles $folder $Ctx 16
	}
}

write-host "$(get-date -format "HH:mm:ss") Backup Task Completed."
write-host ""
# Revoke-PnPUserSession -User $AdminUserName

# Ending a transcript log file, Catch error if transcript was not running.
try { stop-transcript |out-null }
catch [System.InvalidOperationException]{}

