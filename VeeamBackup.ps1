# Failed to get folder properties. Not allowed to access Non IPM folder.
# Stop the Veeam Backup for Microsoft 365 Service and Veeam Backup Proxy for Microsoft 365 Service
# 2. Go to: C:\ProgramData\Veeam\Backup365
# 3. Make a copy of the Config.xml file
# 4. Edit the Config.xml file
# 5. Add <Proxy SkipTeamsMessagesDataFolders="True" />  (right before the </Archiver> tag)
# 6. Start the Veeam Backup for Microsoft 365 Service and Veeam Backup Proxy for Microsoft 365 Service

#if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function CreateFolderIfNotExist ( [string] $FolderPath, [string] $TextToShow ) {

    $tp = Test-Path -Path "$($FolderPath)"
    if ($tp -eq $False) {
        if ($TextToShow) {
            Write-host $TextToShow
        }
        try {
            mkdir "$($FolderPath)" | out-null
        } 
        catch { }
        Start-Sleep -s 1
    }
}
 
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

function RemoveAllEntityBackups { 
    param() 

        
    $alllistrepos = Get-VBORepository
    foreach ($listrepos in $alllistrepos) {
        
        $DefaultVeeamRepository = "$($listRepos.Name)"
        Write-Host " Removing all User Backups from Repository : $($DefaultVeeamRepository)"
        $repo = Get-VBORepository -Name $DefaultVeeamRepository
        
        $usersList = Get-VBOEntityData -Type User -Repository $repo
        $groupsList = Get-VBOEntityData -Type Group -Repository $repo
        $sitesList = Get-VBOEntityData -Type Site -Repository $repo

        foreach ($ruser in $usersList) {
            if ($ruser -ne $null) {
                Write-Host " Removing: $ruser"
                Remove-VBOEntityData -Repository $repo -User $ruser -Mailbox -ArchiveMailbox -OneDrive -Sites -Confirm:$false | out-null
                Start-Sleep -s 1
            }
        }
        foreach ($group in $groupsList) {
            Write-Host " Removing: $group"
            Remove-VBOEntityData -Repository $repo -Group $group -GroupMailbox -GroupSite -Confirm:$false | out-null
            Start-Sleep -s 1
        }
        foreach ($site in $sitesList) {
            Write-Host " Removing: $site"
            #Remove-VBOEntityData -Repository $repo -Site $site -Confirm:$false | out-null
            Start-Sleep -s 1
        }
              
    }
}

Function Format-Size() {
    Param ([long]$size)
    If ($size -gt 1TB) { [string]::Format("{0:0.00} TB", $size / 1TB) }
    ElseIf ($size -gt 1GB) { [string]::Format("{0:0.00} GB", $size / 1GB) }
    ElseIf ($size -gt 1MB) { [string]::Format("{0:0.00} MB", $size / 1MB) }
    ElseIf ($size -gt 1KB) { [string]::Format("{0:0.00} kB", $size / 1KB) }
    ElseIf ($size -gt 0) { [string]::Format("{0:0.00} B", $size) }
    Else { "NULL" }
}

            
Function RemoveVeeamJob() {
    Param ([string]$action, [string]$name)
      
    if ($action -ne "") {
        if ($name -eq "") {
            $getJobs = Get-VBOJob | fl
        }
        else {
            $getJobs = Get-VBOJob -Name "$name" | fl
        }
        foreach ($ajob in $getjobs) {
            if ($ajob.LastStatus -eq "$($action)") {
                write-host " ** REMOVE ** $($action) Job: $($ajob.Id) $($ajob.Name)" 
                Remove-VBOJob -Job $ajob -Confirm:$false | out-null
            }
        }
    }
}

Function StopVeeamJob() {
    Param ([string]$action, [string]$name)
      
    if ($action -ne "") {
        if ($name -eq "") {
            $getJobs = Get-VBOJob | fl
        }
        else {
            $getJobs = Get-VBOJob -Name "$name" | fl
        }
        foreach ($ajob in $getjobs) {
            if ($ajob.LastStatus -eq "$($action)") {
                write-host " ** STOP ** $($action) Job: $($ajob.Id) $($ajob.Name)" 
                Stop-VBOJob -Job $ajob | out-null
            }
        }
    }
}

Function GetDiskGBFree() {
    Param ([string]$drive)
    Try {
        $free = (Get-CimInstance -ClassName Win32_LogicalDisk  -Filter "DriveType=3  AND DeviceId = $drive" -ErrorAction SilentlyContinue | Select-Object -Property DeviceID, @{'Name' = 'FreeSpace (GB)'; Expression = { [int]($_.FreeSpace / 1GB) } } | Measure-Object -Property 'FreeSpace (GB)' -Sum).Sum
    } 
    Catch {
        $free = ""
    }
    return $free
}


# POWERSHELL Veeam Backup

Import-Module "C:\Program Files\Veeam\Backup365\Veeam.Archiver.PowerShell\Veeam.Archiver.PowerShell.psd1"

#$RequiredModules= @('PowerShellGet','ExchangeOnlineManagement','Veeam.Archiver.PowerShell', 'Veeam.Backup.PowerShell','Veeam.SharePoint.PowerShell', 'Veeam.Exchange.PowerShell')
#$MyModulePath = "C:\Program Files\Veeam\Backup365\Veeam.Archiver.PowerShell"
#$env:PSModulePath = $env:PSModulePath + "$([System.IO.Path]::PathSeparator)$MyModulePath"
#if ($Modules = Get-Module -ListAvailable -Name Veeam.Backup.PowerShell) { }
#Install the Modules that maybe required to run this Script
#$failedmodules = $false
#foreach ($Module in $RequiredModules) {
#  Install-ModuleIfNotInstalled $Module
#}
#if (Get-PSRepository "PSGallery") {
#   Set-PSRepository -Name "PowerShellGet" -InstallationPolicy Trusted
#   Unregister-PSRepository -Name "PSGallery"
#}

$tp = Test-Path -Path "x:\"
if ($tp -eq $False) {   	
    net use x: \\10.4.2.248\Archive /user:10.4.2.248\archive uglyK!te72
}


$joii = "joii.org"
    
$failedfile = "C:\scripts\backup-failed.txt"
$backupfile = "C:\scripts\backup.txt"

$archiveserver = "X:\_JOII"
$DefaultVeeamRepository = "Veeam Repos"
$OrganizationName = "joiicommunity.onmicrosoft.com"

$BackupFolder = "N:\BACKUP-Temp"
$BackupSharePoint = "$BackupFolder\SharePoint"
$BackupOneDrive = "$BackupFolder\OneDrive"

Get-PSSession | Remove-PSSession | out-null
Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore -ErrorAction SilentlyContinue | out-null

# Remove Previous Powershell Exchange Session Connections.
Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' } | Remove-PSSession -ErrorAction SilentlyContinue | out-null
  
# $dn = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://10.5.2.10:389/OU=Users, ou=JOII, dc=ad,dc=joii, dc=org","ldap@ad.joii.org","uglyK!te72")
# $Rech = new-object System.DirectoryServices.DirectorySearcher($dn)
# $rc = $Rech.SearchScope = "subtree"
# $rc = $Rech.PropertiesToLoad.Add("mail")
# $rc = $Rech.PropertiesToLoad.Add("displayName")
# $rc = $Rech.PropertiesToLoad.Add("sAMAccountName")
# $rc = $Rech.PropertiesToLoad.Add("userAccountControl")
# $rc = $Rech.PropertiesToLoad.Add("distinguishedName")
# $rc = $Rech.PropertiesToLoad.Add("userPrincipalName")
# $rc = $Rech.PropertiesToLoad.Add("description")

$usernames = @()
$fullnames = @()
$mailboxes = @()
$mailemails = @()
$mailid = @()
$fmailboxes = @()
$mailboxessize = @()
$mailboxesdelsize = @()
$mailboxtype = @()
$fmailboxes = [string[]](Get-Content -Path $backupfile | Select-Object)

# Create Office365 Admin login credentials

#$pass = "ffjljhrgkybhylqg" | ConvertTo-SecureString -asPlainText -Force
$pass = "uglyK!te72" | ConvertTo-SecureString -asPlainText -Force
$creds = $credential = New-Object System.Management.Automation.PSCredential("veeam@joii.org", $pass)
    
#Connect-ExchangeOnline -Credential $creds -ShowBanner:$false | out-null 
#Connect-ExchangeOnline -CertificateFilePath "C:\scripts\NEWJoii.pfx" -CertificatePassword (Get-Credential).password -AppID "034992ed-219d-460f-92a2-93dbd177486d" -Organization "joiicommunity.onmicrosoft.com"
#https://login.microsoftonline.com/joiicommunity.onmicrosoft.com/adminconsent?client_id=
#Connect-ExchangeOnline  -Organization "$OrganizationName" 
#Connect-ExchangeOnline  
#$securespass
    
Connect-ExchangeOnline

$organization = Get-VBOOrganization -Name $OrganizationName
$connection = New-VBOOffice365ConnectionSettings -Credential $Creds -GrantRolesAndPermissions
	
$listrepos = Get-VBORepository | Select-Object -First 1
$DefaultVeeamRepository = $listRepos.Name
    
Clear-Host
cls

write-host " Veeam Repositories."
$repodata = Get-VBOUsageData -Repository $listrepos
foreach ($re in $repodata) {
    write-host " Id: $($re.RepositoryId)  Used: $($re.UsedSpace) Cache: $($re.LocalCacheUsedSpace)  Object: $($re.ObjectStorageUsedSpace)  "
}

    

$repository = Get-VBORepository -Name $DefaultVeeamRepository
    
RemoveAllEntityBackups
    
$users = Get-VBOLicensedUser -ErrorAction SilentlyContinue
if ($users) {
    write-host " Removing $($users.count) Veeam Licensed Users."
    foreach ($ruser in $users) {
        $postfach = Get-VBOLicensedUser -Name $ruser.username
        if ($postfach -ne $null) {
            Remove-VBOLicensedUser -User $postfach | out-null
        }
    }
}


RemoveVeeamJob "Stopped", ""
RemoveVeeamJob "Success", ""
RemoveVeeamJob "Warning", ""
RemoveVeeamJob "Failed", ""

write-host " "

if ($fmailboxes) { 
    write-host " Now Retrieving 365 Mailbox Details..." 
       
}

foreach ($uname in $fmailboxes) {
    $uname = $uname.trim()
    if ($uname.length -gt 0 ) {
      
        $MovetoUnsynced = $false
        $name = $uname.Replace("`'", "")

        $username = $name.trim()
        $fullname = ""
        $loginname = $username

        if ($name -NotLike "*@*" ) {
            $username = $name.Replace(".", " ")
            $fullname = (Get-Culture).TextInfo.ToTitleCase($username)
        }
        else {
            $fullname = $name -replace "@joii.org", ""
            $fullname = $fullname -replace "`@.*", ""
            $loginname = $fullname -replace " ", "."
        }

        $username = $name.Replace(" ", ".")

        $theUser = ""
        $finduser = ''
        $mailbox = ''
        $user2Find = $username.ToLower()
        $userdisabled = ''
        $recipientType = ''
        $upn = ''
        $desc = ''
        $useraccount = ''

        #Find the Users account In Active Directory
        if ($joii.length -eq 0) {
            if ($username.Contains("`@")) {
                # Find the user by using the the emailaddress
                $rc = $Rech.filter = "((mail=$username))"
                $theUser = $Rech.FindOne()
            }
            # Find the user by using the account name
            if ($theUser.length -eq 0) {
                $rc = $Rech.filter = "((sAMAccountName=$user2Find))"
                $theUser = $Rech.FindOne()
            }
            # Find the user by using the the displayName if not previously found
            if ($theUser.length -eq 0) {
                $rc = $Rech.filter = "((displayName=$fullname))"
                $theUser = $Rech.FindOne()
            }
            if ($theUser.length -eq 0) {
                $rc = $Rech.filter = "((distinguishedName=$username))"
                $theUser = $Rech.FindOne()
            }
            if ($theUser.length -gt 0)	{
                $mailbox = $theUser.Properties["mail"]

                $fullname = $theUser.Properties["displayName"]
                $username = $theUser.Properties["sAMAccountName"]

                $useraccount = $theUser.Properties["userAccountControl"]
                $distinguishedName = $theUser.Properties["distinguishedName"]
                $upn = $theUser.Properties["userPrincipalName"]
                $desc = $theUser.Properties["decription"]

                # If the mailbox does not have a proper email address, then try and find it from the rest of the AD information                    
                if ($mailbox -notlike "*@*" ) { 
                    if ($loginname -eq "") {
                        $mailbox = $upn
                    }
                    else {
                        $mailbox = $loginname
                    }
                }

            }
            else {
                # make It Up
                $mailbox = $username
                if (-not $loginname -eq "") {
                    $mailbox = $loginname
                }
            }

            if ($useraccount -eq 514) { $userdisabled = " - Disabled" }
            # ACCOUNTDISABLE	0x0002	2
            # NORMAL_ACCOUNT	0x0200	512
            # Disabled = 514

        }
        else {
            # for joii backups only use the username value as it cant lookup Active Directory
                
            $theUser = $username
            $fullname = $theUser.Replace("@joii.org", "")
            $fullname = $fullname.Replace(".", " ")
            $theUser = $username
            $mailbox = $username
            if ($mailbox -notlike "*@*" ) { $mailbox = $mailbox + "`@joii.org" }
        }


        # Look up the mailbox in office 365 and get the size and to confirm that is does exist
        if ($mailbox -ne "") {
                
            write-host  -NoNewLine " $($mailbox) $($userdisabled)"
            $memailbox = ''

            if ($mailbox.Contains("`@")) {
                $memailbox = Get-EXOMailbox -PrimarySmtpAddress "$mailbox" -ErrorAction SilentlyContinue
                if ($memailbox -eq "" -or $memailbox -eq $null) {
                    $memailbox = Get-EXOMailbox -UserPrincipalName "$mailbox" -ErrorAction SilentlyContinue
                }
            }
            if ($memailbox -eq "" -or $memailbox -eq $null) {
                $memailbox = Get-EXOMailbox -Identity "$mailbox" -ErrorAction SilentlyContinue                
            }
            if ($memailbox -ne "" -and $memailbox -ne $null) {
                
                foreach ($mb in $memailbox) {
                    $mboxname = $mb.Alias.ToString()
                    $mbox = $mb.Name.ToString()
                    $mboxID = $mb.Identity.ToString()
                    $recipientType = $mb.RecipientTypeDetails.ToString()

                    if ($fullname -eq "") { $fullname = $mboxID }

                    $id = $mb.Guid.ToString()
                    $mbe = [string]::Join([Environment]::NewLine, $mb.UserPrincipalName.ToString());
                    $pse = $mb.PrimarySmtpAddress.ToString()

                    $ArchiveFolder = "$($archiveserver)\$($mbe.ToLower())"
                    $tp = Test-Path -Path $ArchiveFolder
                    $gpst = ''
                    if ($tp -eq $True) {
                        $gpst = Get-ChildItem -Path "$ArchiveFolder\*.pst"
                    }
                    if ($gpst) { 
                        write-host "  PST Files found in $($ArchiveFolder) - NOT Backing up this mailbox." 
                    }
                    else {
                        $mailboxes += $mbe
                        $mailemails += $pse
                        $mailid += $id
                        $usernames += $mboxname
                        $fullnames += $fullname
                        $mailboxtype += $recipientType
                        $mailboxsize = ''
                        $boxsize = 0
                        $delsize = 0
                        [long]$totsize = 0

                        if ($id -ne '') {
                            $mstat = Get-EXOMailboxStatistics -Identity $id  -ErrorAction SilentlyContinue
                            if ($mstat) {
                                $md = $mstat | Select-Object -Property @{Name = ”TotalDeletedItemSize”; expression = { [math]::Round(($_.TotalDeletedItemSize.ToString().Split('(')[1].Split(' ')[0].Replace(',', '')), 2) } } | Format-Table -HideTableHeaders | Out-String
                                $m = $mstat | Select-Object -Property @{Name = ”TotalItemSize”; expression = { [math]::Round(($_.TotalItemSize.ToString().Split('(')[1].Split(' ')[0].Replace(',', '')), 2) } } | Format-Table -HideTableHeaders | Out-String
                                $m = [string]::Join([Environment]::NewLine, $m);
                                $md = [string]::Join([Environment]::NewLine, $md);
                                $boxsize = [long]$m.trim() 
                                $delsize = [long]$md.trim()
                            }
                        }

                        #$totsize = $boxsize +  $delsize
                        $totsize = $boxsize 
                        $msize = Format-Size($totsize) 
        
                        $mailboxsize = Format-Size($boxsize) 
                        $mailboxdelsize = Format-Size($delsize) 
                        $mailboxessize += $mailboxsize
                        $mailboxesdelsize += $mailboxdelsize
                        write-host "  $($msize)" 
                    }

                } # END foreach

            }
            else {

                write-host " - Mailbox Not Found in 365. Maybe -> Allocate a temporary Mail License to this account and try again."
                $tmpstr = [string[]](Get-Content -Path $backupfile | Select-Object)
                if (-not $tmpstr.Contains("$mailbox")) {
                    Add-Content $failedfile "$mailbox"
                }
            }

        }
    
    }
}     



#Connect-VBOServer -Server 127.0.0.1 
#Clear-Host

write-host " "
if ($mailboxes) { 
    write-host " Now Running a Backup for each User." 
    write-host " "
    $maxbox = $mailboxes.count
}
$a = 0
$recheck = @()

foreach ($usermailbox in $mailboxes) {
            
    foreach ($rc in $recheck) {
        $checkjob = Get-VBOJob -Name "$mailboxes[$rc]" | select-object LastStatus
        if ($checkjob.LastStatus -ne "Running") {
            write-host " A Previous backup job has finally completed for $rc"
            $addrecheck = $rc
            break
        }
    }
    $recheckid = $a
    $mailbox = $usermailbox
    $username = $usernames[$a]
    $fullname = $fullnames[$a]
    $emailaddress = $mailemails[$a]
    $mailboxsize = $mailboxessize[$a]
    $boxtype = $mailboxtype[$a]
    $arname = $username.Replace(" ", ".")
    $arname = $arname.Replace("`'", "")
            
    write-host "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
    write-host "$($a+1)/$maxbox  Name: $($fullname)  User: $($username)  Email: $($emailaddress)  Mailbox: $($mailbox)  Size: $($mailboxsize)"  [$($boxtype)]
    write-host "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
	        
    $ArchiveFolder = "$($archiveserver)\$($arname.ToLower())"
	                    
    $gpst = ""
            
    CreateFolderIfNotExist "$BackupFolder" 
                           
                
    $backupStatus = "- OK"
    $startbackup = $false

    if ($ArchiveFolder -NotLike "*@*") {
        # Create the new user folders in the archive server if they are not found
        $tp = Test-Path -Path $archiveserver 
        if ($tp -eq $True) {
            CreateFolderIfNotExist "$($ArchiveFolder)" " Creating new archive folder $($ArchiveFolder)"
        }
                
        Write-Host -Nonewline " Checking for any existing PST files in $ArchiveFolder" 
        $gpst = Get-ChildItem -Path "$($ArchiveFolder)\*.pst"

        if ($gpst) { 
            Write-Host " - WARNING $($gpst.count) Files Found!"
            $startbackup = $false
        }
        else {
            Write-Host " - OK"
            $startbackup = $True
        }

    }
    else {
        # @ email address in archive folder name
        $ArchiveFolder = ""  # the archive foldername is blank so the script wont try and create a invalid folder name
        $startbackup = $true
        Write-Host "  *** Manually copy backup files once completed from this folder $BackupFolder"
    }
                
    if ($startbackup -EQ $true) {
        Write-Host " Veeam backup process now starting."
        # Remove all existing jobs from veeam for the mailbox user
        StopVeeamJob "Running", $mailbox
        Start-Sleep -s 2
        RemoveVeeamJob "Stopped", "$mailbox"
        RemoveVeeamJob "Success", "$mailbox"
        RemoveVeeamJob "Warning", "$mailbox"
        RemoveVeeamJob "Failed", "$mailbox"
        Start-Sleep -s 1
              
        #Write-Host " Removing All Existing Backup Jobs."
        #Get-VBOExchangeItemRestoreSession | Stop-VBOExchangeItemRestoreSession | out-null
                    

        $checkjob = Get-VBOJob -Name "$mailbox" | select-object LastStatus
        if ($checkjob.LastStatus -ne "Running") {

            # Create new Backup User Mailbox
            Write-Host " Creating a new Veeam 365 Mailbox Backup Job."
            $user = Get-VBOOrganizationUser -Organization $organization -UserName "$mailbox" 
                
            #Existing job not found so create a new one!
            $backupitems = New-VBOBackupItem -User $user -Mailbox -ArchiveMailbox -OneDrive -Sites
            Write-Host " Check existing Backup Sessions."
    	                    
            #Check if job already exists?
            $findexistingjob = Get-VBOJob -Name "$mailbox" -Organization $organization 
            if ($findexistingjob.count -eq 0) {
                # Add new Backup Job as it does not exist
                Write-Host " Adding a New Backup Job."
	               Add-VBOJob -Name "$mailbox" -Organization $organization -Repository $repository -SelectedItems $backupitems  | out-null
            }
                        
            #Name, Repository, Organization, IsEnabled
            # Start Full Backup Job
            $job = Get-VBOJob -Name "$mailbox"
            if ($job.LastStatus -eq "Running") {
                Write-Host " *** WARNING ** An existing Job is still running for this Mailbox!"
            }
            else {
                Write-Host " Starting a Backup Job $($job.Id)"
                try {
                    Start-VBOJob -Job $job -Full  | out-null
                } 
                catch {
                    Write-Host " Re-connecting to Veeam Backup Server"
                    Disconnect-VBOServer | out-null
                    Connect-VBOServer -Server 127.0.0.1 | out-null
                }

                # ------------------------------------------------------------------------------------------- WAIT FOR RUNNING JOB TO Finish
                Write-Host " -> " -NoNewline
                do {
                    $getjob = ""
                    $iscompleted = ""
                    try {
                        $getjob = Get-VBOJobSession -Job $job -Last
                    }
                    catch {
                        Write-Host " Re-connecting to Veeam Backup Server"
                        Connect-VBOServer -Server 127.0.0.1 | out-null
                        Start-Sleep -s 5
                    }
                        
                    if ($getjob) { $iscompleted = $getjob.Status }

                    if ($iscompleted -eq "Running") { 
                        Start-Sleep -s 60
                        Write-Host "." -NoNewline
                    }

                } until ($iscompleted -ne "Running")

                Write-Host ""

                # --------------------------------------------------------------------------------------------------------------------------
            }
                        
            Start-Sleep -s 1
            $jobsession = Get-VBOJobSession -Job $job -Last
            $jobid = $jobsession.JobId
            $completed = $jobsession.Status
            $progress = $jobsession.Progress
            $stats = $jobsession.Statistics
                        

            $IsExchange = $false
            $IsSharePoint = $false
            $IsOneDrive = $false
            $IsTeams = $false

            if ($completed -eq "Success" -Or ( $completed -eq "Warning" -And $progress -ne "0")) {

                Write-Host " Backup Job: $($jobId) - Status: $($completed) - Items: $($stats) - : $($progress)"

                $getrestorepoints = Get-VBORestorePoint  | Where-Object { $_.JobId -eq $jobid }

                $backingup = ""
                if ($getrestorepoints.IsExchange -eq "True") { 
                    $IsExchange = $true 
                    $backingup = "Exchange"
                }
                if ($getrestorepoints.IsSharePoint -eq "True") { 
                    $IsSharePoint = $true 
                    $backingup = $backingup + ", SharePoint"
                }
                if ($getrestorepoints.IsOneDrive -eq "True") { 
                    $IsOneDrive = $true 
                    $backingup = $backingup + ", OneDrive"
                }
                if ($getrestorepoints.IsTeams -eq "True") { 
                    $IsTeams = $true
                    $backingup = $backingup + ", Teams"
                }

                Write-Host " Found $($backingup) Backup containing $($progress) Item. - $($stats)"
                $exportsize = ''

                if ($IsExchange -eq $true) {
                    Write-Host -NoNewLine " Processing Export Exchange Items Session. "
                    # Export the Backup to a PST File
                    Start-VBOExchangeItemRestoreSession -Job $job -LatestState | out-null
                    Start-Sleep -s 2
                                
                    $session = ''
                    $sess = Get-VBOExchangeItemRestoreSession 
                    foreach ( $s in $sess) {
                        if ($s.Stores.Values -Like "*$($mailbox)*" -ne "") {
                            $session = $s
                            break
                        }
                    }
                                
                    $rmb = "F:\dummyfile.wow"
                    if ($session) {
                        $sessionID = $session.Id
                        $sessionRestorable = $session.IsRestoreAvailable

                        # Returns Microsoft Exchange mailbox databases.
                        $database = Get-VEXDatabase -Session $session 
                        #$databasename = $database.Name

                        # Returns Microsoft Exchange mailboxes.
                        $mailboxes = Get-VEXMailbox -Database $database 

                        $tp = Test-Path -Path "$BackupFolder"
                        if ($tp -eq $True) {
                            # normally there should only be 1 mailbox to backup... but just incase use a foreach....
                            if ($mailboxes) {
                                #$isArchive = $mailboxes.IsArchive
                                #$isDeleted = $mailboxes.IsDeleted

                                foreach ($auser in $mailboxes) {
				                                $usermailbox = Get-VEXMailbox -Database $database -Name $auser.name
                                    $rmb = "$BackupFolder\$($auser.Email).pst"

				                                if ($usermailbox) {
                                        Export-VEXItem -Mailbox $usermailbox -To $rmb -Force | out-null
                                        [long]$exports = (Get-Item $rmb).length
                                        $exportsize = Format-Size($exports)
                                        if ($exportsize) { Write-Host "  $($exportsize)  " } else { Write-Host "" }
                                    }

                                }
                            }
                            else {
                                Write-Host "  No Mailbox found in $($database.Name)"
                            }
                        }
                        Get-VBOExchangeItemRestoreSession | Stop-VBOExchangeItemRestoreSession | out-null
                        Start-Sleep -s 4
                    }
                    else {
                        $backupStatus = "FAILED Exchange Export Session Did Not Start! "
                                    
                    }

                    if ($IsSharePoint -eq $true) {

                        CreateFolderIfNotExist "$BackupSharePoint" 
                                    
                        #SharePoint Restore
                        $tp = Test-Path -Path "$BackupSharePoint"
                        if ($tp -eq $True) {
                            Start-VBOSharePointItemRestoreSession -Job $job -LatestState | out-null
                            # Wait 4 secs to ensure its completed.
                            Start-Sleep -s 4
    
                            $SPsession = Get-VBOSharePointItemRestoreSession 
                            if ($SPsession.count -gt 0) {
                                $SPorganization = Get-VESPOrganization -Session $SPsession[$SPsession.count - 1]
                                if ($SPorganization) {
                                    Write-Host -NoNewLine " Processing Sharepoint Data Export Session.  "
                            
                                    #$site = Get-VESPSite -Organization $organization | out-null
                                    #$list = Get-VESPList -Organization $organization | out-null
                                    # Backup Style Library, Form Templates

                                    $doclib = Get-VESPDocumentLibrary -Organization $SPorganization
                                    if ($doclib) {
                                        foreach ($doc in $doclib) {
                                            $name = $doc.Name
                                            $icount = $doc.ItemsCount

                                            if ($icount -gt 0) {
                                                $tp = Test-Path -Path "$BackupSharePoint\$($name)"

                                                if ($tp -eq $False) {
                                                    mkdir "$BackupSharePoint\$($name)"  | out-null
                                                }

                                                $SPdocumentLibrary = Get-VESPDocumentLibrary -Organization $SPorganization -Name "$name"
                                                if ($SPdocumentLibrary) {
                                                    Save-VESPItem -DocumentLibrary $SPdocumentLibrary -Path "$($BackupSharePoint)\$($name)" -Force | out-null
                                                    [long]$spexports = (Get-Item "$($BackupSharePoint)\$($name)").length
                                                    $spexportsize = Format-Size($spexports)
                                                    if ($spexportsize) { 
                                                        Write-Host "  $($spexportsize)  " 
                                                    }
                                                    else { 
                                                        Write-Host "" 
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                        
                            }
                            Get-VBOSharePointItemRestoreSession  | Stop-VBOSharePointItemRestoreSession | out-null
                            Start-Sleep -s 4
                        } 
                    } # END of Sharepoint

                    if ($IsOneDrive -eq $true) {
                                
                        CreateFolderIfNotExist "$BackupOneDrive"

                        #OneDrive Restore
                        $tp = Test-Path -Path "$BackupOneDrive"
                        if ($tp -eq $True) {
        			                
                            Start-VEODRestoreSession -Job $job -LatestState | out-null
                            # Wait 4 secs to ensure its completed.
                            Start-Sleep -s 4
                            $ODsession = Get-VEODRestoreSession

                            if ($ODsession.count -gt 0) {
                                #Get Latest Session 
                                $users = Get-VEODUser -Session $ODsession[$ODsession.count - 1]
                                Write-Host " Processing OneDrive Data Export Session."
                                foreach ($oduser in $users) {
                                    $docs = Get-VEODDocument -User $oduser
                                    if ($docs) {
                                        Save-VEODDocument -User $oduser -Path "$BackupOneDrive\$($mailbox).zip" -AsZip | out-null
                                    }
                                }
                            }

                            Get-VEODRestoreSession | Stop-VEODRestoreSession | out-null
                            Start-Sleep -s 4
                        }
                    } # END of OneDrive
                              
                    RemoveVeeamJob "Success", "$mailbox"
                    RemoveVeeamJob "Warning", "$mailbox"          
              
                }
                else {
                    # Log the backup job did not complete. No Success.
                    $backupStatus = " - FAILED Veeam Error?"


                } # END OF IS Completed

            } # BACKUP warning, completed
        } # END OF $checkjob.LastStatus -ne "Running"

    } #END OF $startbackup -EQ $true
    
    if ($ArchiveFolder) {   
        # Copy the backup pst file to the archive server 
        #$restorefile = "$BackupFolder\$($auser.Email).pst"
        $checkcopied = "$($ArchiveFolder)\$($auser.Email).pst"

        $filecount = (Get-ChildItem -path "$($BackupFolder)\*.pst" | Measure-Object).count
        if ($filecount -gt 0) {
            Write-Host " Copying Files to Archive Server..."
            Copy-Item -Path "$BackupFolder\*.pst" -Destination "$ArchiveFolder\" -Recurse -Force  | out-null
            $tp = Test-Path -Path $BackupOneDrive
            if ($tp -eq $True) {
                Copy-Item -Path "$BackupOneDrive" -Destination "$ArchiveFolder\" -Recurse -Force  | out-null
            }
            $tp = Test-Path -Path $BackupSharePoint
            if ($tp -eq $True) {
                Copy-Item -Path "$BackupSharePoint" -Destination "$ArchiveFolder\" -Recurse -Force  | out-null
            }
                
            # Wait 1 secs to ensure its finished copying.
            Start-Sleep -s 1

            # Delete the backup if the file has been successfully copied to the Archive server
            $tp = Test-Path -Path $checkcopied
            if ($tp -eq $True) {

                Write-Host " Removing the localy restored files as they have been sucessfully copied to the archive server."
                Remove-Item "$BackupFolder\*.pst" -Force  | out-null
                $tp = Test-Path -Path $BackupOneDrive
                if ($tp -eq $True) {
                    Remove-Item "$BackupOneDrive" -Force -Recurse | out-null
                }
                $tp = Test-Path -Path $BackupSharePoint
                if ($tp -eq $True) {
                    Remove-Item "$BackupSharePoint" -Force -Recurse | out-null
                }
                Start-Sleep -s 4

            } 
            else {
                #File Did NOT Copy

                #Log that the restored mailbox backup file did not get copied to the archiver server??
                #$checkcopied missing
                $backupStatus = " - FAILED ** Could Not Copy PST Files to Archive Server!"

            } #File Copied
                 
               
        } # FileCount was 0
        else {
            #Log that the restored mailbox pst file did not get created
            #$restorefile missing
            $backupStatus = " - FAILED ** A Restore PST File was not created!"
            #Add the mailbox array number to the recheck array
            $recheck += $recheckid
                        
        } #File Count
    }
    else {
        # $checkjob.LastStatus 
    }# END OF Copy files to Archive Folder


    RemoveVeeamJob "Stopped", "$mailbox"
    RemoveVeeamJob "Failed", "$mailbox"

    write-host  " Backup Finished. $backupStatus"
    $a += 1

    Write-Host ""
    Write-Host ""
    Start-Sleep -s 2
    $backupStatus = ""

}

Disconnect-VBOServer | out-null
Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore -ErrorAction SilentlyContinue

write-host   COMPLETED
