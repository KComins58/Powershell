$Domain = "@test.local" #Domain that AD is hosted on
$fileserver = "TestDC\School" #Server name
$emaildomain = "@s.SchoolSchool.com" #Email suffix @example.com
$OUExtension = "OU=AUTOMATED,OU=Students,OU=users,OU=managed,OU=School,DC=test,DC=local" #Sets OU, DC of AD
$sisexportfilestaff = "C:\Users\Administrator\Desktop\Single Extract.txt" #Textfile with staff information that needs to be imported
$maxFiles = 13 #max number of log files before oldest deletes first - days in our case
$UserPerm = $Domain.Substring(1) #permissions are the domain without the @. If they are different names, change accordingly
$UnknownOU = "OU=Withdrawn,OU=Students,OU=users,OU=managed,OU=School,DC=test,DC=local"
$UnknownFolder = "\\$fileserver\student$\Withdrawn"
$logfilepath = "\\TestDC\Student Changelog\Daily" #The folder storing the changelog textfiles  WARNING WILL DELETE ALL BUT 13 files in this location. MAKE SEPARATE LOG LOCATION.

$date = Get-Date -Format "yyyy-MM-dd HH-mm" #Current date/time in the format that textfiles will be named in
$files = Get-ChildItem -Path $logfilepath | Where-Object { !$_.PSIsContainer } | Sort-Object CreationTime #Get the textfile names within the logfile folder and order by creationtime

if ($files.Count -gt $maxFiles) { #Checks if there are more txt files in the changelog folder than is allowed
    $deleteCount = $files.Count - $maxFiles #Calculates how many to delete based on number existing - how many are allowed
    
    for ($i = 0; $i -lt $deleteCount; $i++) { #For loop from 0 -> How many to delete
        $oldestFile = $files[$i] #Oldest file is the 1 that is in the lowest index position
        Write-Host "`nDeleted: $($oldestFile.FullName)`n" #Write to log which files were deleted
        Remove-Item -Path $oldestFile.FullName #Remove the file
    }

}

$logfilepath = "$logfilepath\$date.txt"

try { #Incase transcript wasn't stopped last time
    Stop-Transcript
}

catch { #Do not display error code saying transcript doesn't exist
}

Start-Transcript -Path $logfilepath #Start noting the changes that occur, they are stored during write-host

Import-Module ActiveDirectory # Import the Active Directory functions

if ($runningInstances) { #If running instances
    $runningInstances | Stop-Process -Force #stop them so no conflicting scripts are ran
}

$month = Get-Date -Format "MM" 
$dateyear = Get-Date -Format "yyyy"

function get-year ($currentgrade) {
    if ($month -ge '06') {
        $year = [int]$dateyear + 1
    } 
    else {
        $year = [int]$dateyear
    }

    $result = $year  # Initialize the result variable with the given year

    if ($currentgrade -eq -2) {
        $currentgrade = -1
    }

    $result += (12 - $currentgrade)  # Add the remaining years based on the current grade
    return [string]$result  # Return the calculated year
}

function UniqueTest($sAMAccountName, $givenName, $sn, $employeeid,$gradyear) { #Function that tests if sAMAccountName is unique, as it gets used in the UPN
    $i = 0 #Set counter
    $existinguser = (Get-ADUser -Filter "employeeid -eq '$employeeid'") #Get existing users sAMAccountName based off employeeid
    
    while ((Get-ADUser -Filter "sAMAccountName -eq '$sAMAccountName'") -and ($existinguser.sAMAccountName -ne $sAMAccountName)) { #Repeat until the sAMAccountName is unique or remains the same as it currently is / the and for is if you are updating a user
        $i++ #Increase counter
        $sAMAccountName = ($gradyear+($givenName.Substring(0, $i) + $sn) -replace " ", "" -replace "\.\.", "." -replace "'", "" -replace "-", "" -replace "ó", "o" -replace ",", "" -replace "í", "i" -replace "`"","").ToLower() #Create a new sAMAccountName with an additional initial
    }

    return $sAMAccountName #Return the function value to where it was called
}

function AddToGroups($employeeID,$gradyear,$schoollvl){ #Add a user to the appropriate email groups
    $existingUser = Get-ADUser -Filter "EmployeeID -eq '$employeeID'" -Properties * #Get the employee that was just created/updated
    Get-ADPrincipalGroupMembership $existingUser | Where-Object { $_.Name -ne "Domain Users" -and $_.Name -ne "Journalism Yearbook"} | ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $existingUser -Confirm:$false }
    Add-ADGroupMember -Identity "guest_wireless" -Members $existingUser #Add all to guest_wireless
    
    if ($existingUser.Enabled -eq $false) {
        Set-ADUser -Identity $existingUser.distinguishedname -HomePhone $null
    
    } else {
        Add-ADGroupMember -Identity "$gradyear Students" -Members $existingUser #Add all to guest_wireless
        Add-ADGroupMember -Identity "$schoollvl" -Members $existingUser #Add all to guest_wireless
    }

}

# OU=2024,OU=HS Students,   OU=Students,OU=users,OU=managed,DC=test,DC=local
function UpdateADUser($sAMAccountName,$name,$otherAttributes,$OUgradyear,$employeeID,$EnabledAccount,$mail,$givenName,$sn,$displayname,$gradey,$lunchpin,$description,$userPrincipalName){
   
    if ($sAMAccountName.Length -ge 20) {
        $sAMAccountName = $sAMAccountName.Substring(0,20)
    }

    $existingUser = Get-ADUser -Filter "EmployeeID -eq '$employeeID'" -Properties * #Get matching user data according to employeeid

    $testpath = "CN="+$existinguser.Name+","+$OUgradyear+$OUExtension #Change path in OU to new user name
    PathTest $employeeID

    if ($EnabledAccount -eq $false) {
        $path = $UnknownOU 
        $newhomedirectory = $UnknownFolder+"\" + $sAMAccountName  #The example below assumes student home folders exist in a \\TestDC\student$\username structure
    } 

    else {
        $path = $OUgradyear+$OUExtension #1:OU=2034,OU=MS Students, OU=Students,OU=users,DC=managed,DC=local
        $newhomedirectory = "\\$fileserver\student$\$sAMAccountName" #Where the new homedirectory will be located -either changed based on name change or location change
    }

    if ("CN=$name,$path" -ne $existinguser) {
        
        if ($existingUser.HomeDirectory -ne $newhomedirectory){
            Set-ADUser -Identity $existingUser -Add @{proxyAddresses = $existingUser.mail} #Set proxy addresses so that a changed user will still recieve their old emails  
            Move-Item -Path $existingUser.HomeDirectory -Destination $newhomedirectory -Force #Move homedirectory folder to newhomedirectory folder
        }

        $oldname = $existingUser.Name #Need to save the name previously stored as we move grade before we change name so causes an issue if name/last name + grade changes if we don't

        Move-ADObject -Identity $existinguser -TargetPath $path #Move OU in AD to new OU position
        Rename-ADObject -Identity "CN=$oldname,$path" -NewName $name #Rename OU in AD
           
        Set-ADUser -Identity "CN=$name,$path" -UserPrincipalName $userPrincipalName -sAMAccountName $sAMAccountName -Enabled $EnabledAccount -EmailAddress $mail -givenName $givenName -Surname $sn -DisplayName $displayname -Office $gradey -employeenumber "School$lunchpin" -description $description -HomeDirectory $newhomedirectory -HomeDrive "H:" #create user using $sAMAccountName and set attributes and assign it to the $user variable

        write-host ("$name, $sAMAccountName, $mail" ) #For log taking
    }

}

function AddADUser($sAMAccountName,$name,$otherAttributes,$password,$OUgradyear,$employeeID,$EnabledAccount){
    
    if ($sAMAccountName.Length -ge 20) {
            $sAMAccountName = $sAMAccountName.Substring(0,20)
        }

    if ($EnabledAccount -eq $false) {
        $path = $UnknownOU 
        $homepath = $UnknownFolder+"\" + $sAMAccountName  #The example below assumes student home folders exist in a \\TestDC\student$\username structure
        New-ADUser -sAMAccountName $sAMAccountName -Name $name -Path $path -Enabled $false -CannotChangePassword $true -PasswordNeverExpires $true -AccountPassword $password -OtherAttributes $otherAttributes -HomeDirectory $homepath -HomeDrive "H:" #create user using $sAMAccountName and set attributes and assign it to the $user variable
    
    } else {
        $path = $OUgradyear+$OUExtension #1:OU=2034,OU=Students,OU=Test,DC=test,DC=local 2:2034ccheck 3:CHECK01 CHECK
        $homepath = "\\"  + $fileserver + "\student$\" + $sAMAccountName  #The example below assumes student home folders exist in a \\TestDC\student$\username structure
        New-ADUser -sAMAccountName $sAMAccountName -Name $name -Path $path -Enabled $true -CannotChangePassword $true -PasswordNeverExpires $true -AccountPassword $password -OtherAttributes $otherAttributes -HomeDirectory $homepath -HomeDrive "H:" #create user using $sAMAccountName and set attributes and assign it to the $user variable
    } 
     
    if ((Test-Path ($homepath)) -ne $true){ #If path doesn't exist already
		New-Item -ItemType directory -Path $homepath #creates a new directory at the path specified
		$acl = Get-Acl $homepath #retrieves the access control list 
		$permission = "$UserPerm\$sAMAccountName","Modify","ContainerInherit,ObjectInherit","None","Allow" #sets the $permission variable to an array
		$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission #creates a new file system access rule object using $permission
		$acl.SetAccessRule($accessRule) #adds the newly created access rule to the access control list 
		$acl | Set-Acl $homepath #sets the updated access control list
	}
    
    write-host ("$name, $sAMAccountName ,$mail" )
}

function PathTest($employeeid){
    
    $existingUser = Get-ADUser -Filter "EmployeeID -eq '$employeeID'" -Properties * #Get matching user data according to employeeid
    $existingPath = (Get-ADUser -Identity $existingUser.SamAccountName -Properties HomeDirectory).HomeDirectory #Get the existing user's home directory path

    $existingSam = $existingUser.sAMAccountName
    $homepath = "\\$fileserver\student$\$existingSam"
    
    if (($existingPath -eq $null) -and ((Test-Path ($homepath)) -eq $true)) {
        Set-AdUser -Identity $existingUser -HomeDirectory $homepath -HomeDrive "U:" 
   
    } elseif (($existingPath -eq $null) -and ((Test-Path ($homepath)) -ne $true)) {
        $existingPath = $homepath
        write-host $homepath
    
        New-Item -ItemType directory -Path $homepath #creates a new directory at the path specified
	    $acl = Get-Acl $homepath #retrieves the access control list 
	    $permission = "$UserPerm\$existingSam","Modify","ContainerInherit,ObjectInherit","None","Allow" #sets the $permission variable to an array
	    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission #creates a new file system access rule object using $permission
	    $acl.SetAccessRule($accessRule) #adds the newly created access rule to the access control list 
	    $acl | Set-Acl $homepath #sets the updated access control list
        Set-AdUser -Identity $existingUser -HomeDirectory $homepath -HomeDrive "U:"
    
    } elseif (($existingPath -ne $null) -and ((Test-Path ($existingPath)) -ne $true)) {
        $homepath = $existingUser.HomeDirectory
        $existingPath = $homepath
        write-host $homepath
    
        New-Item -ItemType directory -Path $homepath #creates a new directory at the path specified
	    $acl = Get-Acl $homepath #retrieves the access control list 
	    $permission = "$UserPerm\$existingSam","Modify","ContainerInherit,ObjectInherit","None","Allow" #sets the $permission variable to an array
	    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission #creates a new file system access rule object using $permission
	    $acl.SetAccessRule($accessRule) #adds the newly created access rule to the access control list 
	    $acl | Set-Acl $homepath #sets the updated access control list
        Set-AdUser -Identity $existingUser -HomeDirectory $homepath -HomeDrive "U:"
    } 
}

$grade = @{}
$orgunits = @{}
$schoollevel = @{}

for ($i = -1; $i -le 12; $i++) {
    $currentGrade = $i.ToString()
    $gradeschool = [int]$currentGrade
    
    if ($gradeschool -ge 9) {
        $school = "HS Students"
    } 

    elseif ($gradeschool -ge 5) {
        $school = "MS Students"
    } 

    else {
        $school = "ES Students"
    } 
    
    $year = get-year $currentGrade
    $grade[$currentGrade] = $year
    $schoollevel[$currentGrade] = $school
    $orgunits[$currentGrade] = "OU=$year,OU=$school,"
}

$sisfile = Get-Content -Path $sisexportfilestaff | Select-Object -Skip 1 | ConvertFrom-Csv -Delimiter "," -Header "givenName","sn","lunchpin","grade","studentid","status","aup","gsuite"
foreach ($sisline in $sisfile) { #Read from textfile line by line
 
    $lunchpin = $sisline.lunchpin #Position

    if ($lunchpin.Length -ge 5) {
        $givenName = $sisline.givenName #Set given name
        $sn = $sisline.sn #Set username
        $gradey = $sisline.grade
        $gradyear = $grade.Get_Item($gradey)
        $OUgradyear = $orgunits.Get_Item($gradey)
        $schoollvl = $schoollevel.Get_Item($gradey)
        $employeeid = $sisline.studentid #EmployeeID
        $status = $sisline.status
        #$aup = $sisline.aup
        #$gsuite = $sisline.gsuite

        #if (($status -ne '0') -or ($aup -ne 'Yes') -or ($gsuite -ne 'Yes')) {
        if ($status -ne '0') {
            $EnabledAccount = $false   
        
        } else {
            $EnabledAccount = $true
        }
     
        $password = ConvertTo-SecureString -AsPlainText "School$lunchpin" -Force #Set the password to a secure string. Original password for staff is pre-set and changed on first logon
	    $description = "Class of $gradyear Student User" #Set description which tells us gradyear

        $sAMAccountName = UniqueTest (($gradyear+$givenName[0] + $sn) -replace " ", "" -replace "\.\.", "." -replace "'", "" -replace "-", "" -replace "ó", "o" -replace ",", "" -replace "í", "i" -replace "`"","").ToLower() $givenName $sn $employeeid $gradyear #Remove unnecessary characters/change to common ones then lower into uniform format
        $userPrincipalName = "$sAMAccountName$Domain" #Set User principle name 
        $mail = "$sAMAccountName$emaildomain" #Set the mail attribute for the account (if desired, usually helpful if you're synchronizing to Google Apps/Office 365)
        $displayname = "$givenName $sn" #Set display name
        $name = ($displayname -replace "\.\.", "." -replace "'", "" -replace "-", "" -replace "ó", "o" -replace ",", "" -replace "í", "i" -replace "`"","").ToUpper()
        $otherAttributes = @{'userPrincipalName' = "$userPrincipalName"; 'mail' = "$mail"; 'givenName' = "$givenName"; 'sn' = "$sn"; 'DisplayName' = "$displayname"; 'physicalDeliveryOfficeName' = "$gradey"; 'employeenumber' = "School$lunchpin"; 'employeeID' = "$employeeID"; 'description' = "$description"}
        $otherAttributes.description = [string]$otherAttributes.description #Needs to be a string for AD
             
        if ((Get-ADUser -Filter "EmployeeID -eq '$employeeID'") -ne $null) { #If new user - add
            UpdateADUser $sAMAccountName $name $otherAttributes $OUgradyear $employeeID $EnabledAccount $mail $givenName $sn $displayname $gradey $lunchpin $description $userPrincipalName
        } 
    
        else { #if current user - update
            ADDADUser $sAMAccountName $name $otherAttributes $password $OUgradyear $employeeID $EnabledAccount    
        }

        AddToGroups $employeeID $gradyear $schoollvl #Add user to approriate groups   
    }   
}

$NotPresent = $sisfile.studentid
$ADUsers = Get-ADUser -Filter * -SearchBase $OUExtension -Properties HomeDirectory, EmployeeID, SamAccountName #Get the list of AD users

foreach ($ADUser in $ADUsers) { #Iterate through each AD user
    $SamAccountName = $ADUser.SamAccountName
    $employeeID = $ADUser.EmployeeID #Set employeeID
    $HomeDirectory = $ADUser.HomeDirectory #Set Homedirectory
    $DistinguishedName = $ADUser.DistinguishedName
    $gradyear = ((Split-Path -Path $HomeDirectory -Parent).Split("\"))[-1]

    if ($employeeID -notin $NotPresent -and $HomeDirectory -notlike '*Withdrawn*' -and $DistinguishedName -like '*AUTOMATED*') {
        Move-Item -Path $HomeDirectory -Destination "$UnknownFolder\$SamAccountName" -Force
        Set-ADUser -Identity $DistinguishedName -HomeDirectory ("$UnknownFolder\$SamAccountName") -SamAccountName $SamAccountName -Enabled $false #Change properties in AD
        Move-ADObject -Identity $DistinguishedName -TargetPath $UnknownOU #Move AD t to Withdrawn OU
        Write-Host "Not Found in sisfile`nHome directory: $HomeDirectory -> "$UnknownFolder\$SamAccountName"`nAD: $DistinguishedName -> $UnknownOU`n" #Write-Host adds to changelog
    }

}

Stop-Transcript #End log taking
# Remove the header lines from the transcript file
(Get-Content -Path $LogFilePath | Select-Object -Skip 18) | Set-Content -Path $LogFilePath -Force
