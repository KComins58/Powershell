$Domain = "@test.local" #Domain that AD is hosted on
$fileserver = "TestDC" #Server name
$emaildomain = "@email.com" #Email suffix @example.com
$OUExtension = "OU=users,OU=managed,DC=test,DC=local" #Sets OU, DC of AD
$sisexportfilestaff = "C:\Users\Administrator\Desktop\staffexport.csv" #Textfile with staff information that needs to be imported
$webUrl = "GoogleShhets.html"
$scriptName = $MyInvocation.MyCommand.Name #retrieves the name of the currently running PowerShell script
$runningInstances = Get-Process | Where-Object { $_.ProcessName -eq "powershell" -and $_.MainModule.FileName -like "*$scriptName" } #retrieve a list of running processes, checks if the process name is "powershell, checks if the process's main module filename matches the current script's name.
$maxFiles = 13 #max number of log files before oldest deletes first - days in our case
$UserPerm = $Domain.Substring(1) #permissions are the domain without the @. If they are different names, change accordingly
$UnknownOU = "OU=Unknown,OU=users,OU=managed,DC=test,DC=local"
$UnknownFolder = "\\TestDC\teacher$\Unknown"

$date = Get-Date -Format "yyyy-MM-dd HH-mm" #Current date/time in the format that textfiles will be named in
$logfilepath = "\\TestDC\Changelog\Daily" #The folder storing the changelog textfiles  WARNING WILL DELETE ALL BUT 13 files in this location. MAKE SEPARATE LOG LOCATION.
$files = Get-ChildItem -Path $logfilepath | Where-Object { !$_.PSIsContainer } | Sort-Object CreationTime #Get the textfile names within the logfile folder and order by creationtime

try { #Incase transcript wasn't stopped last time
    Stop-Transcript
}

catch { #Do not display error code saying transcript doesn't exist
}

if ($files.Count -gt $maxFiles) { #Checks if there are more txt files in the changelog folder than is allowed
    $deleteCount = $files.Count - $maxFiles #Calculates how many to delete based on number existing - how many are allowed

    for ($i = 0; $i -lt $deleteCount; $i++) { #For loop from 0 -> How many to delete
        $oldestFile = $files[$i] #Oldest file is the 1 that is in the lowest index position
        Remove-Item -Path $oldestFile.FullName #Remove the file
    }

}

$logfilepath = "$logfilepath\$date.txt"
Start-Transcript -Path $logfilepath #Start noting the changes that occur, they are stored during write-host

Import-Module ActiveDirectory # Import the Active Directory functions

if ($runningInstances) { #If running instances
    $runningInstances | Stop-Process -Force #stop them so no conflicting scripts are ran
}

function UniqueTest($sAMAccountName, $givenName, $sn, $employeeid) { #Function that tests if sAMAccountName is unique, as it gets used in the UPN
    $i = 0 #Set counter
    $existinguser = (Get-ADUser -Filter "employeeid -eq '$employeeid'") #Get existing users sAMAccountName based off employeeid
    
    while ((Get-ADUser -Filter "sAMAccountName -eq '$sAMAccountName'") -and ($existinguser.sAMAccountName -ne $sAMAccountName)) { #Repeat until the sAMAccountName is unique or remains the same as it currently is / the and for is if you are updating a user
        $i++ #Increase counter
        $sAMAccountName = (($givenName.Substring(0, $i) + $sn) -replace " ", "" -replace "\.\.", "." -replace "'", "" -replace "-", "" -replace "ó", "o" -replace ",", "" -replace "í", "i").ToLower() #Create a new sAMAccountName with an additional initial
    }

    return $sAMAccountName #Return the function value to where it was called
}

function HomePath($position) { #get the correct folder/OU names
    
    switch ($position.ToLower())
    {
        "teacher" {return "Teacher"} #All teachers
        "instructional coaches" {return "Teacher"} #All instructional coaches
        "counselor" {return "Office"} #All counselor
        "custodial" {return "Support"} #All custodial
        "kitchen" {return "Support"} #All kitchen
        "maintenance" {return "Support"} #All maintenance
        "nurse" {return "Office"} #All nurse
        "secretary" {return "Office"} #All secretary
        "bus driver" {return "Support"} #All bus driver
        "principal" {return "Office"} #Principle
        "asst principal" {return "Office"} #asst principal

        default {return "Unknown"} #Otherwise causes an error if they have a position that hasn't been added
    }

}

function AddToGroups($employeeID,$position,$office,$accesslvl,$EnabledAccount){ #Add a user to the appropriate email groups
    $existingUser = Get-ADUser -Filter "EmployeeID -eq '$employeeID'" -Properties * #Get the employee that was just created/updated
    Get-ADPrincipalGroupMembership $existingUser | Where-Object { $_.Name -ne "Domain Users" -and $_.Name -ne "911notifier" -and $_.Name -ne "Erate" -and $_.Name -ne "FMP" -and $_.Name -ne "Large Board of Education" -and $_.Name -ne "School Admin Team" -and
    $_.Name -ne "School Teachers" -and $_.Name -ne "School Special Services" -and $_.Name -ne "Practical Nursing"} | ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $existingUser -Confirm:$false }
    #office is building, position is admin/teacher/etc
    
    Add-ADGroupMember -Identity "Large Public Schools" -Members $existingUser #Add all to Large Public schools group
    Add-ADGroupMember -Identity "guest_wireless" -Members $existingUser #Add all to guest_wireless
    $officeCode = $office.ToUpper()
    
    $storage = HomePath $position

    if ($accesslvl -like "*#Add") {
        $accesslvl = $accesslvl.TrimEnd("#Add")
    }

    switch ($accesslvl) {
        "District-All_Access" {Add-ADGroupMember -Identity "District-All_Access" -Members $existingUser}
        "ACCESS-HS-Alltime" {Add-ADGroupMember -Identity "ACCESS-HS-Alltime" -Members $existingUser}
        "ACCESS-HS-Limited" {Add-ADGroupMember -Identity "ACCESS-HS-Limited" -Members $existingUser}
        "ACCESS-MS-Alltime" {Add-ADGroupMember -Identity "ACCESS-MS-Alltime" -Members $existingUser}
        "ACCESS-MS-Limited" {Add-ADGroupMember -Identity "ACCESS-MS-Limited" -Members $existingUser}
        "ACCESS-SC-Alltime" {Add-ADGroupMember -Identity "ACCESS-SC-Alltime" -Members $existingUser}
        "ACCESS-SC-Limited" {Add-ADGroupMember -Identity "ACCESS-SC-Limited" -Members $existingUser}
        "ACCESS-BF-Alltime" {Add-ADGroupMember -Identity "ACCESS-BF-Alltime" -Members $existingUser}
        "ACCESS-BF-Limited" {Add-ADGroupMember -Identity "ACCESS-BF-Limited" -Members $existingUser}
        "ACCESS-SB-Alltime" {Add-ADGroupMember -Identity "ACCESS-SB-Alltime" -Members $existingUser}
        "ACCESS-SB-Limited" {Add-ADGroupMember -Identity "ACCESS-SB-Limited" -Members $existingUser}

        default {return " "}
    }

    switch ($officeCode.Trim()) {
        "BE" {Add-ADGroupMember -Identity "School 1" -Members $existingUser}
        "EW" {Add-ADGroupMember -Identity "School 2" -Members $existingUser}
        "SB" {Add-ADGroupMember -Identity "School 3" -Members $existingUser}
    }

    switch ($position.ToLower()) #tolower so that it isn't case sensitive
    {
        "teacher" {Add-ADGroupMember -Identity "Classroom Teachers" -Members $existingUser} #All teachers
        "instructional coaches" {Add-ADGroupMember -Identity "Instructional Coaches" -Members $existingUser} #All instructional coaches
        "counselor" {Add-ADGroupMember -Identity "School Counselors" -Members $existingUser} #All counselor
        "custodial" {Add-ADGroupMember -Identity "School Custodians" -Members $existingUser} #All custodial
        "kitchen" {Add-ADGroupMember -Identity "School Food Service" -Members $existingUser} #All kitchen
        "maintenance" {Add-ADGroupMember -Identity "School Maintenance" -Members $existingUser} #All maintenance
        "nurse" {Add-ADGroupMember -Identity "School Nurses" -Members $existingUser} #All nurse
        "secretary" {Add-ADGroupMember -Identity "School Secretaries" -Members $existingUser} #All secretary
        "bus driver" {Add-ADGroupMember -Identity "School Transportation Department" -Members $existingUser} #All bus driver
    }

    if ($storage -eq 'Teacher') {
        $suffix = "_Teachers"
        $allpath = "ALL_TEACHERS"
    } 
    
    if ($storage -eq 'Office') {
        $suffix = "_Office"
        $allpath = "ALL_OFFICE"
    }

    $fullpath = "$officeCode$suffix"

    if (($storage -eq 'Office') -or ($storage -eq 'Teacher')) {

        Add-ADGroupMember -Identity $fullpath -Members $existingUser
        Add-ADGroupMember -Identity $allpath -Members $existingUser

    }

    if ($existingUser.Enabled -eq $false) {
            Get-ADPrincipalGroupMembership $existingUser.distinguishedname | Where-Object { $_.Name -ne "Domain Users" } | ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $existingUser -Confirm:$false }
            Set-ADUser -Identity $existingUser.distinguishedname -HomePhone $null
        }

}

function UpdateADUser($employeeID,$office,$sAMAccountName,$name,$givenname,$mail,$sn,$displayname,$newhomedirectory,$position,$userPrincipalName,$EnabledAccount,$accesscard,$accesslvl){
    $existingUser = Get-ADUser -Filter "EmployeeID -eq '$employeeID'" -Properties * #Get matching user data according to employeeid
    $storage = HomePath $position #Get the folder/ou to put the user in
    $offices = $office.ToUpper().Split(',') -replace " ", "" #If a staff member goes between multiple buildings, separate by , #toupper so that it isn't case sensitive
    $onlyoffice = $offices[0]
    $employeeNum = "School$employeeID"
    
    if ($storage -eq "Support") {
        $onlyoffice = $position
    }

    $path = "OU="+$onlyoffice+",OU="+$storage+","+$OUExtension #1:OU=2034,OU=Students,OU=Test,DC=test,DC=local 2:2034ccheck 3:CHECK01 CHECK
    $testpath = "CN="+$existinguser.Name+",OU="+$onlyoffice+",OU=$storage,$OUExtension" #Change path in OU to new user name
    $newhomedirectory = "\\$fileserver\$storage$\$sAMAccountName" #Where the new homedirectory will be located -either changed based on name change or location change

    if ("CN=$name,$path" -ne $existinguser) {
        
        if ($existingUser.HomeDirectory -ne $newhomedirectory)
        {
            Set-ADUser -Identity $existingUser -Add @{proxyAddresses = $existingUser.mail } #Set proxy addresses so that a changed user will still recieve their old emails   
            Move-Item -Path $existingUser.HomeDirectory -Destination $newhomedirectory -Force #Move homedirectory folder to newhomedirectory folder
        }

        Move-ADObject -Identity $existinguser -TargetPath $path #Move OU in AD to new OU position
        Rename-ADObject -Identity $testpath -NewName $name #Rename OU in AD
        
        if ($EnabledAccount -eq "false") {
            Set-ADUser -Identity "CN=$name,$path" -userPrincipalName $userPrincipalName -givenName $givenName -EmailAddress $mail -Surname $sn -SamAccountName $sAMAccountName -DisplayName $displayname -HomeDirectory $newhomedirectory -Description $position -Office $office -Enabled $false -HomePhone $accesscard -EmployeeNumber $employeeNum #Set all the attributes for th user
        } else {
            Set-ADUser -Identity "CN=$name,$path" -userPrincipalName $userPrincipalName -givenName $givenName -EmailAddress $mail -Surname $sn -SamAccountName $sAMAccountName -DisplayName $displayname -HomeDirectory $newhomedirectory -Description $position -Office $office -Enabled $true -HomePhone $accesscard -EmployeeNumber $employeeNum #Set all the attributes for th user
        }

        write-host ("$name, $sAMAccountName ,$mail" ) #For log taking
    }

}

function ChangeEntry($office){
     switch ($office) {
            "School 1" {return "S1"}
            "School 2" {return "S2"}
            "School 3" {return "S3"}
        }
}
function AddADUser($sAMAccountName,$name,$otherAttributes,$position,$password,$office,$EnabledAccount,$employeeID){
    $storage = HomePath $position #Get the folder/ou to put the user in
    $onlyoffice = $office.ToUpper()
    $employeeNum = "School$employeeID"
    
    if ($storage -eq "Support") {
        $onlyoffice = $position
    }

    if ($EnabledAccount -eq "false") {$EnabledA = $false} else {$EnabledA = $true}
    
    $path = "OU="+$onlyoffice+",OU="+$storage+","+$OUExtension #1:OU=2034,OU=Students,OU=Test,DC=test,DC=local 2:2034ccheck 3:CHECK01 CHECK
    $homepath = "\\"  + $fileserver + "\"+ $storage + "$\" + $sAMAccountName  #The example below assumes student home folders exist in a \\TestDC\student$\username structure
    
    if ($EnabledAccount -eq "false") {
        New-ADUser -sAMAccountName $sAMAccountName -Name $name -Path $path -Enabled $false -CannotChangePassword $false -ChangePasswordAtLogon $true -AccountPassword $password -OtherAttributes $otherAttributes -HomeDirectory $homepath -HomeDrive "H:" -EmployeeNumber $employeeNum #create user using $sAMAccountName and set attributes and assign it to the $user variable
    } else {
        New-ADUser -sAMAccountName $sAMAccountName -Name $name -Path $path -Enabled $true -CannotChangePassword $false -ChangePasswordAtLogon $true -AccountPassword $password -OtherAttributes $otherAttributes -HomeDirectory $homepath -HomeDrive "H:" -EmployeeNumber $employeeNum #create user using $sAMAccountName and set attributes and assign it to the $user variable
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

$response = Invoke-WebRequest -Uri $weburl # Get the input from the weburl
$doc = $response.ParsedHtml # Parse the HTML content
$div = $doc.getElementById("0") # Assuming "0" is the ID of the target div

if ($div) {
    $table = $div.getElementsByTagName("table") | Select-Object -First 1 # Read the table from weburl within the specified div
    $rows = $table.getElementsByTagName("tr") # Read the rows from the table within the div
    $extractedInfo = @() # Create an array to store the extracted information

    # Loop through the rows within the div, skipping the first row
    foreach ($row in $rows | Select-Object -Skip 2) {
        $columns = $row.getElementsByTagName("td") | Select-Object -ExpandProperty innerText
    
        if ($columns) {
            $info = $columns[0..7] -join "`t" # create lines with tabs separating info. Change number to # of columns - 1
            $extractedInfo += $info
        }
    } 
} else {
    Write-Host "No div with ID '0' found."
}

$extractedInfo | Out-File -FilePath $sisexportfilestaff # Save the extracted information to a text file
$sisfile = Import-Csv -delimiter "`t" -Path $sisexportfilestaff -header "givenName","sn","position","office","employeeid","accesscard","AccessLvl","EnabledAccount" #Read from the saved textfile from the online csv file

foreach ($sisline in $sisfile) { #Read from textfile line by line

    $givenName = $sisline.givenName #Set given name
    $sn = $sisline.sn #Set username
    $position = $sisline.position #Position
    $office = ChangeEntry ($sisline.office) #Building they work in
    $employeeid = $sisline.employeeid #EmployeeID
    $password = ConvertTo-SecureString -AsPlainText "School$employeeid" -Force #Set the password to a secure string. Original password for staff is pre-set and changed on first logon
    $accesscard = $sisline.accesscard #accesscard
    $sAMAccountName = UniqueTest (($givenName[0] + $sn) -replace " ", "" -replace "\.\.", "." -replace "'", "" -replace "-", "" -replace "ó", "o" -replace ",", "" -replace "í", "i" ).ToLower() $givenName $sn $employeeid #Remove unnecessary characters/change to common ones then lower into uniform format
    $userPrincipalName = "$sAMAccountName$Domain" #Set User principle name 
    $mail = "$sAMAccountName$emaildomain" #Set the mail attribute for the account (if desired, usually helpful if you're synchronizing to Google Apps/Office 365)
    $displayname = "$givenName $sn" #Set display name
    $name = ($displayname -replace "\.\.", "." -replace "'", "" -replace "-", "" -replace "ó", "o" -replace ",", "" -replace "í", "i").ToUpper()
    $accesslvl = $sisline.AccessLvl
    $EnabledAccount = ($sisline.EnabledAccount).ToLower()
    $otherAttributes = @{'userPrincipalName' = "$userPrincipalName"; 'mail' = "$mail"; 'givenName' = "$givenName"; 'sn' = "$sn"; 'DisplayName' = "$displayname"; 'employeeID' = "$employeeID"; 'physicalDeliveryOfficeName' = "$office"; 'description' = "$position"; 'HomePhone' = $accesscard}
    $otherAttributes.description = [string]$otherAttributes.description #Needs to be a string for AD
                
    if ((Get-ADUser -Filter "EmployeeID -eq '$employeeID'") -eq $null) { #If new user - add
        ADDADUser $sAMAccountName $name $otherAttributes $position $password $office $EnabledAccount $employeeID
    } else { #if current user - update
        UpdateADUser $employeeID $office $sAMAccountName $name $givenname $mail $sn $displayname $newhomedirectory $position $userPrincipalName $EnabledAccount $accesscard
    }
        AddToGroups $employeeID $position $office $accesslvl $EnabledAccount #Add user to approriate groups   
  
}

Stop-Transcript #End log taking
# Remove the header lines from the transcript file
(Get-Content -Path $LogFilePath | Select-Object -Skip 18) | Set-Content -Path $LogFilePath -Force
