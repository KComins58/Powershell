$Domain = "@test.local" #Domain that AD is hosted on
$fileserver = "TestDC\School" #Server name
$emaildomain = "@School.k12.mo.us" #Email suffix @example.com
$OUExtension = "OU=Users,OU=Managed,OU=School,DC=test,DC=local" #Sets OU, DC of AD
$sisexportfilestaff = "C:\Users\Administrator\Desktop\staffexport.csv" #Textfile with staff information that needs to be imported
$webUrl = "GoogleSheets.html"
$scriptName = $MyInvocation.MyCommand.Name #retrieves the name of the currently running PowerShell script
$runningInstances = Get-Process | Where-Object { $_.ProcessName -eq "powershell" -and $_.MainModule.FileName -like "*$scriptName" } #retrieve a list of running processes, checks if the process name is "powershell, checks if the process's main module filename matches the current script's name.
$maxFiles = 13 #max number of log files before oldest deletes first - days in our case
$UserPerm = $Domain.Substring(1) #permissions are the domain without the @. If they are different names, change accordingly
$UnknownOU = "OU=Disabled Acct,OU=Users,OU=Managed,OU=School,DC=test,DC=local"
$UnknownFolder = "\\$fileserver\teacher$\Unknown"

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
        "Teachers" {return "Teachers"} #All teachers
        "Maintenance" {return "Support"} #All maintenance
        "Office" {return "Office"} #All office

        default {return "Unknown"} #Otherwise causes an error if they have a position that hasn't been added
    }

}

function AddToGroups($employeeID,$position,$EnabledAccount){ #Add a user to the appropriate email groups
    $existingUser = Get-ADUser -Filter "EmployeeID -eq '$employeeID'" -Properties * #Get the employee that was just created/updated
    Get-ADPrincipalGroupMembership $existingUser | Where-Object { $_.Name -ne "Domain Users"} | ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $existingUser -Confirm:$false }
    #office is building, position is admin/teacher/etc
    
    Add-ADGroupMember -Identity "guest_wireless" -Members $existingUser #Add all to guest_wireless
    
    $storage = HomePath $position

    switch ($position.ToLower()) #tolower so that it isn't case sensitive
    {
        "Teachers" {Add-ADGroupMember -Identity "Teachers" -Members $existingUser} #All teachers
        "Maintenance" {Add-ADGroupMember -Identity "Maintenance" -Members $existingUser} #All maintenance
        "Office" {Add-ADGroupMember -Identity "Office" -Members $existingUser} #All office
    }

    if ($existingUser.Enabled -eq $false) {
            Get-ADPrincipalGroupMembership $existingUser.distinguishedname | Where-Object { $_.Name -ne "Domain Users" } | ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $existingUser -Confirm:$false }
            Set-ADUser -Identity $existingUser.distinguishedname -HomePhone $null
        }

}

function UpdateADUser($employeeID,$sAMAccountName,$name,$givenname,$mail,$sn,$displayname,$newhomedirectory,$position,$office,$userPrincipalName,$EnabledAccount,$accesscard){
    $existingUser = Get-ADUser -Filter "EmployeeID -eq '$employeeID'" -Properties * #Get matching user data according to employeeid
    $storage = HomePath $position #Get the folder/ou to put the user in
    $employeeNum = "Owls$employeeID"

    if ($position -eq 'Office') {
        $path = "OU="+$office+",OU="+$storage+","+$OUExtension 
    } else {$path = "OU="+$storage+","+$OUExtension }

    $testpath = "CN="+$existinguser.Name+",$path" #Change path in OU to new user name
    $newhomedirectory = "\\$fileserver\"+$storage.tolower() +"$\$sAMAccountName" #Where the new homedirectory will be located -either changed based on name change or location change

    if ("CN=$name,$path" -ne $existinguser) {
        
        if ($existingUser.HomeDirectory -ne $newhomedirectory)
        {
            Set-ADUser -Identity $existingUser -Add @{proxyAddresses = $existingUser.mail } #Set proxy addresses so that a changed user will still recieve their old emails   
            Move-Item -Path $existingUser.HomeDirectory -Destination $newhomedirectory -Force #Move homedirectory folder to newhomedirectory folder
        }

        Move-ADObject -Identity $existinguser -TargetPath $path #Move OU in AD to new OU position
        Rename-ADObject -Identity $testpath -NewName $name #Rename OU in AD
        
        if ($EnabledAccount -eq "false") {
            Set-ADUser -Identity "CN=$name,$path" -userPrincipalName $userPrincipalName -givenName $givenName -EmailAddress $mail -Surname $sn -SamAccountName $sAMAccountName -DisplayName $displayname -HomeDirectory $newhomedirectory -Description $position -Enabled $false -HomePhone $accesscard -EmployeeNumber $employeeNum #Set all the attributes for th user
        } else {
            Set-ADUser -Identity "CN=$name,$path" -userPrincipalName $userPrincipalName -givenName $givenName -EmailAddress $mail -Surname $sn -SamAccountName $sAMAccountName -DisplayName $displayname -HomeDirectory $newhomedirectory -Description $position -Enabled $true -HomePhone $accesscard -EmployeeNumber $employeeNum #Set all the attributes for th user
        }

        write-host ("$name, $sAMAccountName ,$mail" ) #For log taking
    }

}

function AddADUser($sAMAccountName,$name,$otherAttributes,$position,$office,$password,$EnabledAccount,$employeeID){
    $storage = HomePath $position #Get the folder/ou to put the user in
    $employeeNum = "Owls$employeeID"
    
    if ($EnabledAccount -eq "false") {$EnabledA = $false} else {$EnabledA = $true}
    
    if ($position -eq 'Office') {
        $path = "OU="+$office+",OU="+$storage+","+$OUExtension 
    } else {$path = "OU="+$storage+","+$OUExtension }

    $homepath = "\\"  + $fileserver + "\"+ $storage.tolower() + "$\" + $sAMAccountName  #The example below assumes student home folders exist in a \\TestDC\student$\username structure

    Write-Host $path

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
$sisfile = Import-Csv -delimiter "`t" -Path $sisexportfilestaff -header "givenName","sn","position","office","employeeid","accesscard","EnabledAccount" #Read from the saved textfile from the online csv file

foreach ($sisline in $sisfile) { #Read from textfile line by line

    $givenName = $sisline.givenName #Set given name
    $sn = $sisline.sn #Set username
    $position = $sisline.position #Position
    $office = $sisline.office #Position
    $employeeid = $sisline.employeeid #EmployeeID
    $password = ConvertTo-SecureString -AsPlainText "Owls$employeeid" -Force #Set the password to a secure string. Original password for staff is pre-set and changed on first logon
    $accesscard = $sisline.accesscard #accesscard
    $sAMAccountName = UniqueTest (($givenName[0] + $sn) -replace " ", "" -replace "\.\.", "." -replace "'", "" -replace "-", "" -replace "ó", "o" -replace ",", "" -replace "í", "i" ).ToLower() $givenName $sn $employeeid #Remove unnecessary characters/change to common ones then lower into uniform format
    $userPrincipalName = "$sAMAccountName$Domain" #Set User principle name 
    $mail = "$sAMAccountName$emaildomain" #Set the mail attribute for the account (if desired, usually helpful if you're synchronizing to Google Apps/Office 365)
    $displayname = "$givenName $sn" #Set display name
    $name = ($displayname -replace "\.\.", "." -replace "'", "" -replace "-", "" -replace "ó", "o" -replace ",", "" -replace "í", "i").ToUpper()
    $EnabledAccount = ($sisline.EnabledAccount).ToLower()
    $otherAttributes = @{'userPrincipalName' = "$userPrincipalName"; 'mail' = "$mail"; 'givenName' = "$givenName"; 'sn' = "$sn"; 'DisplayName' = "$displayname"; 'employeeID' = "$employeeID"; 'physicalDeliveryOfficeName' = "$office"; 'description' = "$position"; 'HomePhone' = "$accesscard"}
    $otherAttributes.description = [string]$otherAttributes.description #Needs to be a string for AD
                
    if ((Get-ADUser -Filter "EmployeeID -eq '$employeeID'") -eq $null) { #If new user - add
        ADDADUser $sAMAccountName $name $otherAttributes $position $office $password $EnabledAccount $employeeID
    } else { #if current user - update
        UpdateADUser $employeeID $sAMAccountName $name $givenname $mail $sn $displayname $newhomedirectory $position $office $userPrincipalName $EnabledAccount $accesscard
    }
        AddToGroups $employeeID $position $EnabledAccount #Add user to approriate groups   
  
}

Stop-Transcript #End log taking
# Remove the header lines from the transcript file
(Get-Content -Path $LogFilePath | Select-Object -Skip 18) | Set-Content -Path $LogFilePath -Force
