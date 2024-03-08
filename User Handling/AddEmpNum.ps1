$Domain = "@test.local" #Domain that AD is hosted on
$fileserver = "TESTDC" #Server name
$OUExtension = "OU=users,OU=managed,DC=test,DC=local" #Sets OU, DC of AD
$staffidupdate = "C:\Users\Administrator\Desktop\staffidupdate.csv" #Textfile with staff information that needs to be imported

$sisfile = Import-Csv -delimiter "," -Path $staffidupdate -header "givenName","sn","employeeid" #Read from the saved textfile from the online csv file

foreach ($sisline in $sisfile) { #Read from textfile line by line

    $givenName = $sisline.givenName # Set given name
    $employeeid = $sisline.employeeid # Set EmployeeID
    $sn = $sisline.sn #Set last name

    $displayname = "$givenName $sn"
    $name = ($displayname -replace "\.\.", "." -replace "'", "" -replace "-", "" -replace "ó", "o" -replace ",", "" -replace "í", "i").ToUpper()
           
    if (
    ((Get-ADUser -Filter "EmployeeID -eq '$employeeid'") -eq $null) -and #if employee id doesn't exist
    ((Get-ADUser -Filter "DisplayName -eq '$displayname'") -ne $null) -and #but the name exists
    ((Get-ADUser -Filter "DisplayName -eq '$displayname'").DistinguishedName -notlike '*OU=Students*') #and they aren't a student
    ) {
        Get-ADUser -Filter { DisplayName -eq $displayname } | Set-ADUser -EmployeeID $employeeid #add employeeid too existing name
    }

}
