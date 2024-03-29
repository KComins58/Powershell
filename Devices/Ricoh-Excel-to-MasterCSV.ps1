#Install-Module -Name ImportExcel -Force -AllowClobber #Install ImportExcel
#requires -module ImportExcel

$todayDate = Get-Date -Format "MMddyyyy"
$date = Get-Date -Format "MM/dd/yyyy HH:mm:ss" #Current date/time in the format that textfiles will be named in
$csvFileName = "C:\Users\Administrator\Desktop\CopierAddress\ADDRESSBOOK$todayDate.csv"
$importfile = "C:\Users\Administrator\Desktop\CopierAddress\COPIER_MASTER_ADDRESS_LIST.xlsx"

# Check if the file already exists, and if so, remove it
if (Test-Path $csvFileName) {
    Remove-Item $csvFileName -Force
}

function Process-Row {
    param(
        [int]$iCount,
        [string]$Column1,
        [string]$Column2,
        [string]$Column3,
        [string]$Column4
    )

    # Remove double quotes from input variables
    $Column1 = $Column1.ToUpper() -replace '"'
    $Column2 = $Column2.ToUpper() -replace '"'
    $Column3 = $Column3 -replace '"'
    $Column4 = $Column4 -replace '"'

    while ($Column3.Length -lt 4)
    {
        $Column3 = "0$Column3"
    }


    $sName = "$Column1 $Column2"
    $sUsername = $Column1[0] +" $Column2" -replace " "
    $sEmail = $sUsername.ToLower()+"@email.com"

    if ($Column4 -eq 'teacher') {
        $sPath = "\\Domain\teacher$\"+$sUsername.ToLower()+"\Documents\scan"
    } else { $sPath = "\\Domain\office$\"+$sUsername.ToLower()+"\Documents\scan" }

    switch -Regex ($Column2[0]) {
    "^[A-B]" {$K = "1"}
    "^[C-D]" {$K = "2"}
    "^[E-F]" {$K = "3"}
    "^[G-H]" {$K = "4"}
    "^[I-K]" {$K = "5"}
    "^[L-N]" {$K = "6"}
    "^[O-Q]" {$K = "7"}
    "^[R-T]" {$K = "8"}
    "^[U-W]" {$K = "9"}
    "^[X-Z]" {$K = "10"}
    }

    $processedRow = @(
        "[$iCount],[$sName],[1],[0],[$iCount],[U],[],[$sUsername],[1],[1],[$K],[0],[0],[0],[1],[$Column3],[1],[],[],"+
        "[omitted],[0],[],[],[omitted],[0],[],[],[omitted],[0],[],[],[omitted],[0],[],[],[],[],[],[],[],[],"+
        "[],[],[-1],[1],[],[g3],[],[$sEmail],[],[0],[],[],[1],[],[],[0],[1],[0],[21],[],[$sPath],[us-ascii],"+
        "[1],[1],[0],[0],[0],[],[omitted],[],[],[1],[],[0],[],[],[],[]"
    )

    return $processedRow
}

# Header information
$header = @"
# Format Version: 5.1.1.0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
# Generated at: $date,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
# Function Name: User Data Preference,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
# Template Name:New Template,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
# Description: null,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
# Authentication Method (0=none or user code/1=others): 0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
Index in ACLs and Groups,Name,Set General Settings,Set Registration No.,Registration No.,Entry Type,Phonetic Name,Display Name,Display Priority,Set Title Settings,Title 1,Title 2,Title 3,Title Freq.,Set User Code Settings,User Code,Set Auth. Info Settings,Device Login User Name,Device Login Password,Device Login Password Encoding,SMTP Authentication,SMTP Authentication Login User Name,SMTP Authentication Login Password,SMTP Authentication Password Encoding,Folder Authentication,Folder Authentication Login User Name,Folder Authentication Login Password,Folder Authentication Password Encoding,LDAP Authentication,LDAP Authentication Login User Name,LDAP Authentication Login Password,LDAP Authentication Password Encoding,Set Access Control Settings,Can Use B/W Copy,Can Use Single Color Copy,Can Use Two Color Copy,Can Use Full Color Copy,Can Use Auto Color Copy,Can Use B/W Print,Can Use Color Print,Can Use Scanner,Can Use Fax,Can Use Document Server,Maximum of Print Usage Limit,Set Email/Fax Settings,Fax Destination,Fax Line Type,International Fax Transmission Mode,E-mail Address,Ifax Address,Ifax Enable,Direct SMTP,Ifax Direct SMTP,Fax Header,Label Insertion 1st Line (Selection),Label Insertion 2nd Line (String),Label Insertion 3rd Line (Standard Message),Set Folder Settings,Folder Protocol,Folder Port No.,Folder Server Name,Folder Path,Folder Japanese Character Encoding,Set Protection Settings,Is Setting Destination Protection,Is Protecting Destination Folder,Is Setting Sender Protection,Is Protecting Sender,Sender Protection Password,Sender Protection Password Encoding,Access Privilege to User,Access Privilege to Protected File,Set Group List Settings,Groups,Set Counter Reset Settings,Enable Plot Counter Reset,Enable Fax Counter Reset,Enable Scanner Counter Reset,Enable User Volume Counter Reset
"@

$iCount = 1

$header | Out-File -FilePath $csvFileName -Encoding UTF8

$importedData | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | ForEach-Object {
    $row = $_
    $rowValues = $row.Split(',')
    
    # Check if the first column is empty
    if (-not [string]::IsNullOrWhiteSpace($rowValues[0])) {
        $processedRow = Process-Row -iCount $iCount -Column1 $rowValues[0] -Column2 $rowValues[1] -Column3 $rowValues[2] -Column4 $rowValues[3]
        $processedRow -join ',' | Out-File -FilePath $csvFileName -Append -Encoding UTF8
        $iCount += 1
    } else {
        # Exit the loop if the first column is empty
        break
    }
}

# Remove the BOM from the file
(Get-Content -Raw -Path $csvFileName) | Set-Content -Path $csvFileName -Encoding UTF8
