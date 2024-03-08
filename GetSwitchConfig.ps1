#import posh-ssh
Import-Module -name posh-ssh

#requires -module posh-ssh

$folderpath = "C:\Users\Administrator\Desktop\Switch Configs"
$passwordtext1 = "C:\Users\Administrator\Desktop\Switch Configs\password.txt"
$passwordtext2 = "C:\Users\Administrator\Desktop\Switch Configs\sftppassword.txt"

$encryptedString1 = Get-Content -Path $passwordtext1
$encryptedString2 = Get-Content -Path $passwordtext2

$username = "admin"
$sftpusername = "password"

# Globals
$today = Get-Date -Format "MM-dd-yyyy"
$month = Get-Date -Format MMMM
$year = Get-Date -Format "yyyy"
$sftp_server = "xx.x.x.xx"

$sftpusername = $sftpusername + "@" + $sftp_server

# simple credential handling

$pwfile = ConvertTo-SecureString -String $encryptedString1
$sftppassword = ConvertTo-SecureString -String $encryptedString2

$Credentials=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $pwfile
# put all the devices in this array
$switches_array = @()
$switches_array = Get-Content -Path "$folderpath\switches.txt"

foreach ($switch in $switches_array)
    {
    # create a folder for every device
    # create a folder for every year
    Get-Item "$folderpath\$switch\" -ErrorAction SilentlyContinue
    if (!$?)
        {
        New-Item "$folderpath\$switch\" -ItemType Directory
        }

    # create a folder for every month
    Get-Item "$folderpath\$switch\$year\" -ErrorAction SilentlyContinue
    if (!$?)
        {
        New-Item "$folderpath\$switch\$year\" -ItemType Directory
        }

    # create a folder for every day
    Get-Item "$folderpath\$switch\$year\$month\" -ErrorAction SilentlyContinue
    if (!$?)
        {
        New-Item "$folderpath\$switch\$year\$month\" -ItemType Directory
        }

    Get-Item "$folderpath\$switch\$year\$month\$today" -ErrorAction SilentlyContinue
    if (!$?)
        {
        New-Item "$folderpath\$switch\$year\$month\$today" -ItemType Directory
        }

    # start the SSH Session
    New-SSHSession -ComputerName $switch -Credential $Credentials -AcceptKey:$true
    $session = Get-SSHSession -Index 0
    # usual SSH won't work, we need a shell stream for the procurve
    $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    # send a "space" for the "Press any key to continue" and wait before you issue the next command
    $stream.Write("`n")
    Sleep 5
    # Change to Enable mode
    $stream.Write("enable`n")
    $stream.Write("%password%`n")
    # copy startup-config and wait before you issue the next command
    $stream.Write("copy startup-config sftp $sftpusername \$year\$month\$today\$switch\Startup-config`n")
    $stream.Write("$sftppassword`n")
    Sleep 10
    # disconnect from host
    Remove-SSHSession -SessionId 0
    
    }
