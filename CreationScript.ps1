#Set Password
do {
    $pwd1 = Read-Host -Prompt "Password: "
    $pwd2 = Read-Host -Prompt "Confirm Password: "

    # Confirm passwords match
    if ($pwd1 -ne $pwd2) {
        Write-Host "Passwords do not match"
    }
} until ($pwd1 -eq $pwd2)

$securepwd = $pwd1 | ConvertTo-SecureString -AsPlainText -Force
$encryptedpwd = $securepwd | ConvertFrom-SecureString #Encrypt the secure sting so it can be saved to new script accurately

#Define content for new script
$scriptContent = @"
    `$pwd = "$encryptedpwd" | ConvertTo-SecureString #Decrypt the encrypted string so it can be called to update password
    `$UserAccount = Get-LocalUser -Name "Administrator" #Get UserAccount with correct username
    if (`$UserAccount.Password -ne `$null) {
        `$storedPwd = `$UserAccount.Password | ConvertFrom-SecureString
    }
    Write-Host "Previously set password: `$storedPwd"
    `$UserAccount | Set-LocalUser -Password `$pwd #Set new password of 
"@

$scriptPath = "LocalAdminUpdate.ps1"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8

Write-Host "Client side script created at '$scriptPath"
