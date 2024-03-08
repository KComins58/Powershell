$currentDate = Get-Date -Format "MM-dd-yyyy"
$currentyear = Get-Date -Format "yyyy"
$previousDate = (Get-Date).AddDays(-1).ToString("MM-dd-yyyy")

$apiUrl = 'https://opendata.usac.org/resource/jt8s-3q52.json?$query=SELECT%0A%20%20%60application_number%60%2C%0A%20%20%60form_pdf%60%2C%0A%20%20%60funding_year%60%2C%0A%20%20%60contact_name%60%2C%0A%20%20%60contact_phone%60%2C%0A%20%20%60contact_email%60%2C%0A%20%20%60billed_entity_name%60%2C%0A%20%20%60billed_entity_city%60%0AWHERE%0A%20%20caseless_one_of(%60billed_entity_state%60%2C%20%22MO%22)%0A%20%20AND%20(caseless_one_of(%60funding_year%60%2C%20%22'+$currentyear+'%22)%0A%20%20%20%20%20%20%20%20%20AND%20caseless_one_of(%60applicant_type%60%2C%20%22School%20District%22))%0AGROUP%20BY%0A%20%20%60application_number%60%2C%0A%20%20%60form_pdf%60%2C%0A%20%20%60funding_year%60%2C%0A%20%20%60contact_name%60%2C%0A%20%20%60contact_phone%60%2C%0A%20%20%60contact_email%60%2C%0A%20%20%60billed_entity_name%60%2C%0A%20%20%60billed_entity_city%60%0AORDER%20BY%20%60application_number%60%20ASC%20NULL%20LAST'
$localFilePath = "C:\Users\Administrator\Desktop\API\$currentDate.csv"
$previousFilePath = "C:\Users\Administrator\Desktop\API\$previousDate.csv"
$differenceFilePath = "C:\Users\Administrator\Desktop\API\difference.csv"

# Configure Gmail SMTP details
$smtpServer = "smtp.gmail.com"
$smtpPort = 587
$smtpFrom = "x@gmail.com"
$smtpTo = "x@gmail.com"
$smtpUsername = "x@gmail.com"
$smtpPassword = "password1"  # Use an App Password if you have 2-step verification enabled

# Group the new data by the 'application_number' column and select the first item from each group
$newData = Invoke-RestMethod -Uri $apiUrl -Method Get | Group-Object -Property application_number | ForEach-Object { $_.Group[0] }
$newData | Export-Csv -Path $localFilePath -NoTypeInformation

if (Test-Path $previousFilePath) {
    # Load the CSV from the previous day
    $previousData = Import-Csv -Path $previousFilePath

    # Compare and get only the new data
    $differenceData = $newData | Where-Object { $_.application_number -notin $previousData.application_number }

    # Save the difference data to the CSV file
    $differenceData | Export-Csv -Path $differenceFilePath -NoTypeInformation

    # Read the content of the difference file, skip the first line, and add it to the email message body
    $differenceContent = Get-Content -Path $differenceFilePath | Select-Object -Skip 1 | Out-String
    if ($differenceContent -ne '')
    {
        $messageSubject = "Difference in API Data - $currentDate"

        # Send email with the difference details in the message body
        Send-MailMessage -SmtpServer $smtpServer -Port $smtpPort -UseSsl -From $smtpFrom -To $smtpTo -Subject $messageSubject -Body $differenceContent -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($smtpUsername, (ConvertTo-SecureString $smtpPassword -AsPlainText -Force)))
    }
    Remove-Item -Path $previousFilePath
    Remove-Item -Path $differenceFilePath
}
