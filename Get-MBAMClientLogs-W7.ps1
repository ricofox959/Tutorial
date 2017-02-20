#requires -Version 3


$LogPath = 'C:\Transfer'

Write-Host "Checking to ensure $LogPath exists, if not creating it"
 
If((Test-Path -Path $LogPath) -ne $true)
{
  New-Item -Path $LogPath -ItemType Container
}

$iLog = $LogPath + "\$($ENV:COMPUTERNAME)_"

#Event Logs
$osVersion = (GWMI Win32_OperatingSystem).Version.Split('.')
$major = [string]($osVersion[0])
$minor = ($osVersion[1])

if ($major -eq "7") {

#For win 8 and higher
Write-Host "Template for Windows 7 and below used"
[xml]$xmlPath = @"
<QueryList>
    <Query Id='0' Path='System'>
        <Select Path='System'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-BitLocker-DrivePreparationTool/Admin'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-BitLocker-DrivePreparationTool/Operational'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-MBAM/Admin'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-MBAM/Operational'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path="Microsoft-Windows-Kernel-Boot/Analytic">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-Power']]]</Select>
        <Select Path="Microsoft-Windows-Kernel-Power/Diagnostic">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-Power']]]</Select>
        <Select Path="Microsoft-Windows-Kernel-Power/Thermal-Diagnostic">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-Power']]]</Select>
        <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-Power']]]</Select>
    </Query>
</QueryList>
"@
}

Else {
Write-Host "Template for Windows 8 and higher used"
[xml]$xmlPath = @"
<QueryList>
    <Query Id='0' Path='System'>
        <Select Path='System'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-BitLocker/BitLocker Management'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-BitLocker/BitLocker Operational'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-Bitlocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-BitLocker-DrivePreparationTool/Admin'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-BitLocker-DrivePreparationTool/Operational'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-MBAM/Admin'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path='Microsoft-Windows-MBAM/Operational'>*[System[Provider[@Name='Microsoft-Windows-BitLocker-API' or @Name='Microsoft-Windows-BitLocker-DrivePreparationTool' or @Name='Microsoft-Windows-BitLocker-Driver' or @Name='Microsoft-Windows-BitLocker-Driver-Performance' or @Name='Microsoft-Windows-MBAM' or @Name='TPM' or @Name='Microsoft-Windows-TPM-WMI']]]</Select>
        <Select Path="Microsoft-Windows-Kernel-Boot/Analytic">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-BootDiagnostics' or @Name='Microsoft-Windows-Kernel-Power' or @Name='Microsoft-Windows-Kernel-PowerTrigger']]]</Select>
        <Select Path="Microsoft-Windows-Kernel-Boot/Operational">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-BootDiagnostics' or @Name='Microsoft-Windows-Kernel-Power' or @Name='Microsoft-Windows-Kernel-PowerTrigger']]]</Select>
        <Select Path="Microsoft-Windows-Kernel-BootDiagnostics/Diagnostic">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-BootDiagnostics' or @Name='Microsoft-Windows-Kernel-Power' or @Name='Microsoft-Windows-Kernel-PowerTrigger']]]</Select>
        <Select Path="Microsoft-Windows-Kernel-Power/Diagnostic">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-BootDiagnostics' or @Name='Microsoft-Windows-Kernel-Power' or @Name='Microsoft-Windows-Kernel-PowerTrigger']]]</Select>
        <Select Path="Microsoft-Windows-Kernel-Power/Thermal-Diagnostic">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-BootDiagnostics' or @Name='Microsoft-Windows-Kernel-Power' or @Name='Microsoft-Windows-Kernel-PowerTrigger']]]</Select>
        <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot' or @Name='Microsoft-Windows-Kernel-BootDiagnostics' or @Name='Microsoft-Windows-Kernel-Power' or @Name='Microsoft-Windows-Kernel-PowerTrigger']]]</Select>
    </Query>
</QueryList>
"@
}

Write-Host "Gathering Event Logs from $ENV:COMPUTERNAME"
Get-WinEvent -FilterXml $xmlPath -Oldest | 
    Select TimeCreated,LevelDisplayName,Message,ID,PCRValues,PCRValuesSize,FilteredTCGLog,FilteredTCGLogSize,Providername,LogName|
        Export-Csv -Path $iLog'events.csv' -NoTypeInformation

# Registry Settings
Write-Host "Gathering FVE Registry Keys from $ENV:COMPUTERNAME"
Get-Item -Path HKLM:\Software\Policies\Microsoft\FVE | Out-File -FilePath $iLog'FVE.txt'

Write-Host "Gathering MBAM Software Registry Keys from $ENV:COMPUTERNAME"
Get-Item -Path HKLM:\Software\Microsoft\MBAM | Out-File -FilePath $iLog'MBAM_SOFT.txt'

Write-Host "Gathering MBAM Policy Registry Keys from $ENV:COMPUTERNAME"
Get-ChildItem -Path HKLM:\Software\Policies\Microsoft\FVE | Out-File -FilePath $iLog'MBAM.txt'

# MBAM properties
Write-Host "Obtaining Paths to MBAM Web Services on $ENV:COMPUTERNAME"
$SRSE_URI = (Get-Item -Path HKLM:\Software\Policies\Microsoft\FVE\MDOPBitLockerManagement).GetValue('StatusReportingServiceEndpoint')
$KRSE_URI = (Get-Item -Path HKLM:\Software\Policies\Microsoft\FVE\MDOPBitLockerManagement).GetValue('KeyRecoveryServiceEndPoint')

Try {
    Write-Host "Testing URL for StatusReportingServiceEndpoint on $ENV:COMPUTERNAME"
    Invoke-WebRequest -Uri $SRSE_URI -UseDefaultCredentials  | Out-File -FilePath $iLog'StatusReportingServiceEndpoint_URI.txt'
    }
    Catch {
        $Error[0] | Add-Content -Path $iLog'StatusReportingServiceEndpoint_URI.txt'
        }

Try {        
    Write-Host "Testing URL for KeyRecoveryServiceEndpoint on $ENV:COMPUTERNAME"
    Invoke-WebRequest -Uri $KRSE_URI -UseDefaultCredentials  | Out-File -FilePath $iLog'KeyRecoveryServiceEndpoint_URI.txt'
    }
    Catch {
        $Error[0] | Add-Content -Path $iLog'KeyRecoveryServiceEndpoint_URI.txt'
        }

# Get Key Protector(s) Type
Write-Host "Getting BitLocker Protection IDs and Types from $ENV:COMPUTERNAME"
Add-Content -Path $iLog'Settings.txt' -Value 'BitLocker Protection IDs and Types'

    $BitLocker = GWMI -Class Win32_EncryptableVolume -Namespace root\CIMV2\Security\MicrosoftVolumeEncryption -Filter "DriveLetter = 'c:'"
    $ProtectorIds = $BitLocker.GetKeyProtectors("0").volumekeyprotectorID            
    $return = @()
    foreach ($ProtectorID in $ProtectorIds){ 
        $KeyProtectorType = $BitLocker.GetKeyProtectorType("$ProtectorID").KeyProtectorType
        switch($KeyProtectorType){
            "0"{$return += "Unknown or other protector type";break}
            "1"{$return += "Trusted Platform Module (TPM)";
                $return += "     Platform Validation Profile " + "{ " + $BitLocker.GetKeyProtectorPlatformValidationProfile("$ProtectorID").PlatformValidationProfile + " }" }
            "2"{$return += "External key";break}
                # GetKeyProtectorExternalKey(    
            "3"{$return += "Numerical password";break}
                # $BitLocker.GetKeyProtectorNumericalPassword($ProtectorID)
            "4"{$return += "TPM And PIN";break}
                # $BitLocker.GetKeyProtectorPlatformValidationProfile("$ProtectorID")
            "5"{$return += "TPM And Startup Key";break}
                # $BitLocker.GetKeyProtectorPlatformValidationProfile("$ProtectorID")
                # GetKeyProtectorExternalKey(       
            "6"{$return += "TPM And PIN And Startup Key";break}
                # $BitLocker.GetKeyProtectorPlatformValidationProfile("$ProtectorID")
                # GetKeyProtectorExternalKey(
            "7"{$return += "Public Key";break}
                # GetKeyProtectorCertificate(
            "8"{$return += "Passphrase";break}
            "9"{$return += "TPM Certificate";break}
            "10"{$return += "CryptoAPI Next Generation (CNG) Protector";break}
                
    }
}
Add-Content -Path $iLog'Settings.txt' -Value $return

$MBAM = GWMI -Class mbam_volume -Namespace root\microsoft\mbam
$ReasonForNonCompliance = $MBAM.ReasonsForNoncompliance
$MBAMStatus = Switch ($ReasonForNonCompliance) {
 0 {"0 - Cipher strength not AES 256."}
 1 {"1 - MBAM Policy requires this volume to be encrypted but it is not."}
 2 {"2 - MBAM Policy requires this volume to NOT be encrypted, but it is."}
 3 {"3 - MBAM Policy requires this volume use a TPM protector, but it does not."}
 4 {"4 - MBAM Policy requires this volume use a TPM+PIN protector, but it does not."}
 5 {"5 - MBAM Policy does not allow non TPM machines to report as compliant."}
 6 {"6 - Volume has a TPM protector but the TPM is not visible (booted with recover key after disabling TPM in BIOS?)."}
 7 {"7 - MBAM Policy requires this volume use a password protector, but it does not have one."}
 8 {"8 - MBAM Policy requires this volume NOT use a password protector, but it has one."}
 9 {"9 - MBAM Policy requires this volume use an auto-unlock protector, but it does not have one."}
10 {"10 - MBAM Policy requires this volume NOT use an auto-unlock protector, but it has one."}
11 {"11 - Policy conflict detected preventing MBAM from reporting this volume as compliant."}
12 {"12 - A system volume is needed to encrypt the OS volume but it is not present."}
13 {"13 - Protection is suspended for the volume."}
14 {"14 - AutoUnlock unsafe unless the OS volume is encrypted."}
default {"Compliant"}
}

Add-Content -Path $iLog'MBAMCompliance.txt' -Value 'Reason for Non-Compliance'; Add-Content -Path $iLog'MBAMCompliance.txt' -Value $MBAMStatus

# Group Policy
Write-Host "Getting Group Policy Results from $ENV:COMPUTERNAME"
$args = '/SCOPE COMPUTER ' + '/H ' + $iLog + 'GPResults.html' 
Start-Process -FilePath 'C:\Windows\System32\gpresult.exe' -ArgumentList $args -WindowStyle Hidden -Wait

# BitLocker WMI MOF health check
Write-Host "Getting Win32_EncryptableVolume Information from $ENV:COMPUTERNAME"
Add-Content -Path $iLog'WMI_NS.txt' -Value 'BitLocker WMI MOF Health Check'
GWMI -Class 'Win32_EncryptableVolume' -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' | Out-File -FilePath $iLog'WMI_NS.txt'

# Get Bitlocker Encryption State
$EncryptVol = $BitLocker.ProtectionStatus
$PSState = switch ($EncryptVol) {
0 {"Protection OFF"}
1 {"Protection ON (Unlocked)"}
2 {"Protection ON (Locked)"}
}
Add-Content -Path $iLog'BitLockerEncryptionState.txt' -Value 'Bitlocker Encryption State';Add-Content -Path $iLog'BitLockerEncryptionState.txt' -Value $PSState

# Get PCR[7] Secure Boot Binding State
$SecureBootBindingState = $BitLocker.GetSecureBootBindingState()
$BindingState = Switch ($SecureBootBindingState.BindingState) {
0 {"Not Possible"}
1 {"Disabled By Policy"}
2 {"Possible"}
3 {"Bound"}
}
Add-Content -Path $iLog'PCR-7-SecureBootBindingState.txt' -Value 'PCR[7] Secure Boot Binding State';Add-Content -Path $iLog'PCR-7-SecureBootBindingState.txt' -Value $BindingState

# BitLocker Suspend Count
$SuspendCount = $BitLocker.GetSuspendCount().SuspendCount
Add-Content -Path $iLog'BitLockerSuspendCount.txt' -Value 'Bitlocker Encryption State';Add-Content -Path $iLog'BitLockerSuspendCount.txt' -Value $SuspendCount

# Gather Logs into Zip folder
Write-Host "Compressing Logs into zip file for $ENV:COMPUTERNAME"
$DestPath = "c:\transfer\" + "$($ENV:COMPUTERNAME)" + "_" + "MBAMLogs.zip"
Compress-Archive -Path c:\transfer\* -CompressionLevel Optimal -DestinationPath $Destpath -Force

$hdr = '*'  * 60
Write-Host $hdr -ForegroundColor Yellow
Write-Host "Directory contents have been archived for you in $LogPath "`n"Please send MBAMLogs.zip to your support engineer for review" -ForegroundColor yellow -BackgroundColor Black
Write-Host $hdr -ForegroundColor Yellow