<-- Common PowerShell Commands for Security Analysts -->

1. System Information Gathering

- Get-ComputerInfo
- Get-WmiObject -Class Win32_OperatingSystem
- systeminfo

2. User and Group Enumeration

- Get-LocalUser
- Get-LocalGroup
- Get-LocalGroupMember -Group "Administrators"

3. Network Configuration and Connections

- Get-NetIPAddress
- Get-NetTCPConnection
- Test-NetConnection -ComputerName google.com -Port 443

4. Process and Service Monitoring

- Get-Process
- Get-Service
- Get-WmiObject Win32_Process | Select-Object Name, CommandLine

5. Event Log Analysis

- Get-EventLog -LogName Security -Newest 100
- Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational

<-- Advanced PowerShell Techniques for Security Analysts -->

1. Detecting Suspicious Processes 

- Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like "*Invoke-WebRequest*" }

2. Hashing Files for Integrity Checks

- Get-FileHash -Path "C:\Path\To\File.exe" -Algorithm SHA256

3. Monitoring for New USer Accounts

Register-WmiEvent -Class Win32_UserAccount -Action {
    Write-Output "New user account created: $($Event.SourceEventArgs.NewEvent.Name)"
}

4. Checking for Persistence Mechanisms

- Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

5. Script Block Logging Review

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | 
Where-Object { $_.Id -eq 4104 } | 
Select-Object TimeCreated, Message

6. Active Directory Recon

-Get-ADUser -Filter * -Properties LastLogonDate
Get-ADComputer -Filter * -Property OperatingSystem




