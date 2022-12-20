<#
  .SYNOPSIS

    Checks windows configuration. Lots of stuff taken from lots of places. Thanks everyone! 

    winowsEnum.ps1
    Author: CB Hue - HueBSolutions LLC
    https://github.com/CBHue/

    Required Dependencies: Sysinternals accesscheck.exe
    Optional Dependencies: None  


  .DESCRIPTION

    Checks provided hosts for readable shares.

  .PARAMETER accessCheck

    Location of sysinternals accesscheck.exe

  .PARAMETER outputDir

    The directory to output the screenshots to. 

  .PARAMETER Threads

    (Placeholder for multi-threading to be added in later)


  .EXAMPLE

    C:\PS>  # powershell -nologo -executionpolicy bypass -file WindowsEnum.ps1 -accessCheck .\SysinternalsSuite\accesschk64.exe -outputDir .\ 

    Description
    -----------
    This command run basic enumeration of a windows host. 

#>


Param
  (
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$accessCheck,
    [string]$outputDir,
    [string]$cmdName,
    [string]$extended
  )

 
function whost($a) {
    Write-Host
    Write-Host -ForegroundColor Green $lines
    Write-Host -ForegroundColor Green " "$a 
    Write-Host -ForegroundColor Green $lines
}

$lines="------------------------------------------"

$standard_commands = [ordered]@{

    'Basic System Information'                    = 'Start-Process "systeminfo" -NoNewWindow -Wait';
    'Environment Variables'                       = 'Get-ChildItem Env: | ft Key,Value';
    'Network Information'                         = 'Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address';
    'DNS Servers'                                 = 'Get-DnsClientServerAddress -AddressFamily IPv4 | ft';
    'ARP cache'                                   = 'Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State';
    'Routing Table'                               = 'Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex';
    'Network Connections'                         = 'Start-Process "netstat" -ArgumentList "-ano" -NoNewWindow -Wait | ft';
    'Connected Drives'                            = 'Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft';
    'Firewall Config'                             = 'Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait | ft';
    'Current User'                                = 'Write-Host $env:UserDomain\$env:UserName';
    'User Privileges'                             = 'start-process "whoami" -ArgumentList "/priv" -NoNewWindow -Wait | ft';
    'Local Users'                                 = 'Get-LocalUser | ft Name,Enabled,LastLogon';
    'Logged in Users'                             = 'Start-Process "qwinsta" -NoNewWindow -Wait | ft';
    'Credential Manager'                          = 'start-process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait | ft'
    'User Autologon Registry Items'               = 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | ft';
    'Local Groups'                                = 'Get-LocalGroup | ft Name';
    'Local Administrators'                        = 'Get-LocalGroupMember Administrators | ft Name, PrincipalSource';
    'User Directories'                            = 'Get-ChildItem C:\Users | ft Name';
    'SAM backup files'                            = 'Write-Host ("%SYSTEMROOT%\repair\SAM").PadRight(90," ") ": " -NoNewline ;
                                                     $r = Test-Path -ErrorAction SilentlyContinue "%SYSTEMROOT%\repair\SAM;"
                                                     if ($r -eq "True") {Write-Host -ForegroundColor Red $r}
                                                     else {Write-Host -ForegroundColor Green $r} 
                                                     Write-Host ("%SYSTEMROOT%\system32\config\regback\SAM").PadRight(90," ")  ": " -NoNewline ; 
                                                     $r = Test-Path -ErrorAction SilentlyContinue %SYSTEMROOT%\system32\config\regback\SAM; 
                                                     if ($r -eq "True") {Write-Host -ForegroundColor Red $r}
                                                     else {Write-Host -ForegroundColor Green $r} 
                                                     Write-Host ("%SYSTEMROOT%\system32\config\SAM").PadRight(90," ") ": " -NoNewline ; 
                                                     $r = Test-Path -ErrorAction SilentlyContinue %SYSTEMROOT%\system32\config\SAM
                                                     if ($r -eq "True") {Write-Host -ForegroundColor Red $r}
                                                     else {Write-Host -ForegroundColor Green $r}';

    'Running Processes'                           = 'gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize';
    'Installed Software Directories'              = 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime';
    'Software in Registry'                        = 'Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name';
    'Folders with Everyone Permissions'           = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}} | ft';
    'Folders with BUILTIN\User Permissions'       = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}} | ft';
    'Checking registry for AlwaysInstallElevated' = 'Test-Path -ErrorAction SilentlyContinue -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" | ft';
    'Scheduled Tasks'                             = 'Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State';
    'Tasks Folder'                                = 'Get-ChildItem C:\Windows\Tasks | ft';
    'Startup Commands'                            = 'Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl';
    'ENV Path'                                    = '$env:Path -split ";"'
    'ENV Path Existence'                              = '$env:Path -split ";" | % {
                                                        if (!$_) {continue}; 
                                                        Write-Host -NoNewline ($_).PadRight(90," ") ": "; 
                                                        $r = Test-Path -ErrorAction SilentlyContinue "$_"
                                                        if ($r -eq "True") {Write-Host -ForegroundColor Green $r}
                                                        else {Write-Host -ForegroundColor Red $r}
                                                     }'
    'ENV PATH icacls root'                        = '$roots = New-Object System.Collections.ArrayList; 
                                                     $env:Path -split ";"| % { $o=($_ -split "\\")[0]; $o=$o.trim(); if ($o){$null = $roots.Add($o+"\")}}; 
                                                     $roots | sort -unique | % {Write-Host -ForegroundColor Cyan "Access Rules for $_`n"; Get-Acl $_ | select Path -ExpandProperty Access}' 
    'ENV Paths Modifiable'                        = '$env:Path -split ";" | % {if (!$_) {continue}; & $accessCheck -accepteula -nobanner -uqwd $env:UserName `"$_`"} | Select-String "RW"'
    'Service Existance'                           = '(gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows\*"} | Select PathName) | 
                                                     % {
                                                        $tmpService =  $_.pathname.split("`"");
                                                        if ($tmpService[0]) {$tmpPath = $tmpService[0]}
                                                        else {$tmpPath = $tmpService[1]}
                                                        Write-Host -NoNewline ($tmpPath).PadRight(90," ") ": "; 
                                                        $r = Test-Path -ErrorAction SilentlyContinue $tmpPath
                                                        if ($r -eq "True") {Write-Host -ForegroundColor Green $r}
                                                        else {Write-Host -ForegroundColor Red $r}   
                                                     }'
    'Services not in c:\windows'                  = 'wmic service get displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"'
    'Unquoted Service Paths'                      = 'gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike ''"*''} | select PathName, DisplayName, Name | ft';
    'Weak service Permissions'                    = "& $accessCheck -accepteula -nobanner -uwcqv $env:UserName *"
    'Writeable folders in C:\'                    = "& $accessCheck -accepteula -nobanner -uqw $env:UserName c:\*"
    'Writeable items in C:\Program Files'         = "& $accessCheck -accepteula -nobanner -uswd $env:UserName `"c:\Program Files`""
    'Writeable items in C:\Program Files (x86)'   = "& $accessCheck -accepteula -nobanner -uswd $env:UserName `"c:\Program Files (x86)`""
    'Readable items in C:\Users'                  = "& $accessCheck -accepteula -nobanner -usrd $env:UserName `"c:\Users\`" | Select-String -NotMatch -Pattern '$env:UserName|C:\\Users\\Public|C:\\Users\\Default'"
}

$extended_commands = [ordered]@{

    'Searching for Unattend and Sysprep files' = 'Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")} | Out-File C:\temp\unattendfiles.txt';
    'Searching for web.config files'           = 'Get-Childitem –Path C:\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\temp\webconfigfiles.txt';
    'Searching for other interesting files'    = 'Get-Childitem –Path C:\ -Include *password*,*cred*,*vnc* -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\temp\otherfiles.txt';
    'Searching for various config files'       = 'Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\temp\configfiles.txt'
    'Searching HKLM for passwords'             = 'reg query HKLM /f password /t REG_SZ /s | Out-File C:\temp\hklmpasswords.txt';
    'Searching HKCU for passwords'             = 'reg query HKCU /f password /t REG_SZ /s | Out-File C:\temp\hkcupasswords.txt';
    'Searching for files with passwords'       = 'Get-ChildItem c:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath -notlike "*Windows Kits*"}| Select-String -Pattern "password" | Out-File C:\temp\password.txt';
    
}

function RunCommands($commands) {

    ForEach ($command in $commands.GetEnumerator()) {
        
        if ($command.Name -contains "SKIP") {
            continue
        }
        
        whost $command.Name
        Invoke-Expression $command.Value
        Start-Sleep -Seconds 5
    }
}

# Run a specific check
if ($cmdName) {
    $oneCMD = @{$cmdName = $standard_commands[$cmdName]}
    RunCommands($oneCMD)
}

# Run the standard set
else {
    RunCommands($standard_commands)
}

if ($extended) {
    if ($extended.ToLower() -eq 'extended') {
        $result = Test-Path -ErrorAction SilentlyContinue C:\temp
        if ($result -eq $False) {
            New-Item C:\temp -type directory
        }
        whost "Results writing to C:\temp\`nThis may take a while..."
        RunCommands($extended_commands)
        whost "Script Finished! Check your files in C:\temp\"
    }
}
else {
    whost "Script finished!"
}