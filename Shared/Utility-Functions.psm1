<#
    File: Utility-Functions.psm1
    Author: cbradley@vmware.com
	Modified by Phil Helmling: 27 Nov 2019, optimised and restructured to reduce API calls
#>

#==========================Header=============================#
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Reg";
}

#Unblock-File "$Global:shared_path\Helpers.psm1"
#$LocalHelpers = Import-Module "$Global:shared_path\Helpers.psm1" -ErrorAction Stop -PassThru -Force;

$shared_path = $Global:shared_path;
#$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$Global:log_path\Utility-Functions.log"; 
$securityLogLocation = "$Global:log_path\SecurityAudit.log";

#$GlobalModules = @();
#$GlobalImporter = @("$shared_path\Database-Management.psm1", "$shared_path\AirWatchAPI.psm1", "$shared_path\Utility-Functions.psm1");
#$GlobalImporter = @("$shared_path\Database-Management.psm1");
#foreach ($Import in $GlobalImporter){
#    Unblock-File $Import;
#    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force
#}

if(Test-Path "$shared_path\api-debug.config"){
    $Debug = $true;
}

function Get-ItemPropertyValueSafe{
    Param([string]$Path, [string]$Name,$DefaultVal)
    $ReturnVal = $DefaultVal
    If(Test-Path $Path){
        If(Test-ItemProperty -Path $Path -Name $Name){
            $ReturnVal = Get-ItemPropertyValue -Path $Path -Name $Name;
        }
    }
    return $ReturnVal;
}

function Test-ItemProperty{
    Param([string]$Path, [string]$Name)
    return (Get-Item -Path $Path).GetValue($Name) -ne $null;
}

function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path='C:\temp\grppolicies\setup_logs.txt',
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
    }
}

function Write-Log2{ #Wrapper function to made code easier to read;
    [CmdletBinding()]
    Param
    (
        [string]$Message,
        [string]$Path=$logLocation,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Success","Error","Warn","Info")]
        [string]$Level="Info",
        [switch]$UseLocal
    )
    if((!$UseLocal) -and $Level -ne "Success"){
        Write-Log -LogPath $Path -LogContent $Message -Level $Level;
    } else {
        $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
        $FontColor = "White";
        If($ColorMap.ContainsKey($Level)){
            $FontColor = $ColorMap[$Level];
        }
        $DateNow = (Date).ToString("yyyy-mm-dd hh:mm:ss");
        Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
        Write-Host "$MethodName::$Level`t$Message" -ForegroundColor $FontColor;
    }
}

function ConvertTo-EncryptedFile{
    param([string]$FileContents)
    Try{
        $secured = ConvertTo-SecureString -String $FileContents -AsPlainText -Force;
        $encrypted = ConvertFrom-SecureString -SecureString $secured
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        Write-Log2 -Path $logLocation -Message "An error has occurrred in ConvertTo-EncryptedFile.  Error: $ErrorMessage"
        return "Error";
    }
    return $encrypted;
}

function ConvertFrom-EncryptedFile{
    param([string]$FileContents)
    Try{
        $decrypter = ConvertTo-SecureString -String $FileContents.Trim() -ErrorAction Stop;
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($decrypter)
        $api_settings = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        Write-Log2 -Path $logLocation -Message "An error has occurrred in ConvertFrom-EncryptedFile.  Error: $ErrorMessage"
        return "Error: $ErrorMessage";
    }
    return $api_settings
}

Function Add-PropertyToObject{
    param(
        [PSCustomObject]$Object,
        [string]$Name,
        [string]$Value
    )
    if($Value){
        $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value;
    }
    return $Object;
}

Function Add-PropertiesToObject{
    param(
        [PSCustomObject]$Object,
        [Hashtable]$Properties,
        [Hashtable]$Reserved
    )
    foreach($Name in $Properties.Keys){
        $Value = $Properties[$Name];
        if($Value.GetType().BaseType.Name -eq "Array" -or
                $Value.GetType().Name -eq "Hashtable"){
            $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value;
        } elseif($Value){
            $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value;
        }
    }
    if($Reserved.Count -gt 0){
        foreach($Name in $Reserved.Keys){
             $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Reserved[$Name];
        }
    }
    return $Object;
}

Function New-DynamicObject{
    param(
        [Hashtable]$Properties,
        [Hashtable]$Reserved
    )
    $Object = New-Object -TypeName PSCustomObject
    foreach($Name in $Properties.Keys){
        $Value = $Properties[$Name];
        if($Value.GetType().BaseType.Name -eq "Array" -or
                $Value.GetType().Name -eq "Hashtable"){
            $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value;
        }
        elseif($Value){
            $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value;
        }
    }
    if($Reserved.Count -gt 0){
        foreach($Name in $Reserved.Keys){
             $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Reserved[$Name];
        }
    }
    return $Object;
}

<#
Function: Get-CurrentLoggedonUser
Author  : cbradley@vmware.com
Description : Gets username of the current logged in user
Input Params: N/A, Output: String
Example: Get-CurrentLoggedonUser
        returns Chase Bradley
#>
function Get-CurrentLoggedonUser{
    param([bool]$ReturnObj=$false)
    If(Test-Path "$shared_path\GetWin32User.cs"){
        Unblock-File "$shared_path\GetWin32User.cs"
        #if (-not ([Management.Automation.PSTypeName]'AWDeviceInventory.QueryUser').Type) {
			[string[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
			Add-Type -Path "$shared_path\GetWin32User.cs" -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'
		#}

		$usernameLookup = [AWDeviceInventory.QueryUser]::GetUserSessionInfo("$env:COMPUTERNAME") | Where-Object {$_.Connectstate -eq "Active" -and $_.IsConsoleSession -eq $True}

    } Else {
        $usernameLookup = Get-WMIObject -class Win32_ComputerSystem | select username;
    }

    if($ReturnObj){
        if($usernameLookup){
			$usernameLookup = $usernameLookup.username;
		}
        if($usernameLookup -match "([^\\]*)\\(.*)"){
            $usernameProp = @{"Username"=$Matches[2];"Domain"=$Matches[1];"FullName"=$Matches[0]}
            $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
        } elseif($usernameLookup -match "([^@]*)@(.*)"){
            $usernameProp = @{"Username"=$Matches[1];"Domain"=$Matches[2];"Fullname"=$Matches[0]}
            $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
        }         
    }
    return $usernameLookup;
}

<#
Function: Get-UserSIDLookup
Author  : cbradley@vmware.com
Description : Gets an SID lookup of a user based on username 
Input Params:  
        .PARAMETER  'UsernameLookup'
		 Username to evaluate.  Can support NT and UPN formats.  
         Using the values '(current_user)' or leaving this parameter
         empty returns the SID of the current logged in user.
            
Output: String
Example: Get-CurrentLoggedonUser
        returns Chase Bradley
#>
function Get-UserSIDLookup{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$UsernameLookup
    )
        If($usernameLookup -eq "(current_user)" -or $UsernameLookup -eq ""){
            $usernameLookup = Get-CurrentLoggedonUser
        } 
        
        If($usernameLookup.Contains("\")){
            $usernameLookup = $usernameLookup.Split("\")[1];
        } Elseif ($usernameLookup.Contains("@")){
            $usernameLookup = $usernameLookup.Split("@")[0];
        }
        $User = New-Object System.Security.Principal.NTAccount($usernameLookup)
        Try{
            $sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value;
            return $sid;
        } Catch{
            $ErrorMessage = $_.Exception.Message;
            return ("Error:: " + $ErrorMessage);
        }
    
}

function Get-ReverseSID{
    Param([string]$SID,[bool]$ignoreGroups=$true)

    Try{
        
        $domainJoined = $false;
        $localmachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
        $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain;
        $domainJoined = (Get-CimInstance -Class CIM_ComputerSystem).PartOfDomain
        if($domainJoined){
            $domain = $localmachine;
        }


        $newSID = Get-WmiObject -Class Win32_UserAccount -Filter ("SID='" + $SID + "'") -ErrorAction Stop;
        if(($newSID | Measure).Count -eq 0 -and $ignoreGroups){
            return "Error:: User not found"
        } elseif (($newSID | Measure).Count -eq 0 -and !$ignoreGroups){
            $newSID = Get-WmiObject -Class Win32_Group -Filter ("SID='" + $SID + "'") -ErrorAction Stop;
        }

        if($newSID){     
            if($domain.ToLower().Contains($newSID.domain.ToLower())){
                #Local user, just return the username
                return $newSID.Name;
            } else {
                #Domain user, just return the username
                return $newSID.Caption;
            }
        }
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        return ("Error:: " + $ErrorMessage);
    }
}

<#
Function: Get-GroupMemberShipStatus
Author  : cbradley@vmware.com
Description : Gets an SID lookup of a user based on username 
Input Params:  
        .PARAMETER  'UsernameLookup'
		 
            
Output: String
Example: 
#>
Function Get-UserGroup{
    param([string]$Name,[string]$Domain)
    
    $LocalMachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
    If($Name -match "([^\\]*)\\(.*)"){
        If($Matches[1] -eq "." -or $Matches[1] -eq "local"){
            $Group = Get-WmiObject -Class Win32_Group | Where {$_.Name -eq $Name -and $_.Domain -eq $LocalMachine};
        } Else{
            $Group = Get-WmiObject -Class Win32_Group | Where {$_.Name -eq $Name -and $_.Domain -eq $Matches[2]};
        }
    } ElseIf($Name -match "[^\\]*"){
        If($Domain){
            $Group = Get-WmiObject -Class Win32_Group | Where {$_.Name -eq $Name -and $_.Domain -eq $Domain};
        } Else {
            $Group = Get-WmiObject -Class Win32_Group | Where {$_.Name -eq $Name -and $_.Domain -eq $LocalMachine};
        }
    }
    return $Group;
}

<#
Function: Get-GroupMemberShipStatus
Author  : cbradley@vmware.com
Description : Gets an SID lookup of a user based on username 
Input Params:  
        .PARAMETER  'UsernameLookup'
		 
            
Output: String
Example: 
#>
Function Get-GroupMembershipStatus{
    param([string]$Username, [string]$UserDomain, [string]$Group, [string]$GroupDomain)

    $LocalMachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
    if(!$GroupDomain){
        $GroupDomain = $LocalMachine;
    } elseif($GroupDomain -eq "local"){
        $GroupDomain = $LocalMachine;
    }

    if(!$UserDomain){
        $UserDomain = $LocalMachine;
    } elseif($UserDomain -eq "local"){
        $UserDomain = $LocalMachine;
    }
    $GroupLookup = (Get-CimInstance "Win32_GroupUser") | where {$_.GroupComponent.Name -EQ $Group};
    $GroupCount = (($GroupLookup | Select-Object {$_.GroupComponent.Name}, {$_.GroupComponent.Domain} -Unique) | Measure);
    if($GroupCount.Count -gt 1){
        $GroupLookup = $GroupLookup | where {$_.GroupComponent.Domain -eq "GroupDomain"};
        $GroupCount = (($GroupLookup | Select-Object {$_.GroupComponent.Name}, {$_.GroupComponent.Domain} -Unique) | Measure);
    }
    if($GroupCount.Count -eq 1){
        $UserLookup = $GroupLookup | where {$_.PartComponent.Name -EQ $Username -and $_.PartComponent.Domain -EQ $UserDomain}
        if($UserLookup){
            return $true;
        }
    }
    return $false;
}

Function Get-AllKnownUsers{
     $ExceptionUsers = @("$LocalMachine\DefaultAccount","$LocalMachine\Administrator")
     $AllUsers = (Get-CimInstance "Win32_GroupUser") | Select-Object @{Name="Name";Expression={$_.PartComponent.Name}},
            @{Name="Domain";Expression={$_.PartComponent.Domain}},
            @{Name="FullName";Expression={$_.PartComponent.Domain + "\" + $_.PartComponent.Name}},
            @{Name="AccountType";Expression={ If($_.PartComponent.ToString() -match "([^\(]*)\(.*"){ $Matches[1].Trim()  }}} -Unique |
            Where {$_.AccountType -like "Win32_UserAccount" -and $_.Username -notin $ExceptionUsers};
     return $AllUsers;
}

Function Get-UsersInGroup{
    param([string]$Group, [string]$GroupDomain, [array]$Users,
         [ValidateSet("IN","NOTIN")]       
         [string]$SearchType="IN")

    $LocalMachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
    if(!$GroupDomain){
        $GroupDomain = $LocalMachine;
    } elseif($GroupDomain -eq "local"){
        $GroupDomain = $LocalMachine;
    }

    $GroupLookup = (Get-CimInstance "Win32_GroupUser") | where {$_.GroupComponent.Name -EQ $Group};   
    $GroupCount = (($GroupLookup | Select-Object {$_.GroupComponent.Name}, {$_.GroupComponent.Domain} -Unique) | Measure);
    if($GroupCount.Count -gt 1){
        $GroupLookup = $GroupLookup | where {$_.GroupComponent.Domain -eq "GroupDomain"};
        $GroupCount = (($GroupLookup | Select-Object {$_.GroupComponent.Name}, {$_.GroupComponent.Domain} -Unique) | Measure);
    }
    $UserList = $Users;
    if($GroupCount.Count -eq 1){
        $GroupUserList = $GroupLookup | select @{Name="FullName";Expression={$_.PartComponent.Domain + "\" + $_.PartComponent.Name}},
            @{Name="AccountType";Expression={ If($_.PartComponent.ToString() -match "([^\(]*)\(.*"){ $Matches[1].Trim()  }}} |
            Where {$_.AccountType -like "Win32_UserAccount"};
       
        If($SearchType -EQ "NOTIN"){
            $UserList = $Users | Where {$_.FullName -notin ($GroupUserList | select FullName).FullName};
        } Else{
            $UserList = $Users | Where {$_.FullName -in ($GroupUserList | select FullName).FullName};
        }
        
        return $UserList;
    }
    If($SearchType -EQ "IN"){
       $UserList = @(); 
    }
    return $UsersList;
}

<#
Function: Get-PhysicalTaskInfo
Author  : cbradley@vmware.com
Description : Gets the phyiscal components of a ScheduledTask object
Input Params:  
        .PARAMETER  'Path'
		 Location of the scheduled task
        .PARAMETER  'Name'
         Name of the scheduled task
            
Output: String

#>

Function Get-TaskPhysicalInfo{
    Param(
        [string]$Path,
        [string]$Name
    )
    $TaskInfo = New-Object PSCustomObject -Property @{"Name"=$Name;"Path"=$Path;"FullPath"="";"RegistryPath"="";"RegistryInfoPath"=""};
    if(Test-Path "$env:SystemRoot\System32\Tasks$Path$Name"){
        $TaskInfo.FullPath = "$env:SystemRoot\System32\Tasks$Path$Name"
        if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree$Path$Name"){
            $TaskInfo.RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree$Path$Name";
        
            $TaskBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
            $RegKey = Get-ChildItem $TaskBase | Where {(Get-ItemPropertyValue -Path $_.PSPath -Name "Path") -eq "$Path$Name"}
            if(($RegKey | Measure).Count -eq 1){
                $TaskInfo.RegistryInfoPath = $RegKey.PSPath;
                return $TaskInfo;
            } 
        }
    }
    return "";
}

function Get-AdvancedCIMSearch{
    [CmdletBinding(DefaultParameterSetName="WO")]
    Param(
         [Parameter(Mandatory=$true)]
         [ValidateNotNullOrEmpty()]    
         [object]$CIMObject,
         [Parameter(Mandatory=$true)]
         [ValidateNotNullOrEmpty()] 
         [string]$InstructionType,
         [Parameter(Mandatory=$true,ParameterSetName="WO")]
         [ValidateNotNullOrEmpty()] 
         [string]$ScriptBlock, 
         [Parameter(Mandatory=$true,ParameterSetName="SO")]
         [ValidateNotNullOrEmpty()] 
         [string]$PropertyName,
         [Parameter(Mandatory=$true,ParameterSetName="SO")]
         [ValidateNotNullOrEmpty()] 
         [string]$PropertyExpression
    )
    if($InstructionType -eq "Where-Object"){
        $WhereBlock = [scriptblock]::Create( $ScriptBlock )
        return $CIMObject | Where-Object -FilterScript $WhereBlock;
    } elseif ($InstructionType -eq "Select-Object"){
        $PropertyScriptBlock = [scriptblock]::Create( $PropertyExpression )
        return $CIMObject | Select-Object *,@{ Name = $PropertyName;Expression = $PropertyScriptBlock}
    }
}

function ConvertTo-DateTime{
    param([string]$Time, [datetime]$TimeSpanBase)
    #Accepted formats for date and time
    If($Time -eq "Now" -or !($Time)){
        #Support Now for DateTime
        return Get-Date;
    } ElseIf($Time -match "([1-9]{1}[0-9]{0,6})(s|m|h|d)" -and $TimeSpanBase){
        #Suppoerts short hand {number}{unit} for example 60s = 60 seconds
        if($Matches[2] -eq "s"){
            $TS = New-TimeSpan -Seconds $Matches[1]
        } elseif($Matches[2] -eq "m"){
            $TS = New-TimeSpan -Minutes $Matches[1]
        } elseif($Matches[2] -eq "h"){
            $TS = New-TimeSpan -Hours $Matches[1]
        } elseif($Matches[2] -eq "d"){
            $TS = New-TimeSpan -Days $Matches[1]
        } else{
            $TS = New-TimeSpan -Minutes 5
        }
        $EndTime = ($TimeSpanBase).Add($TS);
        return $EndTime;
    } Else {
        Try{
            $DateTimeConverter = [datetime]$Time;
            return $DateTimeConverter;
        } Catch {
            $ErrorMessage = $_.Exception.Message;
            Write-Log2 -Path $logLocation -Message "An error has occured: $ErrorMessage";
        }
    }
    return;
}

function Invoke-UnzipFile {
    param([string]$zipfile, [string]$outpath)
	#Initialize Zip processes
	Add-Type -AssemblyName System.IO.Compression.FileSystem
	[System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}
