#############################################
# File: AWLogon.ps1
# Author: Chase Bradley
# Modified by Phil Helmling: 30 March 2021, updated to support User Based Profiles
# Modified by Phil Helmling: 27 Nov 2019, optimised to use $device_info more instead of API lookups
# Modified by: Phil Helmling 08 Aug 2019, restructure for optimised flow and add "Current" LogonGroup condition - don't move device
#
# Reassigns a Shared Device to logged in user and Moves OG if needed. Can specify "LogonGroup":"Current" in shared.config to leave device in same OG
#############################################


$debug = $false

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #default path
    $current_path = "C:\Temp\UserManagement";
}

$InstallPath = "HKLM:\Software\AIRWATCH\ProductProvisioning"; # default path if property not set

# default path
$shared_path = "C:\Temp\Shared"
If(Test-Path $InstallPath){
    $getShared_path = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -eq "SharedPath") | Measure;
    If($getShared_path.Count -gt 0){
        $shared_path = Get-ItemPropertyValue -Path $InstallPath -Name "SharedPath"; 
    }
} 

#import support modules
$GlobalModules = @();
#$GlobalImporter = @("$shared_path\Database-Management.psm1", "$shared_path\Security-Functions.psm1", "$shared_path\AirWatchAPI.psm1", "$shared_path\Utility-Functions.psm1");
$GlobalImporter = @("$shared_path\AirWatchAPI.psm1", "$shared_path\Utility-Functions.psm1");
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force
}

$shared_path = "C:\Temp\Shared"; # default path if property not set
$logLocation = "C:\Temp\Logs\UserManagement.log"; # default path if property not set
If(Test-Path $InstallPath){
    $getShared_path = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -eq "SharedPath") | Measure;
    If($getShared_path.Count -gt 0){
        $shared_path = Get-ItemPropertyValue -Path $InstallPath -Name "SharedPath";       
    }
	
	$getlog_path = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -eq "LogPath") | Measure;
	If($getlog_path.Count -gt 0){
        $log_path = Get-ItemPropertyValue -Path $InstallPath -Name "LogPath";
		$logLocation = "$log_path\UserManagement.log"; 
    }
}

#Sets the global Registry Install path
$Global:InstallPath = $InstallPath;

#Sets the global Shared Path location
$Global:shared_path = $shared_path;

#Sets the global Log Path location
$Global:log_path = $log_path;

#WS1 API endpoints
$device_endpoint = "api/mdm/devices/{DeviceId}/";
$change_user_endpoint = "/api/mdm/devices/{DeviceId}/enrollmentuser";
$user_search_endpoint = "/api/system/users/search";
$user_details_endpoint = "/api/system/users/";
$og_search_endpoint = "/api/system/groups/search";
$change_og_endpoint = "/api/mdm/devices/{DeviceId}/commands/changeorganizationgroup/";
$smartgroup_search = "/api/mdm/smartgroups/search";
$smartgroup_refresh = "/api/mdm/smartgroups";

function Get-AWAPIConfiguration{
	param([bool]$Debug)
	If($Debug) {
		Write-Log2 -Path "$logLocation" -Message "Get device attributes from api.config" -Level Info
		Write-Log2 -Path "$logLocation" -Message "---------------------------------------------------------------------------" -Level Info
	}
	if(Test-Path "$Global:shared_path\api-debug.config"){
		$script:useDebugConfig = $true;
		$script:Debug = $true;
	}
	#Read api.config file and return as object
	if(!$useDebugConfig){
        $Private:api_config_file = [IO.File]::ReadAllText("$Global:shared_path\api.config");
		If ($Debug) { Write-Log2 -Path "$logLocation" -Message "api_config_file: $Global:shared_path\api.config" -Level Info }
		#Encrypt api.config if not already (test to read if 'ApiConfig' exists)
        if($Private:api_config_file.Contains('"ApiConfig"')){
            $Private:api_settings = $Private:api_config_file;
            $encrypted = ConvertTo-EncryptedFile -FileContents $Private:api_config_file;
            if($encrypted){
                Set-Content -Path ("$Global:shared_path\api.config") -Value $encrypted;
            }
        } else {
			#If already enrypted, read into ConvertFrom-EncryptedFile function to decrypt
			$Private:api_settings = ConvertFrom-EncryptedFile -FileContents $Private:api_config_file;
        }
		
    } else {
        If ($Debug) { Write-Log2 -Path "$logLocation" -Message "api-debug.config_file: $Global:shared_path\api-debug.config" -Level Info }
		$Private:api_config_file = [IO.File]::ReadAllText("$Global:shared_path\api-debug.config");
        $Private:api_settings = $Private:api_config_file;
    }
    $Private:api_settings_obj = ConvertFrom-Json -InputObject $Private:api_settings
	
    $content_type = "application/json;version=1";
    $content_type_v2 = "application/json;version=2";

	$Script:Server =  $Private:api_settings_obj.ApiConfig.Server;
	If ($Debug) { write-host "Server: $Script:Server" }
	$Script:API_Key = $Private:api_settings_obj.ApiConfig.ApiKey;
	If ($Debug) { write-host "API_Key: $Script:API_Key" }
	$Script:Auth = $Private:api_settings_obj.ApiConfig.ApiAuth;
	If ($Debug) { write-host "Auth: $Script:Auth" }
	$Script:OrganizationGroupId = $Private:api_settings_obj.ApiConfig.OrganizationGroupId;
	If ($Debug) { write-host "OrganizationGroupId: $Script:OrganizationGroupId" }
	$Script:OrganizationGroupName = $Private:api_settings_obj.ApiConfig.OrganizationGroupName
	If ($Debug) { write-host "OrganizationGroupName: $Script:OrganizationGroupName" }
	$Script:DeviceId = $Private:api_settings_obj.ApiConfig.DeviceId
	If ($Debug) { write-host "DeviceId: $Script:DeviceId" }
    
    #If DeviceId property doesn't exist in the api.config file then add it
    If(![bool]$Script:DeviceId) {
        $Private:api_settings_obj.ApiConfig | Add-Member -MemberType NoteProperty -Name "DeviceId" -Value -1;
		If ($Debug) { Write-Log2 -Path "$logLocation" -Message "add DeviceId as property" -Level Info }
    }
	#If OrganizationGroupName property doesn't exist in the api.config file then add it
	If(![bool]$Script:OrganizationGroupName) {
		$Private:api_settings_obj.ApiConfig | Add-Member -MemberType NoteProperty -Name "OrganizationGroupName" -Value "OrgName";
		If ($Debug) { Write-Log2 -Path "$logLocation" -Message "add OrganizationGroupName as property" -Level Info }
    }
    return $api_settings_obj;
}

#Load the shared.config file
Try {
    $SharedConfigFile = [IO.File]::ReadAllText("$current_path\shared.config");
    $SharedConfig = ConvertFrom-Json -InputObject $SharedConfigFile;
} Catch {
    $m = "Could not parse config file";
    Write-Log2 -Path $logLocation -Message $m -Level Error
    Throw $m;
}

#Load api.config file
$script:api_settings_obj = Get-AWAPIConfiguration -Debug $true

#Get device attributes
If($DeviceId -eq ""){
	$device_info = Get-NewDeviceId -Debug $True -Server $Script:Server -OrganizationGroupId $Script:OrganizationGroupId -API_Key $Script:API_Key -Auth $Script:Auth
	#write-host $device_info
	If ($device_info.EnrollmentStatus -ne "Enrolled"){
		Write-Log2 -Path $logLocation -Message "Device is Unenrolled" -Level Error
	}
	$DeviceId = $device_info.Id.Value
	$Private:api_settings_obj.ApiConfig.DeviceId = $DeviceId;
	#Save the Device id
	$apicontent = ConvertTo-Json $Private:api_settings_obj -Depth 10;
	If(!$useDebugConfig){
		$apiencryptedcontent = ConvertTo-EncryptedFile -FileContents $apicontent
		Set-Content "$shared_path\api.config" -Value $apiencryptedcontent
	} Else {
		Set-Content "$shared_path\api-debug.config" -Value $apicontent
		If ($Debug) { Write-Log2 -Path $logLocation -Message  "saving api-debug.config" -Level Info }
	}
} else {
	$device_info = Invoke-AWApiCommand -Endpoint $device_endpoint -Debug $True -Server $Script:Server -OrganizationGroupId $Script:OrganizationGroupId -API_Key $Script:API_Key -Auth $Script:Auth -DeviceId $Script:DeviceId
	#write-host $device_info
	If ($device_info.EnrollmentStatus -ne "Enrolled"){
		Write-Log2 -Path $logLocation -Message "Device is Unenrolled" -Level Error
	}
	$DeviceId = $device_info.Id.Value
}

If($OrganizationGroupName -eq ""){
	$OrganizationGroupName = $device_info.$LocationGroupName
    If ($Debug) { Write-Log2 -Path $logLocation -Message  "OrganizationGroupName: $OrganizationGroupName" -Level Info }
	$Private:api_settings_obj.ApiConfig.OrganizationGroupName = $OrganizationGroupName;
	#Save the Device id
	$apicontent = ConvertTo-Json $Private:api_settings_obj -Depth 10;
	If(!$useDebugConfig){
		$apiencryptedcontent = ConvertTo-EncryptedFile -FileContents $apicontent
		Set-Content "$shared_path\api.config" -Value $apiencryptedcontent
	} Else {
		Set-Content "$shared_path\api-debug.config" -Value $apicontent
		If ($Debug) { Write-Log2 -Path $logLocation -Message  "saving api-debug.config" -Level Info }
	}
}

if (!$device_info){
    Write-Log2 -Path $logLocation -Message "Could not get device_info. Check API connection & AirWatchAPI.log" -Level Error
}

#Get Current Logged on User from Windows
$CurrentUsername = ""
$CurrentUserLookup = Get-CurrentLoggedonUser
$CurrentUsername = $CurrentUserLookup.username 
$CurrentUserSID = $CurrentUserLookup.SID
$CurrentUserUPN = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$CurrentUserSID\IdentityCache\$CurrentUserSID" -Name “UserName”

if ($debug){
    Write-Log2 -Path $logLocation -Message "$CurrentUserLookup" -Level Info
    Write-Log2 -Path $logLocation -Message "Current User UPN: $currentUserUPN" -Level Info
    Write-Log2 -Path $logLocation -Message "Current UserName: $CurrentUsername with SID: $CurrentUserSID" -Level Info
}

$deviceshared = $device_info.Ownership
#if device is not shared, don't do anything
if ($deviceshared -eq "S") {
    if ($debug){ Write-Log2 -Path $logLocation -Message "Device is Corporate Shared" -Level Info }
    $deviceusername = $device_info.UserName
    if ($deviceusername -ne $CurrentUsername) {
        #change user
        #if device is assigned to another user ie has been checked out to someone else, then change user and move OG to force refresh
        if($debug){ Write-Log2 -Path $logLocation -Message "Device is Shared and not assigned to UserName $CurrentUsername" -Level Info }

        #is user in WS1 directory?
        $user_search = Invoke-AWApiCommand -Endpoint "$user_search_endpoint`?username=$CurrentUsername" -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth
		$user = $user_search.Users.UserName
        if($debug){ Write-Log2 -Path $logLocation -Message "User is in WS1 $user" -Level Info }

        #is user domain user?
        If($user_search){
            $domainUsers = $user_search.Users | where {$_.SecurityType -ne 0}
            If(($domainUsers | measure).Count -eq 1){
                $CurrentUserId = $domainUsers[0].Id.Value;
                if($debug){ Write-Log2 -Path $logLocation -Message "User $CurrentUsername is Domain User $CurrentUserId" -Level Info }
            }

            If($CurrentUserId){
                #change user on device
				#$change_user_endpoint = "/api/mdm/devices/$DeviceId/enrollmentuser";
				$endpoint = "/api/mdm/devices/" + $DeviceId + "/enrollmentuser/"+$CurrentUserId
				#write-host $endpoint
                $change_users = Invoke-AWApiCommand -Endpoint $endpoint -Method "PATCH" -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth
                if($change_users){

                    $enrolid = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*" -ErrorAction SilentlyContinue).PSChildname
                    foreach ($row in $enrolid) {
                        $enrollmentspath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$row"
                        $upn = (Get-ItemProperty -Path $enrollmentspath -ErrorAction SilentlyContinue).UPN
                        $EnrollmentState = (Get-ItemProperty -Path $enrollmentspath -ErrorAction SilentlyContinue).EnrollmentState
                        $providerID = (Get-ItemProperty -Path $enrollmentspath -ErrorAction SilentlyContinue).ProviderID
                        
                        if ($EnrollmentState -eq "1" -and $upn -and $providerID -eq "AirWatchMDM"){
                            if($upn -ne $currentUserUPN){
                                New-ItemProperty -Path $enrollmentspath -Name "UPN" -Type String -Value $currentUserUPN -ErrorAction SilentlyContinue -Force;
                                New-ItemProperty -Path $enrollmentspath -Name "SID" -Type String -Value $currentUserSID -ErrorAction SilentlyContinue -Force;
                            }
                        }
                        
                        if($debug){
                            $newUPN = Get-ItemPropertyValue -Path $enrollmentspath -Name "UPN"
                            $newsid = Get-ItemPropertyValue -Path $enrollmentspath -Name "SID"
                            Write-Log2 -Path $logLocation -Message "New Enrollment UPN $newupn & SID $newsid" -Level Info
                        }
                    }
                    
                    #List Profiles assigned to Device
                    $endpoint = "/API/mdm/devices/$DeviceId/profiles"
                    $profiles = Invoke-AWApiCommand -Endpoint $endpoint -Method "GET" -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth
                    $deviceprofiles = $profiles | Select-Object -ExpandProperty DeviceProfiles
                    $deviceprofilesIDs = $deviceprofiles | Select-Object -ExpandProperty Id | Select-Object -Property Value

                    #List User Based Profiles in OG
                    $endpoint = "/API/mdm/profiles/search?organizationgroupid=$OrganizationGroupId&platform=WinRT&includeandroidforwork=false&pagesize=10000"
                    $allProfiles = Invoke-AWApiCommand -Endpoint $endpoint -Method "GET" -ApiVersion 2 -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth
                    $UserBaseProfiles = $allProfiles | Select-Object -ExpandProperty ProfileList | Where-Object {$_.Context -eq "User"}
                    $UserBaseProfilesIDs = $UserBaseProfiles | Select-Object -ExpandProperty ProfileId

                    #build array of Profile IDs on the device that are User Based Profiles so we can install them
                    $deviceUserBaseProfileIDs = $deviceprofilesIDs | where-object {$UserBaseProfilesIDs -contains $_.Value}
                    #Match User Base Profiles and Install them
                    sleep 10
                    foreach ($profile in $deviceUserBaseProfileIDs) {
                        $profileID = $profile.Value
                        $endpoint = "/API/mdm/profiles/$profileID/install"
                        $JSON = @{"DeviceId"=$DeviceId} | ConvertTo-Json
                        If ($Debug) { Write-Log2 -Path $logLocation -Message "Profile to reinstall: $profileID & JSON: $JSON" -Level Info }
                        
                        $reinstallProfile = Invoke-AWApiCommand -Endpoint $endpoint -Method "POST" -Data $JSON  -ApiVersion 1 -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth
                    }
                    sleep 10
                    #Force device to send sample which will update things like Certificate info in console.
                    $endpoint = "/API/mdm/devices/$DeviceId/commands?command=DeviceQuery"
                    $querydevice = Invoke-AWApiCommand -Endpoint $endpoint -Method "POST" -ApiVersion 1 -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth

                } else {
                    $m = "An error occured.  Not able to change users through API.";
                    Write-Log2 -Path $logLocation -Message $m -Level Error
                    Throw $m;
                }
            }
        }
    } else {
        #do nothing
        if($debug){
            Write-Log2 -Path $logLocation -Message "Device already assigned to Username $CurrentUsername so not changing user assignment" -Level Info
        }
    }

    #If shared.config LogonGroup is set to 'Current' then leave the device in the same OG - ie don't move it
    #First Get OG IDs for Logon and Logoff OGs set in shared.config
    $LogonGroup = $SharedConfig.SharedConfig.LogonGroup;
    if ($Debug) { Write-Log2 -Path $logLocation -Message "shared.config LogonGroup set to $LogonGroup" -Level Info }
    $LogoffGroup = $SharedConfig.SharedConfig.LogoffGroup;
    #If($LogonGroup -notlike "Current") {
    If($LogonGroup -ne "Current") {
        #$OrganizationGroupName = $device_info.LocationGroupName;
        If($OrganizationGroupName -eq $LogonGroup){
            #if device is already in Logon OG, then don't need to move OG
            if ($Debug) { Write-Log2 -Path $logLocation -Message "Device already in OG $LogonGroup so not moving OG" -Level Info }
        } else {
            #device is not in Logon OG so get OG IDs in order to do the OG move
            $endpoint = "$og_search_endpoint`?groupid=$LogonGroup"
            $Logon_OG_Search = Invoke-AWApiCommand -Endpoint $endpoint -ApiVersion 2 -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth
            If($Logon_OG_Search.OrganizationGroups){
                $LogonGroupIdNum = $Logon_OG_Search.OrganizationGroups[0].Id;
                if ($Debug) { Write-Log2 -Path $logLocation -Message "Logon Group $LogonGroup & ID $LogonGroupIdNum" -Level Info }
            }
            #Doublecheck the Logon / Logoff OG IDs
            If(!$LogonGroupIdNum){    
                Throw "An error occured getting the Logon/Logoff Group IDs";
            }

            $CurrentOrganizationGroupId = $device_info.LocationGroupId.Id.Value

            #Not sure if need to move out to Logoff OG before moving to Logon OG
            # If($CurrentOrganizationGroupId -ne $LogoffGroupIdNum){
            #     #move device to Logoff OG
            #     $OG_Switch = Invoke-AWApiCommand -Method Put -Endpoint ($change_og_endpoint + "$LogoffGroupIdNum")     
            # }

            #Basically puts device back into checkin position
            If($CurrentOrganizationGroupId -ne $LogonGroupIdNum){
                #move device to Logon OG
                $OG_Switch = Invoke-AWApiCommand -Method Put -Endpoint ($change_og_endpoint + "$LogonGroupIdNum") -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth
                if ($Debug) { Write-Log2 -Path $logLocation -Message "Device moved to Logon OG" -Level Info }
            }
        }
    } else {
        if ($Debug) { Write-Log2 -Path $logLocation -Message "shared.config LogonGroup is set to 'Current' then leave the device in the same OG - ie don't move it" -Level Info }
    }
}
else {
    if ($Debug) { Write-Log2 -Path $logLocation -Message "Device Ownership is $device_info.Ownership / not 'Shared' so doing nothing" -Level Info }
}