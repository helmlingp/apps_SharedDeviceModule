#############################################
# File: AirWatchAPI.psm1
# Author: Chase Bradley
# Modified by Phil Helmling: 30 March 2021, updated to support User Based Profiles
# Modified by Phil Helmling: 6 December 2020, optimised and restructured to reduce API calls
#############################################
$Debug=$false
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Reg";
}

$shared_path = $Global:shared_path;
#$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$Global:log_path\AirWatchAPI.log"; 

function Invoke-SecureWebRequest{
    param([string]$Endpoint, [string]$Method="GET", $ApiVersion=1, $Data, [bool]$Debug, [string]$SSLThumbPrint, [string]$Server, [string]$OrganizationGroupId, [string]$API_Key, [string]$Auth, [string]$DeviceId)
	
    #$Private:api_settings_obj = Get-AWAPIConfiguration; #done once in main program
	#$SSLThumbprint = $Private:api_settings_obj.ApiConfig.SSLThumbprint;
	If($Debug) { Write-host "Entered Invoke-SecureWebRequest with Server/Endpoint: $Server/$Endpoint and $SSLThumbprint and $DeviceId"}
	$Endpoint = $Endpoint.Replace("{DeviceId}",$DeviceId).Replace("{OrganizationGroupId}",$OrganizationGroupId);

    Try
    {
        # Create web request
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		$WebRequest = [System.Net.WebRequest]::Create("$Server/$Endpoint")
		If($Debug) { Write-host "webrequest create: $Server/$Endpoint" }
		$WebRequest.Method = $Method;

        #Setting Private Headers
        #$WebRequest.Headers.Add("aw-tenant-code",$Private:api_settings_obj.ApiConfig.ApiKey);
        #$WebRequest.Headers.Add("Authorization",$Private:api_settings_obj.ApiConfig.ApiAuth);
        $WebRequest.Headers.Add("aw-tenant-code",$API_Key);
        $WebRequest.Headers.Add("Authorization",$Auth);
		
        #Setting Content
        $WebRequest.Accept = "application/json;version=$ApiVersion";
        $WebRequest.ContentType = "application/json;version=$ApiVersion";  
    
        #Data stream 
        If($Data) {
            $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($Data);
            $WebRequest.ContentLength = $ByteArray.Length;  
            $Stream = $WebRequest.GetRequestStream();
            Try{              
                $Stream.Write($ByteArray, 0, $ByteArray.Length);   
            } Catch {
                $Error = $_.Exception.Message; 
            } Finally{
                $Stream.Close();
            }
        } Else {
            $WebRequest.ContentLength = 0;
        }

        # Set the callback to check for null certificate and thumbprint matching.
        $WebRequest.ServerCertificateValidationCallback = {
            #$ThumbPrint = $SSLThumbprint;
            
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$args[1]
            #Write-Log2 -Path "$logLocation" -Message "certificate: $certificate" -Level Info
            If ($certificate -eq $null) {
                Write-Log2 -Path "$logLocation" -Message "no cert" -Level WARN
                return $false
            }

            #If (($certificate.Thumbprint -eq $ThumbPrint) -and ($certificate.SubjectName.Name -ne $certificate.IssuerName.Name))
            If ($certificate.Thumbprint -eq $SSLThumbprint) { #-and ($certificate.SubjectName.Name -ne $certificate.IssuerName.Name))
                If($Debug) { Write-Log2 -Path "$logLocation" -Message "Certificate is good" -Level Info }
                return $true
            }
            If($Debug) { Write-Log2 -Path "$logLocation" -Message "Certificate is no good" -Level WARN }
            return $false
        }

        # Get response stream
        $Response = $webrequest.GetResponse();
        $ResponseStream = $webrequest.GetResponse().GetResponseStream()

        # Create a stream reader and read the stream returning the string value.
        $StreamReader = New-Object System.IO.StreamReader -ArgumentList $ResponseStream
        
        Try{
            $Content = $StreamReader.ReadToEnd();
        } Catch {
            $Error = $_.Exception.Message;
        } Finally{
            $StreamReader.Close();
        }

        $CustomWebResponse = $Response | Select-Object Headers, ContentLength, ContentType, CharacterSet, LastModified, ResponseUri,
            @{N='StatusCode';E={$_.StatusCode.value__}},@{N='Content';E={$Content}}

        return $CustomWebResponse;
    }
    Catch
    {
        If($Debug){ Write-Log2 -Path $logLocation -Message "Failed: $($_.exception.innerexception.message)" -Level Error }
        $StatusCode = $_.Exception.InnerException.Response.StatusCode.value__;
        If(!($StatusCode)){
            $StatusCode = 999;
            $Content = $_.Exception.InnerException.Message;
        } ElseIf($_.Exception.InnerException.StatusCode.value__){
            $StatusCode = 999;
            $Content = $_.Exception.InnerException.Message;
        }
        return New-Object -TypeName PSCustomObject -Property @{"StatusCode"=$StatusCode;"Content"=$Content}
    } 

}

function Invoke-PrivateWebRequest{
    param([string]$Endpoint, $Method="Get", $ApiVersion=1, $Data, [bool]$Debug, [string]$SSLThumbPrint, [string]$Server, [string]$OrganizationGroupId, [string]$API_Key, [string]$Auth, [string]$DeviceId)
    
	If($Debug){ Write-Log2 -Path "$logLocation" -Message "Entered Invoke-PrivateWebRequest with Server/Endpoint: $Server/$Endpoint" -Level Info }
    $Endpoint = $Endpoint.Replace("{DeviceId}",$DeviceId).Replace("{OrganizationGroupId}",$OrganizationGroupId);
    $WebRequest = $null;
    if($Data){
        Try {
            $WebRequest = Invoke-WebRequest -Uri ("$Server/$Endpoint") -Method $Method -Body $Data -UseBasicParsing -Headers @{'aw-tenant-code' = $API_Key;'Authorization' = $Auth;'accept' = "application/json;version=$ApiVersion";'Content-Type' = 'application/json'}
            If($Debug){ Write-Log2 -Path "$logLocation" -message "WebRequest: $WebRequest" -Level Info}
        } Catch{
            $ErrorMessage = $_.Exception.Message;
            If($Debug){ Write-Log2 -Path "$logLocation" -Message "An error has occurrred.  Error: $ErrorMessage"  -Level Info}
            if($_.Exception -like "Unable to connect to the remote server"){
                return "Offline";
            } 
        }
    } else {
        Try {
            $WebRequest = Invoke-WebRequest -Uri ("$Server/$Endpoint") -Method $Method -UseBasicParsing -Headers @{'aw-tenant-code' = $API_Key;'Authorization' = $Auth;'accept' = "application/json;version=$ApiVersion";'Content-Type' = 'application/json'}
            If($Debug){ Write-Log2 -Path "$logLocation" -message "WebRequest: $WebRequest" -Level Info}
        } Catch{
            $ErrorMessage = $_.Exception.Message;
            If($Debug){ Write-Log2 -Path "$logLocation" -Message "An error has occurrred.  Error: $ErrorMessage"  -Level Info}
            if($_.Exception -like "Unable to connect to the remote server"){
                return "Offline";
            } 
        }
    }
     <# Finally{
        $Private:api_settings_obj = $null;
    } #>

    return $WebRequest;
}

function Get-NewDeviceId{
	param($Data, [bool]$Debug, [string]$SSLThumbPrint, [string]$Server, [string]$OrganizationGroupId, [string]$API_Key, [string]$Auth)

    $serialSearch = wmic bios get serialnumber;
    $serialnumber = $serialSearch[2];
    $serialnumber = $serialnumber.Trim();
	$serialEncoded = [System.Web.HttpUtility]::UrlEncode($serialnumber);
    $deviceSearchEndpoint = "api/mdm/devices?searchBy=Serialnumber&id=$serialEncoded";
	
	If($Debug){
		Write-Log2 -Path "$logLocation" -Message "Entered Get-NewDeviceId" -Level Info
		Write-Log2 -Path "$logLocation" -Message "-----------------------" -Level Info
		Write-Log2 -Path "$logLocation" -Message "serialnumber: $serialnumber" -Level Info
		Write-Log2 -Path "$logLocation" -Message "SSLThumbprint: $SSLThumbprint" -Level Info
	}
	
    If($SSLThumbprint){      
		$WebResponse = Invoke-SecureWebRequest -Endpoint $deviceSearchEndpoint -Method "GET" -ApiVersion 1 -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -API_Key $API_Key -Auth $Auth
    } Else {
		$WebResponse = Invoke-PrivateWebRequest -Endpoint $deviceSearchEndpoint -Method "GET" -ApiVersion 1 -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -API_Key $API_Key -Auth $Auth
    }
		
    If($WebResponse.StatusCode -lt 300){
        If($WebResponse.Content){
            $device_json = ConvertFrom-Json($WebResponse.Content)

        }
    }

    return $device_json
}

function Invoke-AWApiCommand{
    param([string]$Endpoint, [string]$Method="GET", $ApiVersion=1, $Data, [bool]$Debug, [string]$SSLThumbPrint, [string]$Server, [string]$OrganizationGroupId, [string]$API_Key, [string]$Auth, [string]$DeviceId)
    #$loglocation = "C:\ProgramData\Airwatch\Logs\test.log"
	
	If($Debug){
		Write-Log2 -Path "$logLocation" -Message "Entered Invoke-AWApiCommand with endpoint: $Endpoint" -Level Info
		Write-Log2 -Path "$logLocation" -Message "---------------------------------------------------------------------------" -Level Info
	}
    #Return Object set
    $ReturnObjectSet = @();

	If($SSLThumbprint){
		#$Private:api_settings_obj = $null;
		$WebRequest = Invoke-SecureWebRequest -Endpoint $Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth -DeviceId $DeviceId
		#$Mode = 1;
	} Else{
		#$Private:api_settings_obj = $null;
		write-host "invoking PrivateWebRequest with $Server/$Endpoint"
		$WebRequest = Invoke-PrivateWebRequest -Endpoint $Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth -DeviceId $DeviceId
	}

	If($Debug){
		Write-Log2 -Path "$logLocation" -Message "Connecting to: $Endpoint";
		If($WebRequest.Content){
			Write-Log2 -Path "$logLocation" -Message $WebRequest.Content;
		}
    }	

    Try{ 
        if($WebRequest.StatusCode -lt 300){
			$ReturnObj = New-Object -TypeName PSCustomObject -Property @{"StatusCode"=$WebRequest.StatusCode};
			If($WebRequest.Content){
			   $ReturnObj = ConvertFrom-Json($WebRequest.Content); 
			   if($ReturnObj.Total){
					if($ReturnObj.Total -gt ($ReturnObj.PageSize * ($ReturnObj.Page + 1)) -and $ReturnObj.PageSize -gt 0){
						$ReturnObjectSet += $ReturnObj;
						While($ReturnObj.Total -gt ($ReturnObj.PageSize * $ReturnObj.Page)){
							If($Endpoint -match "([^?]*)\?"){
								$Page_Endpoint = $Endpoint + "&page=" + ($ReturnObj.Page + 1).ToString();
								Write-Log2 -Path "$logLocation" -Message -Message $Page_Endpoint;
							} Else{
								$Page_Endpoint = $Endpoint + "?page=" + ($ReturnObj.Page + 1).ToString();
								Write-Log2 -Path "$logLocation" -Message -Message $Page_Endpoint;
							}

							#If($Mode -eq 1){
							If($SSLThumbprint){
								$WebRequest = Invoke-SecureWebRequest -Endpoint $Page_Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth -DeviceId $DeviceId
							} Else {
								$WebRequest = Invoke-PrivateWebRequest -Endpoint $Page_Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth -DeviceId $DeviceId
							}
							if($WebRequest.StatusCode -eq 200){
								 $ReturnObj += (ConvertFrom-Json($WebRequest.Content)); 
							}
						}
					}
				}
			}
			
			return $ReturnObj;
	
        } Else {
			return $WebRequest.Content;
        }
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        return (New-Object -TypeName PSCustomObject -Property @{"Error"="$ErrorMessage"});
    }
}

Export-ModuleMember -Function Get-NewDeviceId, Invoke-AWApiCommand
