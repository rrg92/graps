param($ResetStorage = $false)

#M�dulo para o powershell!
$ErrorActionPreference= "Stop";

## Global Var storing important values!
	if($Global:Graps_Storage -eq $null -or $ResetStorage){
		$Global:Graps_Storage = @{
				SESSIONS = @{}
				DEFAULT_SESSION = $null
			}
	}

#Auxiliar functions!
	Function verbose {
		$ParentName = (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name;
		write-verbose ( $ParentName +':'+ ($Args -Join ' '))
	}
	
	#Based on answer of Douglas in http://stackoverflow.com/a/25349901/4100116
	Function EscapeNonUnicodeJson {
		param([string]$Json)
		
		$Replacer = {
			param($m)
			
			return [string]::format('\u{0:x4}', [int]$m.Value[0] )
		}
		
		$RegEx = [regex]'[^\x00-\x7F]';
		write-verbose "EscapeNonUnicodeJson: Original Json: $Json";
		$ReplacedJSon = $RegEx.replace( $Json, $Replacer)
		write-verbose "EscapeNonUnicodeJson: NonUnicode Json: $ReplacedJson";
		return $ReplacedJSon;
	}

	#Converts objets to JSON and vice versa,
	Function ConvertToJson($o) {
		ConvertTo-Json $o -Compress -Depth 10;
	}

	Function ConvertFromJson([string]$json) {
		ConvertFrom-Json $json;
	}


#Make calls to a zabbix server url api.
	#Handle the zabbix server answers.
	#If the repsonse represents a error, a exception will be thrown. Otherwise, a object containing the response will be returned.
	Function TranslateHttpJson {
		param($Response)
		
		#Converts the response to a object.
		$ResponseObject = ConvertFromJson $Response;
		
		return $ResponseObject;
	}

	
	#Convert a datetime object to a unix time representation.
	Function Datetime2Unix {
		param([datetime]$Datetime)
		
		return $Datetime.toUniversalTime().Subtract([datetime]'1970-01-01').totalSeconds;
	}

	#Converts a unixtime representation to a datetime in local time.
	Function UnixTime2LocalTime {
		param([uint32]$unixts)
		
		return ([datetime]'1970-01-01').toUniversalTime().addSeconds($unixts).toLocalTime();
	}
	
	Function UrlEncode {
		param($Value)
		
		try {
			$Encoded = [System.Web.HttpUtility]::URLEncode($Value);
			return $Encoded;
		} catch {
			write-verbose "Failure on urlencode. Data:$Value. Error:$_";
			return $Value;
		}
	}
	
	#Converts a hashtable to a URLENCODED format to be send over HTTP requests.
	Function BuildURLEncoded {
		param($Data)
		
		$FinalString = @();
		$Data.GetEnumerator() | %{
			verbose "$($MyInvocation.InvocationName): Converting $($_.Key)..."
			$ParamName = UrlEncode $_.Key; 
			$ParamValue = UrlEncode $_.Value; 
		
			$FinalString += "$ParamName=$ParamValue";
		}

		$FinalString = $FinalString -Join "&";
		return $FinalString;
	}
	
	#Copies bytes from a stream to another!
	Function CopyToStream {
		param($From,$To)
		
		[Byte[]]$Buffer = New-Object Byte[](4096);
		$BytesRead = 0;
		while( ($BytesRead = $From.read($Buffer, 0,$Buffer.length)) -gt 0  ){
			$To.Write($buffer, 0, $BytesRead);
		}
	}

	#Makes a POST HTTP call and return cmdlet with the results.
	#This will return a object containing following:
	#	raw 		- The raw bytes of response content.
	#	html		- The html respponse, if contentType is text/html
	#	httpResponse - The original http response object!
	#	session	- The session data, to be used as the parameter "session" to simulate sessions!
	Function InvokeHttp {
		[CmdLetBinding()]
		param($URL, [hashtable]$data = @{}, $Session = $null, $method = 'POST', [switch]$AllowRedirect = $false)
		
		
		$Result = New-Object PsObject @{
			raw = $null
			html = $null
			httpResponse = $null
			session = @{cookies=$null}
		}
		
		$CookieContainer = New-Object Net.CookieContainer;
		
		if($Session){
			write-verbose "InvokeHttp: Session was informed. Importing cookies!"
			$Session.Cookies | ?{$_} | %{
					write-verbose "InvokeHttp: Cookie $($_.Name) imported!"
					$CookieContainer.add($_);
			}
		}
		
		try {
			$HttpRequest 					= [Net.WebRequest]::Create($URL);
			$HttpRequest.CookieContainer 	= $CookieContainer;
			$HttpRequest.Method 			= $method;
			$HttpRequest.AllowAutoRedirect 	= $AllowRedirect
			
			if($HttpRequest.method -eq 'POST'){
				write-verbose "InvokeHttp: Setiing up the POST headers!"
				$PostData 	= BuildURLEncoded $data
				write-verbose "InvokeHttp: Post data encoded is: $PostData"
				$PostBytes 	= [System.Text.Encoding]::UTF8.GetBytes($PostData)
				$HttpRequest.ContentType = 'application/x-www-form-urlencoded';
				$HttpRequest.ContentLength 	= $PostBytes.length;
				write-verbose "InvokeHttp: Post data length is: $($PostBytes.Length)"
				
				write-verbose "InvokeHttp: getting request stream to write post data..."
				$RequestStream					= $HttpRequest.GetRequestStream();
				try {
					write-verbose "InvokeHttp: writing the post data to request stream..."
					$RequestStream.Write($PostBytes, 0, $PostBytes.Length);
				} finally {
					write-verbose "InvokeHttp: disposing the request stream..."
					$RequestStream.Dispose();
				}
			}
			
			write-verbose "InvokeHttp: Calling the page..."
			$HttpResponse = $HttpRequest.getResponse();
			
			if($HttpResponse){
				write-verbose "InvokeHttp: Http response received. $($HttpResponse.ContentLength) bytes of $($HttpResponse.ContentType)"
				$Result.httpResponse = $HttpResponse;
				
				
				if($HttpResponse.Cookies){
					write-verbose "InvokeHttp: Generating response session!";
					$HttpResponse.Cookies | %{
						write-verbose "InvokeHttp: Updating path of cookie $($_.Name)";
						$_.Path = '/';
					}
					
					$Result.session = @{cookies=$HttpResponse.Cookies};
				}
				
				write-verbose "InvokeHttp: Getting response stream and read it..."
				$ResponseStream = $HttpResponse.GetResponseStream();
				
				write-verbose "InvokeHttp: Creating memory stream and storing bytes...";
				$MemoryStream = New-Object IO.MemoryStream;
				CopyToStream -From $ResponseStream -To $MemoryStream
				$ResponseStream.Dispose();
				$ResponseStream = $null;


				#If content type is text/html, then parse it!
				if($HttpResponse.contentType -like 'text/html;*'){
					write-verbose "InvokeHttp: Creating streamreader to parse html response..."
					$MemoryStream.Position = 0;
					$StreamReader = New-Object System.IO.StreamReader($MemoryStream);
					write-verbose "InvokeHttp: Reading the response stream!"
					$ResponseContent =  $StreamReader.ReadToEnd();
					write-verbose "InvokeHttp: Using HAP to load HTML..."
					$HAPHtml = New-Object HtmlAgilityPack.HtmlDocument
					$HAPHtml.LoadHtml($ResponseContent);
					$Result.html = $HAPHtml;
				}
				
				write-verbose "InvokeHttp: Copying bytes of result to raw content!";
				$MemoryStream.Position = 0;
				$Result.raw = $MemoryStream.toArray();
				$MemoryStream.Dispose();
				$MemoryStream = $null;
				
				 
			}
			
			return $Result;
		} catch {
			throw "INVOKE_HTTP_ERROR: $_"
		} finnaly {
			if($MemoryStream){
				$MemoryStream.Dispose();
			}
			
			if($StreamReader){
				$StreamReader.Dispose();
			}
			
			
			if($ResponseStream){
				$ResponseStream.close();
			}
		
			if($HttpResponse){
				$HttpResponse.close();
			}
			

		}
		
	}
	
	
	
		

##############################################33333
## Module session management
Function GetSlotHash {
	param($ClientID,$Tenant)
	
	return $ClientID+$Tenant;
}


function New-GrapSession {
	param(
		 $ClientID
		,$Tenant
		,$Secret
	)
	
	$Hash = GetSlotHash $ClientID $Tenant;
	
	$Sess = $Global:Graps_Storage.SESSIONS;
	$Slot = $Sess[$Hash]
	
	if(!$Slot){
		$Slot =  @{
			ClientID	= $ClientID
			Tenant		= $Tenant;
			Secret		= $Secret;
			AccessToken		= $null
			RefreshToken	= $null
			scope			= $null
			SlotHash		= $Hash
		}
		$Global:Graps_Storage.SESSIONS[$Hash] = $Slot;
	}
}

function Get-GrapDefaultSession {
	$Default 	= $Global:Graps_Storage.DEFAULT_SESSION;
	$Sessions	= $Global:Graps_Storage.SESSIONS;
	
	if($Default){
		return $Default;
	} else {
		if($Sessions.count -eq 1){
			return @($Sessions.Values)[0];
		} else {
			throw "NO_DEFAULT_SESSIONS"
		}
	}
	
}

function Set-GrapDefaultSession {
	param($Session)
	
	$Global:Graps_Storage.DEFAULT_SESSION = $Session;
}

function Get-GrapSessions {
	return $Global:Graps_Storage.SESSIONS;
}

##############################################33333
## MS RAP API IMPLEMENTATION
# Authenticates using device code!
function Connect-GrapDeviceCode {
	[CmdletBinding()]
	param(
		[string[]]$Scopes = '.default'
		
		,#Copies the code to clipboard
			[switch]$Clip = $false
	)
	
	$Session = Get-GrapDefaultSession;
	
	$ClientID 	= $Session.ClientID;
	$Tenant	= $Session.Tenant;
	
	if($Scopes -NotContains 'offline_access'){
		$Scopes += 'offline_access'
	}
	
	$Session.Scope = $Scopes -Join ' ';
	
	
	$ReqParameters = @{
		body = @{
			client_id = $ClientID
			scope = $Session.Scope
		}
		
		Uri = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/devicecode"
		Method = 'POST'
	}

	$Result  = Invoke-WebRequest @ReqParameters -Verbose;
	$JS = ConvertFrom-Json $Result;
	write-host $JS.message "Expire date:" ( (Get-Date).addSeconds($JS.expires_in) );
	
	if($Clip){
		$JS.user_code | clip;
		write-host "**User code copied to clipboard!**"
	}
	
	start ($JS.verification_uri + "?usercode=" + $JS.user_code)
	
	$PoolInterval = $JS.interval;
	
	# step 2 - pool token...
	$ReqParameters = @{
		body = @{
			client_id = $ClientID
			grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
			device_code = $JS.device_code
		}
		
		UrI = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
		Method = 'POST'
	}
	

	while($true){
		try {
			verbose "Requesing token..."
			$Result  = Invoke-WebRequest @ReqParameters  -UseBasicParsing;
			$JS = ConvertFrom-Json $Result;	
			$Session.RefreshToken 	= $JS.refresh_token;
			$Session.AccessToken 	= $JS.access_token;
			verbose "	Tokens got..."
		} catch {
			$ex = $_;
			$Code = $ex.Exception.Response.StatusCode
			if($Code -eq 400 -and $ex.ErrorDetails.Message){
				$JS = ConvertFrom-Json $ex.ErrorDetails.Message
				if($JS.error -eq "authorization_pending"){
					verbose "	Authorization pending... Sleeping by $PoolInterval seconds..."
					Start-Sleep -s $PoolInterval;
					continue;
				}
				
				if($JS.error -eq "expired_token"){
					throw "TOKEN_EXPIRED"
				}
				
				if($JS.error -eq "bad_verification_code"){
					throw "BAD_DEVICE_CODE"
				}
				
				if($JS.error -eq "authorization_declined"){
					throw "AUTH_DECLINED"
				}
			} else {
				throw
			}
		}
		
		break;
	}
	
	
}


# Authenticates using resourc eowner password 
function Connect-GrapRopc {
	[CmdletBinding()]
	param(
		[string[]]$Scopes = '.default'
		,$User 		= $null
		,$Password	= $null
	)
	
	$Session = Get-GrapDefaultSession;
	
	$ClientID 	= $Session.ClientID;
	$Tenant	= $Session.Tenant;
	
	if($Scopes -NotContains 'offline_access'){
		$Scopes += 'offline_access'
	}
	
	$Session.Scope = $Scopes -Join ' ';
	
	if(!$User){
		$Creds = Get-Credential
		$User = $Creds.UserName;
		$Password = $Creds.GetNetworkCredential().Password;
	}
	
	$ReqParameters = @{
		body = @{
			client_id = $ClientID
			scope = $Session.Scope
			grant_type = 'password'
			username = $User
			password = $Password
		}
		
		Uri = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
		Method = 'POST'
	}

	$Result  = Invoke-WebRequest @ReqParameters -Verbose;
	$JS = ConvertFrom-Json $Result;
	$Session.RefreshToken 	= $JS.refresh_token;
	$Session.AccessToken 	= $JS.access_token;
}


function Invoke-Grap {
	[CmdletBinding()]
	param(
		$resource
		,$Method = 'GET'
		,$Top = $null
		,[string[]]$Select
		,$filter
	)
	
	$querystring = @()
	
	if($top){
		$querystring += '$top='+$top
	}
	
	if($select){
		$querystring += '$select='+($select -Join ",")
	}
	
	if($filter){
		$querystring += '$filter='+$filter
	}
	
	$FinalQS = $querystring -join "&";
	
	
	$FullLink = 'https://graph.microsoft.com/v1.0/' + $resource + '?'+ $FinalQS;
	
	
	$Session = Get-GrapDefaultSession;
	
	while($true){
		$ResultValue = @();
		#Get always a updated token (for refresh cases...)
		$token = $Session.AccessToken;
		try {
			
			while($true){
				$q = Invoke-WebRequest -Uri $FullLink -Headers @{  
						"Authorization" = "Bearer $token";  
					} -Method $Method;
					
				$cq = ConvertFrom-Json $q;
				
				if($cq.value){
					$ResultValue += $Cq.value;
				} else {
					$ResultValue += $Cq;
				}
				
				
				$NextLink = $cq."@odata.nextlink";
				
				if($NextLink){
					$FullLink = $NextLink;
				} else {
					break;
				}
			}
			
			return $ResultValue;
		} catch {
			$ex = $_;
			$Code = $ex.Exception.Response.StatusCode
			if($ex.ErrorDetails.Message){
				$JS = ConvertFrom-Json $ex.ErrorDetails.Message
				
				if($JS.error.code -eq "InvalidAuthenticationToken"){
					verbose "Token expired... Updating..."
					Update-AccessToken;
					continue;
				} else {
					throw $ex.ErrorDetails.Message
				}
			} else {
				throw
			}
		}
	}
	

			
	

}

function Update-AccessToken {
	$Session = Get-GrapDefaultSession;
	$ClientID 	= $Session.ClientID;
	$Scope		= $Session.Scope;
	$Tenant		= $Session.Tenant;
	$RefreshToken = $Session.RefreshToken
	
	$ReqParameters = @{
		body = @{
			client_id = $ClientID
			scope = $Scope
			grant_type = 'refresh_token'
			refresh_token = $RefreshToken
		}
		
		Uri = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
		Method = 'POST'
	}
	
	$Result  = Invoke-WebRequest @ReqParameters  -UseBasicParsing;
	$JS = ConvertFrom-Json $Result;	
	$Session.RefreshToken 	= $JS.refresh_token;
	$Session.AccessToken 	=  $JS.access_token;
	return;
}


##############################################33333
## Auliary
function Export-GrapSession {
	param($Session, $File)
	
	$Session | Export-CliXml $File;
	
}

function Import-GrapSession {
	param($file)
	
	$Session = Import-Clixml $file;
	
	$Global:Graps_Storage.SESSIONS[$Session.SlotHash] = $Session;
}
