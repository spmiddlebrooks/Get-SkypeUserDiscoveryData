<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
.NOTES
	Version: 1.0
	Updated: 8/30/2017
	Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
.LINK
	https://github.com/spmiddlebrooks
#>
#Requires -Version 3.0
#Requires -Modules ActiveDirectory,Lync

[cmdletbinding()]
param( 
	[Parameter(Mandatory=$True,Position=0)]
		[ValidateScript({
			if ( Test-Path $_ ) {$True}
			else {Throw "FilePath $_ not found"}
		})]	
		[string] $FilePath = "",
	[Parameter(Mandatory=$False)]
		[switch] $CheckExoRoutingDomain,
	[Parameter(Mandatory=$False)]
		[string] $ExoRoutingDomain = "tenant.mail.onmicrosoft.com",
	[Parameter(Mandatory=$False)]
		[switch] $CheckForInvalidDomains,
	[Parameter(Mandatory=$False)]
		[string] $InvalidDomainRegex = ".+@()"
)


function Test-CsvFormat {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 8/30/2017
		Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
	.LINK
		https://github.com/spmiddlebrooks
	#>
	param (
		[string] $CsvFilePath
	)
	$Csv = Import-CSV $CsvFilePath

	## List all columns that MUST be in the csv:
	$ColumnsExpected = @(
		'userPrincipalName'
	)
	<#
	$ColumnsExpected = @(
		'userPrincipalName',
		'emailAddress',
		'telephone',
		'RegistrarPool',
		'ConferencePolicy',
		'ClientPolicy'
	)
	#>
	
	## Verify that all expected columns are there (additional columns in the csv will be ignored)
	$ColumnsOK = $True
	$ColumnsCsv = $Csv | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
	
	$ColumnsExpected | ForEach-Object {
		If ($ColumnsCsv -notcontains $_) {
			$ColumnsOK = $False
			"Expected column not found: '$($_)'" | Write-Host -ForegroundColor Red
		}
	}
	
	If ($ColumnsOK) {
		return $Csv
	}
	else {
		Throw "The csv format is incorrect!"
	}
}
# End function Test-CsvFormat

function Test-ForInvalidCharacters {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 8/30/2017
		Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
	.LINK
		https://github.com/spmiddlebrooks
	#>
	param (
		[string] $strAddress,
		[string] $addressType
	)

	$arrAddress = $strAddress -split '@'
	if ( $($arrAddress[0]) -match "[\'\&\<\>\`\*\@\\\[\]\{\}\^\:\,\$\=\!\#\(\)\%\|\+\?\/\~]" ) {
		return ('Invalid_Char_' + $addressType)
	}
}
# End function Test-ForInvalidCharaters

function Get-AdUserInformation {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 8/30/2017
		Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
	.LINK
		https://github.com/spmiddlebrooks
	#>
	param (	
		[string] $upn
	)

	$LocalSite = (Get-ADDomainController -Discover).Site
	[string] $GlobalCatalog = (Get-ADDomainController -Discover -Service GlobalCatalog -SiteName $LocalSite).HostName
	If (-Not $GlobalCatalog) { 
		[string] $GlobalCatalog = (Get-ADDomainController -Discover -Service GlobalCatalog -NextClosestSite).HostName
	}

	if ( $user = Get-AdUser -Server "$($GlobalCatalog):3268" -Filter {userPrincipalName -eq $upn} -properties enabled,proxyaddresses,msRTCSIP-PrimaryUserAddress ) {
		#userPrincipalName found
	}
	else {
		#userPrincipalName NOT found
		return
	}

	$upn 				= $upn.ToLower()	
	$proxyaddresses     = $user.proxyaddresses
	$PrimarySmtp 		= $null
	$PrimarySip			= $null
	$ProxySip    		= $null
	$errFlags 			= @()
	
	if ($user."msRTCSIP-PrimaryUserAddress") {
		$PrimarySip = ($user."msRTCSIP-PrimaryUserAddress".tolower() -split ':')[1]
	}

	foreach ($proxyaddress in $proxyaddresses) {
		$null = $proxyaddress -match "(SMTP|SIP):(.+@[\w-\.]+);?"

		if ($matches) {
			$qualifier = $matches[1]
			$address   = $matches[2]
		
			if ($qualifier -match 'SIP') {
				$ProxySip = $address.tolower()
			}
			elseif ($qualifier -match 'SMTP') {
				### Get primary SMTP address
				if ($qualifier -cmatch 'SMTP') {
					$PrimarySmtp = $address.tolower()
				}
				### Check for O365 mail routing domain
				elseif ($check_msol_smtp -AND $address -match $msol_smtp_domain) {
					$msol_smtp = $address.tolower()
				}
				### Check for invalid email domains
				elseif ($check_invalid_email_domains -AND $address -match $invalid_email_domain_regex) {
					$errFlags += 'Invalid_Email_Domain'
				}
			}
			$matches.clear()
		}
	}

	if ($check_msol_smtp -and !$msol_smtp) {
		$errFlags += 'No_Msol_Smtp'
	}

	if ($upn -AND ($PrimarySmtp -OR $PrimarySip -OR $ProxySip)) {
		$errFlags += Test-ForInvalidCharacters $upn 'Upn'

		### PrimarySmtp address checks
		if ($PrimarySmtp -AND $upn -eq $PrimarySmtp) {
			$errFlags += Test-ForInvalidCharacters $PrimarySmtp 'PrimarySmtp'
		}
		elseif (!$PrimarySmtp) {
			$errFlags += 'No_PrimarySmtp'
		}
		else {
			$errFlags += 'Upn_NE_PrimarySmtp'
		}

		### PrimarySip & ProxySip address checks
		if ($PrimarySip -AND $upn -eq $PrimarySip) {
			$errFlags += Test-ForInvalidCharacters $PrimarySip 'PrimarySip'

			if ($ProxySip -AND $upn -eq $ProxySip) {
				$errFlags += Test-ForInvalidCharacters $ProxySip 'ProxySip'
			}
			elseif (!$ProxySip) {
				$errFlags += 'PrimaySIP_without_ProxySip'
			}
			else {
				$errFlags += 'ProxySIP_NE_Upn_PrimarySIP'
			}
		}
		elseif (!$PrimarySip) {
			$errFlags += 'No_PrimarySip'

			if ($ProxySip) {
				$errFlags += 'ProxySIP_without_PrimarySip'
			}
		}
		else {
			$errFlags += 'Upn_NE_PrimarySip_ProxySip'
		}		

	}
	elseif ($upn) {
		$errFlags += Test-ForInvalidCharacters $upn 'Upn'
		$errFlags += 'Upn_without_Smtp_Sip'
	}
	else {
		$errFlags += 'No_Upn'
	}

	$AdUser = [PSCustomObject] @{
		FirstName = $($user.GivenName)
		LastName = $($user.Surname)
        Enabled = $user.enabled
		samAccountName = $($user.samAccountName.ToLower())
		userPrincipalName = $($user.userPrincipalName.ToLower())
		PrimarySmtp = $PrimarySmtp
		PrimarySip = $PrimarySip
		ProxySip = $ProxySip
		ErrorFlags = ($errFlags -join '|')
	}
	
	return $AdUser
}
# End function Get-AdUserInformation

function Get-CsUserInformation {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 8/30/2017
		Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
	.LINK
		https://github.com/spmiddlebrooks
	#>
	param (	
		[string] $upn
	)

	if ( $CsUser = Get-CsUser -Identity $upn -ErrorAction SilentlyContinue ) {
		#userPrincipalName found
		return $CsUser
	}
	else {
		#userPrincipalName NOT found
		return
	}

}
# End function Get-CsUserInformation

	
############################################################################
$RowNumber = 1

$objReportTemplate = [PSCustomObject] @{
	ErrorFlags = ''
	FirstName = ''
	LastName = ''
	AdEnabled = ''
	CsEnabled = ''
	samAccountName = ''
	userPrincipalName = ''
	PrimarySmtp = ''
	PrimarySip = ''
	ProxySip = ''
	VoicePolicy = ''
	VoiceRoutingPolicy = ''
	ConferencingPolicy = ''
	PresencePolicy = ''
	DialPlan = ''
	LocationPolicy = ''
	ClientPolicy = ''
	ClientVersionPolicy = ''
	ArchivingPolicy = ''
	PinPolicy = ''
	ExternalAccessPolicy = ''
	MobilityPolicy = ''
	PersistentChatPolicy = ''
	UserServicesPolicy = ''
	CallViaWorkPolicy = ''
	ThirdPartyVideoSystemPolicy = ''
	HostedVoiceMail = ''
	HostedVoicemailPolicy = ''
	RegistrarPool = ''
	LineUri = ''
	EnterpriseVoiceEnabled = ''
}


If ($AllCsvUsers = Test-CsvFormat $FilePath) {

	Foreach ($CsvUser in $AllCsvUsers) {
        
        if ($AllCsvUsers.Count -lt 1) { $AllCsvUsersCount = 1 }
        else { $AllCsvUsersCount = $AllCsvUsers.Count }

		Write-Progress -Activity "Processing Users" -Status "Processing $RowNumber of $AllCsvUsersCount)" -PercentComplete (($RowNumber / $AllCsvUsers.Count) * 100)
		$RowNumber += 1
	
		If ( $AdUser = Get-AdUserInformation $($CsvUser.userPrincipalName) ) {
			Write-Verbose "User found in AD"
			If ( $CsUser = Get-CsUserInformation $($CsvUser.userPrincipalName) ) {
				Write-Verbose "User found in Lync/Skype"
				$objReportItem = $objReportTemplate.PSObject.Copy()
				$objReportItem.FirstName = $($AdUser.FirstName)
				$objReportItem.LastName = $($AdUser.LastName)
				$objReportItem.AdEnabled = $AdUser.Enabled
				$objReportItem.CsEnabled = $CsUser.Enabled
				$objReportItem.samAccountName = $($AdUser.samAccountName.ToLower())
				$objReportItem.userPrincipalName = $($AdUser.userPrincipalName.ToLower())
				$objReportItem.PrimarySmtp = $AdUser.PrimarySmtp
				$objReportItem.PrimarySip = $AdUser.PrimarySip
				$objReportItem.ProxySip = $AdUser.ProxySip
				$objReportItem.VoicePolicy = $CsUser.VoicePolicy
				$objReportItem.VoiceRoutingPolicy = $CsUser.VoiceRoutingPolicy
				$objReportItem.ConferencingPolicy = $CsUser.ConferencingPolicy
				$objReportItem.PresencePolicy = $CsUser.PresencePolicy
				$objReportItem.DialPlan = $CsUser.DialPlan
				$objReportItem.LocationPolicy = $CsUser.LocationPolicy
				$objReportItem.ClientPolicy = $CsUser.ClientPolicy
				$objReportItem.ClientVersionPolicy = $CsUser.ClientVersionPolicy
				$objReportItem.ArchivingPolicy = $CsUser.ArchivingPolicy
				$objReportItem.PinPolicy = $CsUser.PinPolicy
				$objReportItem.ExternalAccessPolicy = $CsUser.ExternalAccessPolicy
				$objReportItem.MobilityPolicy = $CsUser.MobilityPolicy
				$objReportItem.PersistentChatPolicy = $CsUser.PersistentChatPolicy
				$objReportItem.UserServicesPolicy = $CsUser.UserServicesPolicy
				$objReportItem.CallViaWorkPolicy = $CsUser.CallViaWorkPolicy
				$objReportItem.ThirdPartyVideoSystemPolicy = $CsUser.ThirdPartyVideoSystemPolicy
				$objReportItem.HostedVoiceMail = $CsUser.HostedVoiceMail
				$objReportItem.HostedVoicemailPolicy = $CsUser.HostedVoicemailPolicy
				$objReportItem.RegistrarPool = $CsUser.RegistrarPool
				$objReportItem.LineUri = $CsUser.LineUri
				$objReportItem.EnterpriseVoiceEnabled = $CsUser.EnterpriseVoiceEnabled
				$objReportItem.ErrorFlags = $AdUser.ErrorFlags
			}
			Else {
				Write-Verbose "User found in AD, but not in Lync/Skype"
				$objReportItem = $objReportTemplate.PSObject.Copy()
				$objReportItem.FirstName = $($AdUser.FirstName)
				$objReportItem.LastName = $($AdUser.LastName)
				$objReportItem.AdEnabled = $AdUser.Enabled
				$objReportItem.samAccountName = $($AdUser.samAccountName.ToLower())
				$objReportItem.userPrincipalName = $($AdUser.userPrincipalName.ToLower())
				$objReportItem.PrimarySmtp = $AdUser.PrimarySmtp
				$objReportItem.PrimarySip = $AdUser.PrimarySip
				$objReportItem.ProxySip = $AdUser.ProxySip
				if ($AdUser.ErrorFlags) {
					$objReportItem.ErrorFlags = ($AdUser.ErrorFlags + '|CsUser_NotFound')
				}
				else {
					$objReportItem.ErrorFlags = 'CsUser_NotFound'
				}
			}
		}
		Else {
			Write-Verbose "User not found in AD"
			$objReportItem = $objReportTemplate.PSObject.Copy()
			$objReportItem.userPrincipalName = $($CsvUser.userPrincipalName)
			$objReportItem.ErrorFlags = ('UPN_NotFound')
		}

	    $objReportItem
	}
}
