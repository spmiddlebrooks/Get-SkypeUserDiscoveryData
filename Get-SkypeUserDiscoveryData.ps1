<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
.NOTES
	Version: 1.1.7
	Updated: 9/22/2017
	Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
.LINK
	https://github.com/spmiddlebrooks
#>
#Requires -Version 3.0
#Requires -Modules ActiveDirectory

[cmdletbinding()]
param( 
	[Parameter(Mandatory=$True,Position=0)]
		[ValidateScript({
			if ( Test-Path $_ ) {$True}
			else {Throw "FilePath $_ not found"}
		})]	
		[string] $FilePath = "",
    [Parameter(Mandatory=$False)]
		[ValidateNotNullorEmpty()]
        [ValidateSet('SamAccountName','mail','userPrincipalName')]
        [string] $IdentityAttribute = 'userPrincipalName',
	[Parameter(Mandatory=$False)]
		[string] $IdentityRegEx = '\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b',
	[Parameter(Mandatory=$False)]
		[switch] $CheckExoRoutingDomain,
	[Parameter(Mandatory=$False)]
		[string] $ExoRoutingDomain = "tenant.mail.onmicrosoft.com",
	[Parameter(Mandatory=$False)]
		[switch] $CheckForInvalidDomains,
	[Parameter(Mandatory=$False)]
		[string] $InvalidDomainRegex = ".+@()"
)

function Set-ModuleStatus { 
<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
.NOTES
	Original Author: Pat Richard
.LINK
	https://www.ucunleashed.com/938
#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param	(
		[Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true, HelpMessage = "No module name specified!")] 
			[ValidateNotNullOrEmpty()]
			[string] $name
	)
	PROCESS{
		# Executes once for each pipeline object
		# the $_ variable represents the current input object		
		if (!(Get-Module -name "$name")) { 
			if (Get-Module -ListAvailable | Where-Object Name -eq "$name") { 
				Import-Module -Name "$name"
				# module was imported
				return $true
			} else {
				# module was not available
				return $false
			}
		} else {
			# Write-Output "$_ module already imported"
			return $true
		} 
	} # end PROCESS
} 
# End function Set-ModuleStatus

function Test-CsvFormat {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.1
		Updated: 9/21/2017
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
		'Identity'
	)
	
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

function Get-AdGlobalCatalog {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 9/21/2017
		Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
	.LINK
		https://github.com/spmiddlebrooks
	#>
	param (	
	)

	$LocalSite = (Get-ADDomainController -Discover).Site
	[string] $GlobalCatalog = (Get-ADDomainController -Discover -Service GlobalCatalog -SiteName $LocalSite).HostName
	If (-Not $GlobalCatalog) { 
		[string] $GlobalCatalog = (Get-ADDomainController -Discover -Service GlobalCatalog -NextClosestSite).HostName
	}
    return $GlobalCatalog
}
# End function Get-AdGlobalCatalog

function Test-RegexPattern {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 9/22/2017
		Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
	.LINK
		https://github.com/spmiddlebrooks
	#>
	param (	
        $RegexPattern
	)

    try {
        New-Object Regex $RegexPattern
    }
    catch {
        throw 'Invalid Regex pattern specified for IdentityRegex'
    }
}
# End function Test-RegexPattern

function Get-AdUserInformation {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.1.4
		Updated: 9/22/2017
		Original Author: Scott Middlebrooks (Git Hub: spmiddlebrooks)
	.LINK
		https://github.com/spmiddlebrooks
	#>
	param (	
        [string] $GlobalCatalog,
		[string] $Identity
	)
    [bool] $CsUserEnabled = $false

    if ($IdentityRegex -and $Identity -match $IdentityRegex) {
        $Identity = $Matches[1]
        $Matches.Clear()
        Write-Verbose "Regex matched Identity = $Identity"
    }

	if ( $AdUser = Get-AdUser -Server "$($GlobalCatalog):3268" -Filter {$IdentityAttribute -eq $Identity} -Properties Enabled,proxyaddresses,msRTCSIP-UserEnabled,msRTCSIP-PrimaryUserAddress ) {	
		#Identity found
		
		$upn 				= $AdUser.userPrincipalName.ToLower()	
		$proxyaddresses     = $AdUser.proxyaddresses
		$PrimarySmtp 		= $null
		$PrimarySip			= $null
		$ProxySip    		= $null
		$errFlags 			= @()
		
		# Is user Lync/Skype Enabled?
		if ( $AdUser."msRTCSIP-UserEnabled" ) {
			$CsUserEnabled = $true

			# Check that msRTCSIP-PrimaryUserAddress exists with correct format
			if ( $AdUser."msRTCSIP-PrimaryUserAddress" -and $AdUser."msRTCSIP-PrimaryUserAddress" -match 'sip:(.+@[\w-\.]+)' ) {
				# Convert to all lowercase		
				$PrimarySip = $Matches[1].ToLower()
				$Matches.Clear()
			}
			# If msRTCSIP-PrimaryUserAddress exists but is not the correct format, log Error
			elseif ($AdUser."msRTCSIP-PrimaryUserAddress") {
				$errFlags = 'PrimarySIP_Exists_InvalidFormat'
			}
		}
	
		# Extract primary SMTP and SIP addresses from proxyaddresses attribute
		foreach ($proxyaddress in $proxyaddresses) {
			$null = $proxyaddress -match "(SMTP|SIP):(.+@[\w-\.]+);?"
	
			if ($Matches) {
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
					elseif ($CheckExoRoutingDomain -AND $address -match $ExoRoutingDomain) {
						$ExoRoutingAddress = $address.tolower()
					}
					### Check for invalid email domains
					elseif ($CheckForInvalidDomains -AND $address -match $InvalidDomainRegex) {
						$errFlags += 'Invalid_Email_Domain'
					}
				}
				$Matches.Clear()
			}
		}
	
		# If CheckExoRoutingDomain is set and there is no ExoRouting Address, log Error 
		if ($CheckExoRoutingDomain -and -Not $ExoRoutingAddress) {
			$errFlags += 'No_Msol_Smtp'
		}

		# If we have a userPrincipalName with at least one of: Smtp or Sip
		if ($upn -AND ($PrimarySmtp -OR $PrimarySip -OR $ProxySip)) {
			$errFlags += Test-ForInvalidCharacters $upn 'Upn'
	
			### PrimarySmtp address checks
			# If we have a SMTP address and userPrincipalName and SMTP match
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
			if ($CsUserEnabled) {
				if ( $PrimarySip -AND $upn -eq $PrimarySip ) {
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
		}
		# If we only have userPrincipalName without any of the other addresses
		elseif ($upn) {
			$errFlags += Test-ForInvalidCharacters $upn 'Upn'
			$errFlags += 'Upn_without_Smtp_Sip'
		}
		else {
			$errFlags += 'No_Upn'
		}
	
		$AdUser = [PSCustomObject] @{
			FirstName = $($AdUser.GivenName)
			LastName = $($AdUser.Surname)
			Enabled = $($AdUser.Enabled)
            CsEnabled = $CsUserEnabled
			samAccountName = $($AdUser.samAccountName.ToLower())
			userPrincipalName = $($AdUser.userPrincipalName.ToLower())
			PrimarySmtp = $PrimarySmtp
			PrimarySip = $PrimarySip
			ProxySip = $ProxySip
			ErrorFlags = ($errFlags -join '|')
		}
		return $AdUser
	}
	else {
		#Identity NOT found
		return $False
	}
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
    CsvIdentity = ''
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

# Attempt to load the SkypeforBusiness module
if (Set-ModuleStatus SkypeForBusiness) {
    $UcPlatform = 'SkypeforBusiness'
}
# If the SkypeforBusiness module is not present, attempt to load the Lync module
elseif (Set-ModuleStatus Lync) {
    $UcPlatform = 'Lync'
}
# If neither module is present throw an exception to prevent further operations
else {
    throw "Cannot proceed, could not load Skype for Business or Lync PowerShell module"
}

$AdGlobalCatalog = Get-AdGlobalCatalog

Write-Verbose "AdGlobalCatalog = $AdGlobalCatalog"

if (Test-RegexPattern -RegexPattern $IdentityRegex) {
    Write-Verbose 'IdentityRegx is a valid Regex pattern'
}

If ($AllCsvUsers = Test-CsvFormat $FilePath) {

	Foreach ($CsvUser in $AllCsvUsers) {
        
        if ($AllCsvUsers.Count) {
            $AllCsvUsersCount = $AllCsvUsers.Count
        }
        else { 
            $AllCsvUsersCount = 1
        }

		Write-Progress -Activity "Processing Users" -Status "Processing $RowNumber of $AllCsvUsersCount)" -PercentComplete (($RowNumber / $AllCsvUsersCount) * 100)
		$RowNumber += 1

        	Write-Verbose "CSV Identity = $($CsvUser.Identity)"

		If ( $AdUser = Get-AdUserInformation -GlobalCatalog $AdGlobalCatalog -Identity $($CsvUser.Identity) ) {
			Write-Verbose "Identity found in AD"
			$objReportItem = $objReportTemplate.PSObject.Copy()
			$objReportItem.FirstName = $($AdUser.FirstName)
			$objReportItem.LastName = $($AdUser.LastName)
			$objReportItem.AdEnabled = $AdUser.Enabled
			$objReportItem.CsEnabled = $AdUser.CsEnabled
			$objReportItem.CsvIdentity = $CsvUser.Identity
			$objReportItem.samAccountName = $($AdUser.samAccountName)
			$objReportItem.userPrincipalName = $($AdUser.userPrincipalName)
			$objReportItem.PrimarySmtp = $AdUser.PrimarySmtp

			If ( $AdUser.CsEnabled ) {
				Write-Verbose "Identity is Lync/Skype enabled"
				$CsUser = Get-CsUserInformation $($AdUser.userPrincipalName)
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
				Write-Verbose "Identity is NOT Lync/Skype enabled"
			}
		}
		Else {
			Write-Verbose "Identity NOT found in AD"
			$objReportItem = $objReportTemplate.PSObject.Copy()
			$objReportItem.CsvIdentity = $CsvUser.Identity
			$objReportItem.ErrorFlags = ('AdUser_NotFound')
		}

	    $objReportItem

	}
}
