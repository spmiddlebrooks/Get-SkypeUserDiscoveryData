# Test-CsUser

Test-CsUser will take a CSV input file of users and perform the following functions using the userPrincipalName as the "primary key":

	1. Check that the user object exists in Active Directory, using userPrincipalName from the CSV input file as the Identifier.
		a. Verify that the following addresses all match:  userPrincipalName, MsRtcSip-PrimaryUserAddress, Primary Smtp (from proxy addresses) and SIP (from proxy addresses)
		b. Check each of the above addresses for invalid characters.
		c. Optionally: Check for the existence of an Exchange Online Hybrid routing address, i.e. user@tenant.mail.onmicrosoft.com
		c. Optionally: Check for the existence of any mail domains that should be flagged as erroneous
	2. Check that the user object exists in Lync/Skype, using userPrincipalName from the CSV file as the Identifier.
	3. Collect various attributes of the user object from both AD and Lync/Skype and output that as a PowerShell object.
		a. The output object will contain a field named "ErrorFlags."  This field will contain a pipe "|" delimited string of values containing all errors that were encountered during processing the userPrincipalName.  The field will be blank if no errors were found.

The CSV file specified as the -FilePath parameter MUST contain a column named userPrincipalName.  Other columns can exist in the CSV and will be ignored.  For most use cases, you will probably want to use a command similar to the below to generate a report file in CSV format.
Example: Test-CsUser.ps1 -FilePath CsvInputFile.csv | Export-Csv -NoTypeInformation -FilePath UserReport.csv
