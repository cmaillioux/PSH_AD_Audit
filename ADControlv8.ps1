$PSDefaultParameterValues['*:Encoding'] = 'utf8'
$currentpath = Get-location
$myFolder = New-Item "$($currentpath)\transfert_audit\" -itemtype Directory -force

function Test-RegistryValue{
	param(
	[parameter(Mandatory=$true)]
	[ValidateNotNullOrEmpty()]$Path, 
	
	[parameter(Mandatory=$true)]
	[ValidateNotNullOrEmpty()]$Value
    )
	
	try {
		Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
		return $true
	}
	catch {
		return $false
	}
}

Function Get-UserAccountControlValueTable
{	
    $userAccountControlHashTable = New-Object HashTable
    $userAccountControlHashTable.Add("SCRIPT",1)
    $userAccountControlHashTable.Add("ACCOUNTDISABLE",2)
    $userAccountControlHashTable.Add("HOMEDIR_REQUIRED",8) 
    $userAccountControlHashTable.Add("LOCKOUT",16)
    $userAccountControlHashTable.Add("PASSWD_NOTREQD",32)
    $userAccountControlHashTable.Add("ENCRYPTED_TEXT_PWD_ALLOWED",128)
    $userAccountControlHashTable.Add("TEMP_DUPLICATE_ACCOUNT",256)
    $userAccountControlHashTable.Add("NORMAL_ACCOUNT",512)
    $userAccountControlHashTable.Add("INTERDOMAIN_TRUST_ACCOUNT",2048)
    $userAccountControlHashTable.Add("WORKSTATION_TRUST_ACCOUNT",4096)
    $userAccountControlHashTable.Add("SERVER_TRUST_ACCOUNT",8192)
    $userAccountControlHashTable.Add("DONT_EXPIRE_PASSWORD",65536) 
    $userAccountControlHashTable.Add("MNS_LOGON_ACCOUNT",131072)
    $userAccountControlHashTable.Add("SMARTCARD_REQUIRED",262144)
    $userAccountControlHashTable.Add("TRUSTED_FOR_DELEGATION",524288) 
    $userAccountControlHashTable.Add("NOT_DELEGATED",1048576)
    $userAccountControlHashTable.Add("USE_DES_KEY_ONLY",2097152) 
    $userAccountControlHashTable.Add("DONT_REQ_PREAUTH",4194304) 
    $userAccountControlHashTable.Add("PASSWORD_EXPIRED",8388608) 
    $userAccountControlHashTable.Add("TRUSTED_TO_AUTH_FOR_DELEGATION",16777216) 
    $userAccountControlHashTable.Add("PARTIAL_SECRETS_ACCOUNT",67108864)

    $userAccountControlHashTable = $userAccountControlHashTable.GetEnumerator() | Sort-Object -Property Value 
    return $userAccountControlHashTable
}

Function Get-UserAccountControlFlags($userInput)
{    
        Get-UserAccountControlValueTable | foreach {
	    $binaryAnd = $_.value -band $userInput
	    if ($binaryAnd -ne "0") { write $_ }
    }
}

# Recherche des comptes associés aux différents groupes 
$allgroups = Get-ADGroup -filter * | sort name 
$detailedgroups = foreach($item in $allgroups.name) {
    $detailedusers = get-ADGroupMember -identity $item | Where { $_.objectClass -eq "user" } | select samaccountname
    $resume = foreach($item2 in $detailedusers.samaccountname) {
        Get-ADUser -Identity $item2 -properties name,samaccountname,Enabled,PasswordLastset,PasswordExpired,PasswordNeverExpires,WhenCreated,WhenChanged,sid,distinguishedname | select name,samaccountname,Enabled,PasswordLastset,PasswordExpired,PasswordNeverExpires,WhenCreated,WhenChanged,sid,distinguishedname
    }
$resume | export-csv $myFolder\$item.csv
}

$allgroups = Get-ADGroup -filter * | sort name 
$detailedgroups = foreach($item in $allgroups.name) {
    get-ADGroupMember -identity $item | Where { $_.objectClass -eq "group" } | select name,samaccountname,sid
}
$detailedgroups | export-csv $myfolder\$(item)_groupes.csv
 
#Contrôles comptes, SPN anormaux, comptes desactives, mots de passe qui n'expirent pas, etc. 
Get-aduser -filter * -properties passwordlastset,passwordneverexpires,lastlogondate,whenChanged,whenCreated,enabled,admincount,ServicePrincipalName,PrimaryGroupId,UserAccountControl,sid | sort name | select name,samaccountname,passwordlastset,passwordneverexpires,lastlogondate,whenCreated,whenchanged,enabled,admincount,ServicePrincipalName,PrimaryGroupId, UserAccountControl,sid | export-csv $myFolder\Controles_Utilisateurs.csv

#Contrôles machines, etc. 
Get-adcomputer -filter * -properties PrimaryGroupId,UserAccountControl,sid | sort name | select samaccountname,PrimaryGroupId, UserAccountControl,sid | export-csv $myFolder\Controles_Machines.csv

#Info RootDSE
Get-ADRootDSE | export-csv $myFolder\RootDSE.csv

$domainroot = Get-ADDomain
#Permissions sur l'objet AdminSDHolder
Get-Acl -path "AD:CN=AdminSDHolder,CN=System,$($domainroot.DistinguishedName)" | select -ExpandProperty Access | select IdentityReference,ActiveDirectoryRights,ObjectType,AccessControlType -Unique | export-csv $myFolder\Permissions_adminsdholder.csv

#Liste des privilges Windows
secedit /export /areas USER_RIGHTS /cfg $myfolder\WindowsPrivileges.txt

#Info GPO
get-GPO -All | export-csv $myFolder\GPOList.csv 

#Infos controleurs de domaine
get-ADDomainController | export-csv $myFolder\ControlesDC.csv

#Password_change_dc_no_change
"Tests sur valeurs changement de mot de passe ordinateur du DC" | Out-File -FilePath $myFolder\DCPassword.txt 
$changemdp1 = test-RegistryValue -path 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters' -value DisablePasswordChange
if ($changemdp1) {
	Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Name "DisablePasswordChange" | Out-File -FilePath $myFolder\DCPassword.txt -Append
}
$changemdp2 = test-RegistryValue -path 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters' -value MaximumPasswordAge
if ($changemdp2) {
	Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Name "MaximumPasswordAge" | Out-File -FilePath $myFolder\DCPassword.txt -Append
}

#DSRM Logon Behavior
$testdsrm = test-RegistryValue -path 'HKLM:\System\CurrentControlSet\Control\Lsa' -value DsrmAdminLogonBehavior
if ($testdsrm) {
	Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\Lsa -Name "DsrmAdminLogonBehavior" | Out-File -FilePath $myFolder\DSRMLogon.txt -Append
}

#Regarder les flags sur les comptes 
"Affichage des Flags de Comptes" | Out-File -FilePath $myFolder\Flags_comptes.txt 
$monres = get-aduser -filter * -properties samaccountname,UserAccountControl | select samaccountname,UserAccountControl
foreach($item in $monres) {
	$item.samaccountname | Out-File -FilePath $myFolder\Flags_comptes.txt -Append
	Get-UserAccountControlFlags($item.UserAccountControl) | Out-File -FilePath $myFolder\Flags_comptes.txt -Append
}

#Regarder les flags sur les machines
"Affichage des Flags de Machines" | Out-File -FilePath $myFolder\Flags_machines.txt 
$monres2 = get-adcomputer -filter * -properties samaccountname,UserAccountControl | select samaccountname,UserAccountControl
foreach($item in $monres2) {
	$item.samaccountname | Out-File -FilePath $myFolder\Flags_machines.txt -Append
	Get-UserAccountControlFlags($item.UserAccountControl) | Out-File -FilePath $myFolder\Flags_machines.txt -Append
}

#Politique de mot de passe du domaine
$domainname = Get-ADDomain | select DNSRoot
Get-ADDefaultDomainPasswordPolicy -Identity $domainname.DNSRoot | Out-File -FilePath $myFolder\PolitiqueMdPDomaine.txt