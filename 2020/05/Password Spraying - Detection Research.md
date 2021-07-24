# Password Spraying-Detection Research
*Sunday, May 16, 2021*
*2:23 AM*

*-- Dan Grindall*
*https://www.linkedin.com/in/dan-grindall/*

All works within are created and intended for educational purposes, only. Do not use any knowledge gained here to engange in illigal activities! Purpose and character of the use portions of copyrighted work is for nonprofit educational purposes as described in Section 107 of U.S. Copyright act: https://www.copyright.gov/title17/92chap1.html#107

## Background for Password Spraying

Why should you care about detecting password spraying? Because it works!


 
**From Rapid7 "Under The Hoddie 2019 Research Report"; A Survey to Pentest Organizations:**
       
*-- Source: https://www.rapid7.com/research/reports/under-the-hoodie-2020/*

* CREDENTIAL CAPTURE: HOW DID YOU OBTAIN PASSWORDS OR PASSWORD HASHES?

![Picture1.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture1.png)


* GUESSABLE CRACKED PASSWORDS

![Picture2.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture2.png)


* EXTERNAL ENGAGEMENT: HOW EFFECTIVE WERE LOCKOUTS?

![Picture3.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture3.png)




## Lab Environment for Research

~ All POC testing, screenshots created using Detection Lab: https://www.detectionlab.network/introduction/
 
~ Create Fake accounts for POC
https://www.darkoperator.com/blog/2016/7/30/creating-real-looking-user-accounts-in-ad-lab
 


## Enumerate Domain Users

**Enumerate domain users via cmd.exe:**
```net user /domain```

![Picture4.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture4.png)

~ Get Domain Admins
```net group "Domain Admins" /domain```
 
~ Get User Details
```net user <username> /domain```

![Picture5.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture5.png)

~ Note that we can't rely on detecting specific commands as there are many ways to skin this cat. Attackers prefference may vary.
*--https://www.jaapbrasser.com/active-directory-friday-list-password-information-for-domain-administrators/*


**Alternate method to enumerate domain users via Powershell:**

~ Note that 2016 domain controllers always display lastlogin date as 1/1/1601 - Known Bug for LDAP simple bind.
```
# enum_domain_users.ps1
$Searcher = New-Object DirectoryServices.DirectorySearcher -Property @{
    Filter = "(objectclass=user)"
    PageSize = 0
}
$Searcher.FindAll() | ForEach-Object {
    New-Object -TypeName PSCustomObject -Property @{
        samaccountname = $_.Properties.samaccountname -join ''
    pwdlastset = [datetime]::FromFileTime([int64]($_.Properties.pwdlastset -join ''))
        LastLogonDate = [datetime]::FromFileTime([int64]($_.Properties.LastLogonDate -join ''))
        enabled = -not [boolean]([int64]($_.properties.useraccountcontrol -join '') -band 2)
    }
}
```

![Picture6.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture6.png)

**Alternate method to enumerate domain admins via Powershell:**

~ Note that 2016 domain controllers always display lastlogin date as 1/1/1601 - Known bug for LDAP simple bind
```
#enum_domain_admins.ps1
$Searcher = New-Object DirectoryServices.DirectorySearcher -Property @{
    Filter = "(memberof=CN=Domain Admins,CN=Users,DC=windomain,DC=local)"
    PageSize = 0
}
$Searcher.FindAll() | ForEach-Object {
    New-Object -TypeName PSCustomObject -Property @{
        samaccountname = $_.Properties.samaccountname -join ''
        pwdlastset = [datetime]::FromFileTime([int64]($_.Properties.pwdlastset -join ''))
        LastLogonDate = [datetime]::FromFileTime([int64]($_.Properties.LastLogonDate -join ''))
        enabled = -not [boolean]([int64]($_.properties.useraccountcontrol -join '') -band 2)
    }
}
```

![Picture7.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture7.png)

**Enumerate Domain Lockout and Password Policy**
```
net accounts
```
![Picture8.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture8.png)

*We can see that the Lockout threshold is 5 and Lockout Observation window is 30 minutes.*

**Alternate methods to enumerate Domain Lockout and Password Policy:**

~Powershell - RSAT module installed:
```
Get-ADDefaultDomainPasswordPolicy
```
![Picture9.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture9.png)

~Get password policy wth crackmapexec:
```
crackmapexec smb <target> -u <user> -p <pass> --pass-pol
```

## Password Spraying
 
**Crackmapexec:**

https://github.com/byt3bl33d3r/CrackMapExec
 
~ Using crackmapexec and mp64 to generate passwords and spray them against SMB services on the network.
``` 
crackmapexec smb 10.0.0.1/24 -u Administrator -p `(./mp64.bin Pass@wor?l?a)`
 ```

**DomainPasswordSpray (Powershell)**

https://github.com/dafthack/DomainPasswordSpray
 
~ Using DomainPasswordSpray to spray a password against all users of a domain.
/!\ be careful with the account lockout !
```
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
 ```
 
~ Example of Password Spraying using DomainPasswordSpray.ps1
 
* Create passwords.txt with passwords to spray as well as users.txt with list of users that were previously enumerated.

![Picture10.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture10.png)

* *Note that the script pauses for durration of domain password policy observation window (lockout interval). A patient attacker can leave this running and come back to it (days later).*

![Picture11.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture11.png)

## Creating a honey account as detection method
 
This is a technique taught by SANS (SEC 504 "SEC504: Hacker Tools, Techniques, Exploits, and Incident Handling"

This technique is also referenced by CISA, Microsoft and other industry leaders.
 
Criteria for honey account(s) that we learned from enumerating domain accounts from a hacker perspective: The honey account must look like a real account.
 1.	Must be active.
 1.	Ideally be member of "Domain Admins" group to guarantee attention of attackers (not a hard requirement but more effective).
 1.	Should have a 20+ character random generated password.
 1.	Password set to never expire.
 1.	Must have been logged into at least once to reset last logon time from 1601/01/01 00:00:00.
 1.	Must have login hours set to "None" (Login Denied). 
 
![Picture12.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture12.png)

![Picture13.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture13.png)

![Picture14.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture14.png)


## Detecting Password Spraying
 

**Honey Account "Tripwire" Events**
 
EventID: 4776(S, F): The computer attempted to validate the credentials for an account.
https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776 

``` 
index="wineventlog" host="dc.windomain.local" EventCode=4776 Logon_Account=secopsadmin
```
![Picture15.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture15.png)

**Detecting Password Spray using distict count of target accounts per source workstation (or source IP) in specified interval**
 ```
index="wineventlog" host="dc.windomain.local" EventCode=4776 
| timechart span=30m dc(Logon_Account) as Distinct_Logon_Account by Source_Workstation
```
![Picture16.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture16.png)

**Investigation Dashboard Pane: Successful Auth Drilldown, by source, showing accounts compromised.**
![Picture17.png](https://github.com/dangrgr/blog/blob/main/2020/05/images/Picture17.png)

*Note: A Full Dashboard showing correlated metrics could be created incorporating these examples and more.*




