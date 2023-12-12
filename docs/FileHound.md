# FileHound

**<center>[For fileservices are dark and full of terrors](https://youtu.be/MgmA2Yehw78?t=23)</center>**

I started this to learn more about Bloodhound and neo4j while attending a bloodhound workshop by @sadprocessor. Eventually I learned way more about javascript than I ever cared to (_still not a lot..._).

The basic idea is to map fileshares into your attack path, which might show you sensitive data being exposed to users who do not need access to it.

It can also give you an idea, how much damage your typical crypto virus might be able to do, depending who gets infected.

It may be helpful if you need to migrate fileservices into a new domain (_not sure how, but it might_).

## Collection
FileHound collects fileshares and the NTFS permissions of the shared folder.

Filehound could possibly be detected by your AV because it contains code of some _really_ awesome projects and people, whose names shall not be used in sourcecode ;)
- Fileshares are enumerated per Computer via NetShareEnum which is patched together from [PSReflect-Functions by @jaredcatkinson](https://github.com/jaredcatkinson/PSReflect-Functions) and [PSReflect by @mattifestation](https://github.com/mattifestation/PSReflect).
- Filehound also looks up DFS Namespaces and the target folders (which still has a dependendy to the DFSN Posh Module being installed via RSAT/Fileservices). DFS Namespaces are queried from Active Directory through some functions from [PowerView by @harmj0y](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- To create the output, Filehound uses the New-OutPut Function of [AzureHound by @_wald0, @cptjesus, @haus3c](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/AzureHound.ps1)


All of this could probably done in SharpHound.

### Work to be done:
- Remove DFSN Module dependency (get-dfsntargetfolder)
- Handle Ntfs Acl way more detailed
- Accept Client list
- DFS Scan should be optional
- Clean up code & codeflow
- Icons in BloodHound UI for fileshare nodes

## OpSec
- should work with user rights
    - not if Powershell constrained language mode is used!
- AD Operations to resolve SIDs
- Query on ACL might be audited on high value shares
- Firewalls might be in place, FW drops might be audited
- handling of foreign security principals (objectid need to include source domain for bloodhound)

## Node
This adds the node "Fileshare" with properties:
- cifspath: UNC path of the share
- domain: AD domain name
- name: Sharename
- cifshostsid: AD SID of the hosting computer
- cifshost: computername of the hosting computer
- objectid: objectId normalized for bloodhound _(well known security principals get the format "DOMAIN-SID")_
## Edges
The following edges are created for Users, Groups and Computers. 
- NtfsFullControl
- NtfsRead
- NtfsAceControl
- NtfsPublish
## Demo
### Prebuilt query
![Prebuilt Query](/docs/images/filehound/fs-builtinquery.PNG)

### Node properties
![Fileshare node properties](/docs/images/filehound/fs-nodedetails.png)

### All owned objects to this share
![Owned objects to this share](/docs/images/filehound/fs-ownedobjectstoshare.PNG)


## Users with Full Control Rights
![Users with full control](/docs/images/filehound/fs-userwithfullcontrol.PNG)
### Import
- [Clone & build this branch](https://bloodhound.readthedocs.io/en/latest/installation/windows.html#alternative-build-the-bloodhound-gui)
- Run Filehound

## JSON
````json
{
	"meta": {
		"count": 10,
		"type": "fileshares",
		"version": 4
	},
	"data": [
    {
        "name":  "PublicFolder",
        "cifspath":  "\\\\APP1\\Public\\PublicFolder",
        "cifshost":  "APP1",
        "objectid":  "contoso.local.S-1-5-21-1200012274-2048297836-1055935347-1103.PublicFolder",
        "domain":  "contoso.local",
        "cifshostsid":  "S-1-5-21-1200012274-2048297836-1055935347-1103",
        "fullcontrol":  [
                            null
                        ],
        "read":  [
                     null
                 ],
        "changepermissions":  [
                                  null
                              ],
        "owner":  null
    },
    {
        "name":  "supersecretshare",
        "cifspath":  "\\\\DC1\\supersecretshare",
        "cifshost":  "DC1",
        "objectid":  "contoso.local.S-1-5-21-1200012274-2048297836-1055935347-1000.supersecretshare",
        "domain":  "contoso.local",
        "cifshostsid":  "S-1-5-21-1200012274-2048297836-1055935347-1000",
        "fullcontrol":  [
                            {
                                "PrincipalSid":  "CONTOSO.LOCAL-S-1-5-18",
                                "PrincipalType":  "UNKNOWN"
                            },
                            {
                                "PrincipalSid":  "CONTOSO.LOCAL-S-1-5-32-544",
                                "PrincipalType":  "Group"
                            },
                            {
                                "PrincipalSid":  "S-1-5-21-1200012274-2048297836-1055935347-1105",
                                "PrincipalType":  "User"
                            }
                        ],
        "read":  [

                 ],
        "changepermissions":  [
                                  {
                                      "PrincipalSid":  "S-1-5-21-1200012274-2048297836-1055935347-1561",
                                      "PrincipalType":  "User"
                                  }
                              ],
        "owner":  {
                      "PrincipalSid":  "S-1-5-21-1200012274-2048297836-1055935347-1105",
                      "PrincipalType":  "User"
                  }
    }
	]
}
````