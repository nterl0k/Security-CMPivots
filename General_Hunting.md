# General Hunting
This queries below are meant to be a starter area/good way to learn how to apply CMPivot to some general security analysis needs at scale. The bulk of these queries will be helpful samples that can be taken and adapted to your own needs, however some may have common usefulness(like startup/process anomaly hunting)

## Event Logs
"EventLog" operator is used to find specific event logs.
- EventLog appears to be limited by the use of the "Get-EventLog" commandlet so only certain event logs are available:
	- Security
	- System
	- Application
	- OAlert

#### Example 1) Find 4688 Events for PowerShell process executions
	
	EventLog('Security') 
	| where EventID == 4688
	| where Message contains 'powershell'
		
## Running Processes
Digging through running processes can provide a ton of data where outlier and anomaly detection can be helpful. If you're looking for anything using PowerShell, you must exclude the "Script Store" directory so that the CMPivot query doesn't pick up it's own PowerShell command.

#### Example 1) Find Process running with "Users\*\AppData" or "Users\*\download"

	- Raw Data (Dump out some raw data for carving in another tool. IE Excel)
	Process 
	| where (Device like '%') 
	| where ((CommandLine like '%Users%AppData%') or (CommandLine like '%Users%Download%')) 
	| where (CommandLine !like '%example.exe%') 
	| order by Name desc
		
	- Least Frequency Counts (Find the processes which are anomalous and occur infrequently)
	Process 
	| where (Device like '%')
	| where ((CommandLine like '%Users%AppData%') or (CommandLine like '%Users%Download%')) 
	| where (CommandLine !like '%example.exe%') 
	| summarize count() by Name 
	| order by count_ asc
	
#### Example 2) Find a specific (potentially malicious) process

	Powershell Encoded Command
	Process 
	| where (Device like '%') 
	| where (Name == 'powershell.exe') 
	| where ((CommandLine like '%-enc%') or (CommandLine like '%-e %')) 
	| where (CommandLine !like '%ScriptStore%')
		
	Powershell Invoke-Expression (memory resident, probably won't be seen running)
	Process 
	| where (Device like '%') 
	| where (Name == 'powershell.exe') 
	| where  ((CommandLine like '%iex%') or (CommandLine like '%Invoke-Expression%')) 
	| where  (CommandLine !like '%ScriptStore%')

## Services
Services can be a particular way attackers establish persistence on a system, looking for anomalous services is always a good starting place.

#### Example 1) Find a service running in user space

	Services
	| where (Device like '%')
	| where PathName like '%C:\User%'
		
	- Raw Data (Dump out some raw data for carving in another tool. IE Excel)
	Services
	| where (Device like '%')
	| where PathName like '%C:\User%'
	| where (PathName !like '%example%')
	| order by DisplayName 
		
	- Least Frequency Counts (find the services which are anomalous and occur infrequently)
	Services 
	| where (Device like '%') 
	| where PathName like '%C:\User%' 
	| where (PathName !like '%example%') 
	| summarize count() by DisplayName 
	| order by count_ asc

#### Example 2)	Find service with non-system running user/owner.
	
	Services 
	| where (Device like '%') 
	| where (StartName !contains 'Local') and (StartName !contains 'Network')
	
## Startup values
Another area of persistence good for routine analysis are the startup items collected by SCCM. These include the common areas the HKLM\HKCU registry entries, start-up program folders and other.

#### Example 1) Find a specific (potential malicious) starts-up (Powershell)
	
	AutoStartSoftware
	| where ((Device like '%') and (StartupValue like '%powershell%'))
	| project Device, FileName, FileVersion, StartupType, StartupValue
	
	AutoStartSoftware 
	| where (Device like '%') 
	| where (StartupValue like '%powershell%') 
	| project Device, FileName, FileVersion, StartupType, StartupValue
	
#### Example 2) Find Starts in User Controllable locations:
	- Raw Data (Dump out some raw data for carving in another tool. IE Excel)
	AutoStartSoftware 
	| where (Device like '%')
	| where ((StartupValue like '%Users%') or (StartupValue like '%ProgramData%'))
	| where (StartupValue !like '%zoom.exe%')
	| order by FileName desc
		
	- Least Frequency Counts (find the start-ups which are anomalous and occur infrequently)
	AutoStartSoftware
	| where (Device like '%')
	| where ((StartupValue like '%Users%') or (StartupValue like '%ProgramData%'))
	| where (StartupValue !like '%example.exe%')
	| summarize count() by FileName
	| order by count_ asc 

## Files
The sky is the limit with this one, however one unfortunate problem is that SCCM doesn't appear to recurse using this function so you'll need some level of specificity in your hunting.

##### Example 1) All Devices with a specific hash value file in a specific folder.
	File('C:\\Users\\*\\AppData\\Local\\Temp\\*')
	| where (Device == '%') 
	| where (Hash == 'SHA-256 example hash here')
