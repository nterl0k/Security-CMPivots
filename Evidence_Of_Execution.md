# Evidence Of Execution 
Queries here will attempt to extract suspicious or notable program execution logs/objects for inspection. Knowing normal for your environment will greatly help the applicability of these queries, however they can also be used as a template to hunt for specific malicious executions if known.

## Prefetch File Discovery 
The queries below will enumerate .pf files created by the Windows superfetch/prefetch service. Used to capture data about executables run on a system to improve system performance, but can also be used to showcase the execution of programs. Included are some common built-on programs abused by attackers during compromise, however these may also be part of legitimate enterprise processes.

For more information - https://www.forensicswiki.org/wiki/Prefetch 

### Bulk Query
    This query can be used to export/parse the majority of the individual queries, however it may need to be tweaked to remove known noise.
    
    File('%windir%\\Prefetch\\*') 
    | where (Device like '%') 
    | where ((((((((((((FileName like '%C:\\WINDOWS\\Prefetch\\at.exe%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\attrib%') 
    or FileName like '%C:\\WINDOWS\\Prefetch\\bitsadmin%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\certutil%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\mshta%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\mstsc%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\Schtask%') 
    or FileName like '%C:\\WINDOWS\\Prefetch\\Taskeng%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\taskkill%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\tasklist%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\tscon%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\xcopy%')
    or FileName like '%C:\\WINDOWS\\Prefetch\\vssadmin%'
    | where LastWriteTime >= ago(7d)
    | order by LastWriteTime desc

### Individual Queries
	• Attrib Execute, usually used to modify file attributes - ATT&CK T1158
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%attrib%') 
		| order by LastWriteTime desc
	
	• Schtasks Execute, usually used to create a scheduled task - ATT&CK T1053,S0111
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%Schtask%') 
		| order by LastWriteTime desc
	
	• Taskeng Execute, usually used to create a scheduled task - ATT&CK T1053
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%Taskeng%') 
		| order by LastWriteTime desc
	
	• tscon.exe Execute, usually used to Terminal Services Console - ATT&CK T1076
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%tscon%') 
		| order by LastWriteTime desc
	
	• mstsc.exe Execute, usually used to Perform a RDP Session - ATT&CK T1076
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%mstsc%') 
		| order by LastWriteTime desc
	
	• AT Execute, usually used to create a scheduled task - ATT&CK T1053,S0110
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%at.exe%') 
		| order by LastWriteTime desc
	
	• Tasklist Execute, usually used to list task - ATT&CK T1057,T1063,T1007,S005
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%tasklist%') 
		| order by LastWriteTime desc
	
	• Taskkill Execute, usually used to kill task
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%taskkill%') 
		| order by LastWriteTime desc
	
	• Mshta Execute, is a utility that executes Microsoft HTML Applications (HTA) - ATT&CK T1170
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%mshta%') 
		| order by LastWriteTime desc
	
	• Whoami Execute, used to prints the effective username of the current user
		File('%windir%\\Prefetch\\*')
		| where (Device like '%') 
		| where (FileName like '%whoami%') 
		| order by LastWriteTime desc
	
	• Xcopy Execute, is used for copying multiple files or entire directory trees from one directory to another and for copying files across a network
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%xcopy%') 
		| order by LastWriteTime desc
	
	• Esentutl Execute, is a legitimate built-in command-line program it could be used to create a exe from dump raw source
		File('%windir%\\Prefetch\\*')
		| where (Device like '%') 
		| where (FileName like '%esentutl%') 
		| order by LastWriteTime desc
	
	• Certutil Execute, Certutil.exe is a legitimate built-in command-line program to manage certificates in Windows - ATT&CK T1105,T1140,T1130,S0160
		○ File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%certutil%') 
		| order by LastWriteTime desc
	
	• Bitsadmin Execute, Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM) - ATT&CK T1197,S0190
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%bitsadmin%') 
		| order by LastWriteTime desc
		
	• vssadmin Execute, usually used to execute activity on Volume Shadow copy
		File('%windir%\\Prefetch\\*') 
		| where (Device like '%') 
		| where (FileName like '%vssadmin%') 
            | order by LastWriteTime desc
