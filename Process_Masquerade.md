# Process Masquerading (ATT&CK T1034)
Process running from non-standard locations that appear as legitimate Windows processes.
### Full Query
	Process 
	| where (Device like '%') 
	| where (((((((((((Name == 'conhost.exe') 
	or Name == 'csrss.exe') 
	or Name == 'dllhost.exe')
	or Name == 'explorer.exe')
	or Name == 'iexplore.exe')
	or Name == 'lsass.exe')
	or Name == 'services.exe')
	or Name == 'smss.exe')
	or Name == 'svchost.exe')
	or Name == 'wininit.exe')
	or Name == 'winlogon.exe')
	or Name == 'wmiprvse.exe' 
	| where ((CommandLine !like '%\\System32\\conhost.exe%')
	and (CommandLine !like '%\\System32\\csrss.exe%') 
	and (CommandLine !like '%\\Syswow64\\dllhost.exe%') and (CommandLine !like '%\\system32\\dllhost.exe%')
	and (CommandLine !like '%Windows\\Syswow64%') and (CommandLine !like '%Windows\\explorer%') and (CommandLine != 'explorer.exe')
	and (CommandLine !like '%Program Files (x86)\\Internet Explorer\\iexplore.exe%') and (CommandLine !like '%Program Files\\Internet Explorer\\iexplore.exe%')
	and (CommandLine !like '%\\system32\\lsass.exe%')
	and (CommandLine !like '%\\system32\\services.exe%')
	and (CommandLine !like '%\\System32\\smss.exe%')
	and (CommandLine !like '%Windows\\Syswow64\\svchost%-k%') and (CommandLine !like '%Windows\\system32\\svchost%-k%')
	and (CommandLine !like '%Windows\\wininit.exe%') and (CommandLine != 'wininit.exe')
	and (CommandLine !like '%\\System32\\winlogon.exe%') and (CommandLine != 'winlogon.exe')
	and (CommandLine !like '%Windows\\Syswow64\\wbem\\wmiprvse.exe%') and (CommandLine !like '%Windows\\system32\\wbem\\wmiprvse.exe%'))

### Individual Process Queries
		Process Queries by Name:
    
    ○ ConHost.exe (Command window host)
            Process
		| where (Device like '%') 
		| where (Name == 'conhost.exe') 
		| where (CommandLine !like '%\\System32\\conhost.exe%')
		
	○ csrss.exe (Client Server Runtime Process)
		Process 
		| where (Device like '%') 
		| where (Name == 'csrss.exe') 
		| where (CommandLine !like '%\\System32\\csrss.exe%')
	
	○ Explorer.exe (GUI and user process handler)
		Process 
		| where (Device like '%') 
		| where (Name == 'explorer.exe') 
		| where ((CommandLine !like '%Windows\\Syswow64%') and (CommandLine !like '%Windows\\explorer%') and (CommandLine != 'explorer.exe'))
		
	
	○ Dllhost.exe (DLL loading and managing host)
		Process 
		| where (Device like '%') 
		| where (Name == 'dllhost.exe') 
		| where ((CommandLine !like '%\\Syswow64\\dllhost.exe%') and (CommandLine !like '%\\system32\\dllhost.exe%'))
		
	○ Iexplore.exe (Windows Browser)
		Process 
		| where (Device like '%') 
		| where (Name == 'iexplore.exe') 
		| where ((CommandLine !like '%Program Files (x86)\\Internet Explorer\\iexplore.exe%') and (CommandLine !like '%Program Files\\Internet Explorer\\iexplore.exe%'))
		
	○ lsass.exe (Windows Credential service)
		Process 
		| where (Device like '%') 
		| where (Name == 'lsass.exe') 
		| where (CommandLine !like '%\\system32\\lsass.exe%')
		
	○ Services.exe (Responsible for background processes and tasks)
		Process 
		| where (Device like '%') 
		| where (Name == 'services.exe') 
		| where (CommandLine !like '%\\system32\\services.exe%')
		
	○ Smss.exe (session manager)
		Process 
		| where (Device like '%') 
		| where (Name == 'smss.exe') 
		| where (CommandLine !like '%\\System32\\smss.exe%')
		
	○ Svchost.exe (generic host process for windows services)
		Process 
		| where (Device like '%') 
		| where (Name == 'svchost.exe') 
		| where ((CommandLine !like '%Windows\\Syswow64\\svchost%-k%') and (CommandLine !like '%Windows\\system32\\svchost%-k%'))
		
	○ Wininit.exe (Windows startup and initial background process)
		Process 
		| where (Device like '%') 
		| where (Name == 'wininit.exe') 
		| where ((CommandLine !like '%Windows\\wininit.exe%') and (CommandLine != 'wininit.exe'))
		
	○ Winlogon.exe (Windows logon service)
		Process 
		| where (Device like '%') 
		| where (Name == 'winlogon.exe') 
		| where ((CommandLine !like '%\\System32\\winlogon.exe%') and (CommandLine != 'winlogon.exe'))
	
	○ wmiprvse.exe (WMI service host)
		Process 
		| where (Device like '%') 
		| where (Name == 'wmiprvse.exe') 
		| where ((CommandLine !like '%Windows\\Syswow64\\wbem\\wmiprvse.exe%') and (CommandLine !like '%Windows\\system32\\wbem\\wmiprvse.exe%'))
