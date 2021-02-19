##########
# Pegasus Script is a set of tweaks for OS fine-tuning and automating the routine tasks
# Suppoted Windows 10 Version: Win 10 / Server 2016 / Server 2019
# Author: Denny
# Version: v0.01, 2021-02-19
# Source: https://github.com/dennyamarojr/Pegasus-Script
##########
# Default preset
$tweaks = @(
	### Require administrator privileges ###
	"RequireAdmin",
	"CreateRestorePoint",

	### Privacy Tweaks ###
	"DisableTelemetry",             # "EnableTelemetry",
	"DisableAutoLogger",            # "EnableAutoLogger",
	"DisableDataCollection",        # "EnableDataCollection",
	"DisableErrorReporting",        # "EnableErrorReporting",
	"DisableWindowsFeedback",       # "EnableWindowsFeedback",
	"DisableSignInInfo",            # "EnableSignInInfo",
	"DisableLanguageListAccess",    # "EnableLanguageListAccess",
	"DisableAdvertisingID",         # "EnableAdvertisingID",
	"DisableWelcomeExperience",     # "EnableWelcomeExperience",
	"DisableWindowsTips",           # "EnableWindowsTips",
	"DisableSettingsSuggestedContent",     # "EnableSettingsSuggestedContent",
	"DisableAppsSilentInstalling",     # "EnableAppsSilentInstalling",
	"DisableWhatsNewInWindows",     # "EnableWhatsNewInWindows",
	"DisableTailoredExperiences",   # "EnableTailoredExperiences",
	"DisableWiFiSense",             # "EnableWiFiSense",
	"DisableCortana",               # "EnableCortana",
	"DisableSearchBoxSuggestions",   # "EnableSearchBoxSuggestions",
	# "DisableLocation",             # "EnableLocation",
	# "DisableLocationTracking",      # "EnableLocationTracking",
	"DisableActivityHistory",       # "EnableActivityHistory",
	"DisableSensors",              # "EnableSensors",
	"DisableMapUpdates",            # "EnableMapUpdates",
	"DisableBiometrics",           # "EnableBiometrics",
	"DisableRecentFiles",          # "EnableRecentFiles",
	"DisableClearRecentFiles",     # "EnableClearRecentFiles",
	"SetP2PUpdateDisable",         # "SetP2PUpdateLocal",     # "SetP2PUpdateInternet",
	"DisableBackgroundApps",        # "EnableBackgroundApps",
	# "DisableSmartScreen",         # "EnableSmartScreen",
	"DisableWebSearch",             # "EnableWebSearch",
	"DisableOfficeTelemetry",       # "EnableOfficeTelemetry",
	"DisableOfficeTelemetryAgent",     # "EnableOfficeTelemetryAgent",
	"DisableOfficeSubscriptionHeartbeat",     # "EnableOfficeSubscriptionHeartbeat",
	"DisableOfficeFeedback",       # "EnableOfficeFeedback",
	"DisableOfficeCEIP",           # "EnableOfficeCEIP",
	"DisableVSCTelemetry",         # "EnableVSCTelemetry",
	"DisableNVIDIATelemetry",      # "EnableNVIDIATelemetry",
	"DisableDiagTrack",             # "EnableDiagTrack",
	"DisableWAPPush",               # "EnableWAPPush",
	"DisableDiagSvc",              # "EnableDiagSvc",
	"DisableDiagHub",              # "EnableDiagHub",
	"DenyAppAccessToLocation",      # "AllowAppAccessToLocation",
	"DenyAppAccessToMotionData",      # "AllowAppAccessToMotionData",
	"DenyAppAccessToPhone",      # "AllowAppAccessToPhone",
	"DenyAppAccessToTrustedDevices",     # "AllowAppAccessToTrustedDevices",
	"DenyAppAccessToSyncWithDevices",    # "AllowAppAccessToSyncWithDevices",
	"DenyAppAccessToDiagnosticInfo",     # "AllowAppAccessToDiagnosticInfo",
	"DenyAppAccessToContacts",           # "AllowAppAccessToContacts",
	"DenyAppAccessToNotifications",      # "AllowAppAccessToNotifications",
	"DenyAppAccessToCalendar",           # "AllowAppAccessToCalendar",
	"DenyAppAccessToCallHistory",        # "AllowAppAccessToCallHistory",
	"DenyAppAccessToEmail",              # "AllowAppAccessToEmail",
	"DenyAppAccessToTasks",              # "AllowAppAccessToTasks",
	"DenyAppAccessToMessaging",          # "AllowAppAccessToMessaging",
	"DenyAppAccessToRadios",             # "AllowAppAccessToRadios",
	"DenyAppAccessToBluetooth",          # "AllowAppAccessToBluetooth",
	"DenyAppAccessToAccountInfo",        # "AllowAppAccessToAccountInfo",
	"DenyAppAccessToCamera",             # "AllowAppAccessToCamera",
	"DenyAppAccessToMicrophone",         # "AllowAppAccessToMicrophone",
	"DenyAppAccessToAppShareAndSync",    # "AllowAppAccessToAppShareAndSync",
	"DenyAppAccessToDocuments",          # "AllowAppAccessToDocuments",
	"DenyAppAccessToPictures",           # "AllowAppAccessToPictures",
	"DenyAppAccessToVideos",             # "AllowAppAccessToVideos",
	"DenyAppAccessToFileSystem",         # "AllowAppAccessToFileSystem",
	"DenyAppAccessToCellularData",       # "AllowAppAccessToCellularData",
	"DenyAppAccessToWiFiData",           # "AllowAppAccessToWiFiData",
	"DenyAppAccessToWiFiDirect",         # "AllowAppAccessToWiFiDirect",
	"DenyAppAccessToDownloads",          # "AllowAppAccessToDownloads",
	"DenyAppAccessToEyeTracker",         # "AllowAppAccessToEyeTracker",
	"DenyAppAccessToVoice",              # "AllowAppAccessToVoice",
	"DenyAppAccessToVoiceLocked",        # "AllowAppAccessToVoiceLocked",

	### Security Tweaks ###
	"SetUACLow",                    # "SetUACHigh",     # "SetUACDefault",
	# "EnableSharingMappedDrives",  # "DisableSharingMappedDrives",
	"DisableAdminShares",           # "EnableAdminShares",
	"EnableFirewall",            	# "DisableFirewall",
	# "HideDefenderTrayIcon",       # "ShowDefenderTrayIcon",
	"EnableDefender",            	# "DisableDefender",
	"EnableDefenderCloud",       	# "DisableDefenderCloud",
	# "EnableCtrldFolderAccess",    # "DisableCtrldFolderAccess",
	# "EnableCIMemoryIntegrity",    # "DisableCIMemoryIntegrity",
	# "EnableDefenderAppGuard",     # "DisableDefenderAppGuard",
	"HideAccountProtectionWarn",    # "ShowAccountProtectionWarn",
	# "DisableDownloadBlocking",    # "EnableDownloadBlocking",
	"DisableScriptHost",            # "EnableScriptHost",
	"EnableDotNetStrongCrypto",     # "DisableDotNetStrongCrypto",
	# "EnableMeltdownCompatFlag",     # "DisableMeltdownCompatFlag",
	# "EnableF8BootMenu",           # "DisableF8BootMenu",
	# "DisableBootRecovery",        # "EnableBootRecovery",
	# "DisableRecoveryAndReset",    # "EnableRecoveryAndReset",
	"SetDEPOptOut",                	# "SetDEPOptIn",     # "SetDEPAlwaysOn",

	### Network Tweaks ###
	"SetCurrentNetworkPublic",      # "SetCurrentNetworkPrivate",
	"SetUnknownNetworksPublic",     # "SetUnknownNetworksPrivate",
	"DisableNetDevicesAutoInst",    # "EnableNetDevicesAutoInst",
	"DisableHomeGroups",            # "EnableHomeGroups",
	"DisableSMB1",                  # "EnableSMB1",
	"DisableSMBServer",             # "EnableSMBServer",
	"DisableNetBIOS",            	# "EnableNetBIOS",
	"DisableLMHOSTS",            	# "EnableLMHOSTS",
	"DisableLLMNR",            	    # "EnableLLMNR",
	"DisableSmartNameResolution",   # "EnableSmartNameResolution",
	"DisableProtocolReordering",    # "EnableProtocolReordering",
	#"EnableSecureUpdateLevel",      # "DisableSecureUpdateLevel",
	"DisableLLDP",            	    # "EnableLLDP",
	"DisableLLTD",            	    # "EnableLLTD",
	"DisableMSNetClient",           # "EnableMSNetClient",
	"DisableQoS",            	    # "EnableQoS",
	#"DisableIPv4",            	    # "EnableIPv4",
	#"DisableIPv6",            	    # "EnableIPv6",
	# "DisableNCSIProbe",           # "EnableNCSIProbe",
	"DisableConnectionSharing",     # "EnableConnectionSharing",
	"DisableRemoteAssistance",      # "EnableRemoteAssistance",
	# "EnableRemoteDesktop",        # "DisableRemoteDesktop",

	### Service Tweaks ###
	# "EnableUpdateMSRT",           # "DisableUpdateMSRT",
	"DisableUpdateDriver",          # "EnableUpdateDriver",
	"DisableUpdateAutoDownload",    # "EnableUpdateAutoDownload",
	"DisableUpdateRestart",         # "EnableUpdateRestart",
	"DisableFeatureUpdates",        # "EnableFeatureUpdates",
	"DisableForcedFeatureUpdates",      # "EnableForcedFeatureUpdates",
	"DisableMaintenanceWakeUp",     # "EnableMaintenanceWakeUp",
	# "DisableAutoRestartSignOn",        # "EnableAutoRestartSignOn",
	"DisableSharedExperiences",     # "EnableSharedExperiences",
	"DisableSearchHistory",         # "EnableSearchHistory",
	# "EnableClipboardHistory",     # "DisableClipboardHistory",
	"DisableAutoplay",              # "EnableAutoplay",
	"DisableAutorun",               # "EnableAutorun",
	# "EnableStorageSense",         # "DisableStorageSense",
	"DisableDefragmentation",       # "EnableDefragmentation",
	"DisableSuperfetch",            # "EnableSuperfetch",
	# "DisableIndexing",            # "EnableIndexing",
	"SetBIOSTimeUTC",               # "SetBIOSTimeLocal",
	"DisableHibernation",           # "EnableHibernation",
	# "DisableSleepButton",           # "EnableSleepButton",
	"DisableSleepTimeout",          # "EnableSleepTimeout",
	"DisableFastStartup",           # "EnableFastStartup",
	"DisableAutoRebootOnCrash",          # "EnableAutoRebootOnCrash",

	### UI Tweaks ###
	"DisableActionCenter",          # "EnableActionCenter",
	# "DisableLockScreen",          # "EnableLockScreen",
	# "DisableLockScreenRS1",       # "EnableLockScreenRS1",
	"HideNetworkFromLockScreen",    # "ShowNetworkOnLockScreen",
	"HideShutdownFromLockScreen",   # "ShowShutdownOnLockScreen",
	# "DisableLockScreenBlur",      # "EnableLockScreenBlur",
	# "DisableAeroShake",           # "EnableAeroShake",
	"DisableAccessibilityKeys",     # "EnableAccessibilityKeys",
	"ShowTaskManagerDetails"        # "HideTaskManagerDetails",
	"ShowFileOperationsDetails",    # "HideFileOperationsDetails",
	"EnableFileDeleteConfirm",      # "DisableFileDeleteConfirm",
	"ShowTaskbarSearchIcon",        # "HideTaskbarSearch",      # "ShowTaskbarSearchBox",
	"HideTaskView",                 # "ShowTaskView",
	# "ShowLargeTaskbarIcons",        # "ShowSmallTaskbarIcons",
	# "SetTaskbarCombineAlways",      # "SetTaskbarCombineWhenFull",     # "SetTaskbarCombineNever",
	"HideTaskbarPeopleIcon",        # "ShowTaskbarPeopleIcon",
	"ShowTrayIcons",                # "HideTrayIcons",
	# "ShowSecondsInTaskbar",       # "HideSecondsFromTaskbar",
	"DisableSearchAppInStore",      # "EnableSearchAppInStore",
	"DisableNewAppPrompt",          # "EnableNewAppPrompt",
	"HideRecentlyAddedApps",        # "ShowRecentlyAddedApps",
	"HideMostUsedApps",             # "ShowMostUsedApps",
	# "SetWinXMenuPowerShell",      # "SetWinXMenuCmd",
	# "SetControlPanelCategories",  # "SetControlPanelLargeIcons",  # "SetControlPanelSmallIcons",
	"DisableShortcutInName",        # "EnableShortcutInName",
	# "HideShortcutArrow",          # "ShowShortcutArrow",
	"SetVisualFXPerformance",       # "SetVisualFXAppearance",
	# "EnableTitleBarColor",        # "DisableTitleBarColor",
	"SetAppsDarkMode",              # "SetAppsLightMode",
	"SetSystemDarkMode",            # "SetSystemLightMode",
	# "AddENKeyboard",              # "RemoveENKeyboard",
	"EnableNumlock",              	# "DisableNumlock",
	# "DisableEnhPointerPrecision",    # "EnableEnhPointerPrecision",
	# "SetSoundSchemeNone",         # "SetSoundSchemeDefault",
	"DisableStartupSound",          # "EnableStartupSound",
	# "DisableChangingSoundScheme",    # "EnableChangingSoundScheme",
	# "EnableVerboseStatus",        # "DisableVerboseStatus",
	"DisableF1HelpKey",             # "EnableF1HelpKey",

	### Explorer UI Tweaks ###
	"ShowKnownExtensions",          # "HideKnownExtensions",
	"ShowHiddenFiles",              # "HideHiddenFiles",
	"HideSyncNotifications"         # "ShowSyncNotifications",
	"HideRecentShortcuts",          # "ShowRecentShortcuts",
	"SetExplorerThisPC",            # "SetExplorerQuickAccess",
	"ShowThisPCOnDesktop",          # "HideThisPCFromDesktop",
	"Hide3DObjectsFromThisPC",      # "Show3DObjectsInThisPC",
	# "Hide3DObjectsFromExplorer",    # "Show3DObjectsInExplorer",
	"HideDesktopFromThisPC",        # "ShowDesktopInThisPC",
	# "HideDesktopFromExplorer",      # "ShowDesktopInExplorer",
	"HideDocumentsFromThisPC",      # "ShowDocumentsInThisPC",
	# "HideDocumentsFromExplorer",    # "ShowDocumentsInExplorer",
	"HideDownloadsFromThisPC",      # "ShowDownloadsInThisPC",
	# "HideDownloadsFromExplorer",    # "ShowDownloadsInExplorer",
	"HideMusicFromThisPC",          # "ShowMusicInThisPC",
	# "HideMusicFromExplorer",        # "ShowMusicInExplorer",
	"HidePicturesFromThisPC",       # "ShowPicturesInThisPC",
	# "HidePicturesFromExplorer",     # "ShowPicturesInExplorer",
	"HideVideosFromThisPC",         # "ShowVideosInThisPC",
	# "HideVideosFromExplorer",       # "ShowVideosInExplorer",
	# "DisableThumbnails",          # "EnableThumbnails",
	"DisableThumbnailCache",        # "EnableThumbnailCache",
	"DisableThumbsDBOnNetwork",     # "EnableThumbsDBOnNetwork",

	### Application Tweaks ###
	"DisableOneDrive",              # "EnableOneDrive",
	"UninstallOneDrive",            # "InstallOneDrive",
	# "UninstallMsftBloat",         # "InstallMsftBloat",
	# "UninstallThirdPartyBloat",   # "InstallThirdPartyBloat",
	"DebloatMsftApps",
	"DebloatThirdPartyApps",
	# "UninstallWindowsStore",      # "InstallWindowsStore",
	# "DisableXboxFeatures",        # "EnableXboxFeatures",
	"CleanupRegistry",
	"DisableMeetNow",               # "EnableMeetNow",
	"DisableFullscreenOptims",            # "EnableFullscreenOptims",
	"DisableAdobeFlash",            # "EnableAdobeFlash",
	"DisableEdgePreload",            # "EnableEdgePreload",
	"DisableEdgeShortcutCreation",            # "EnableEdgeShortcutCreation",
	"DisableIEFirstRun",            # "EnableIEFirstRun",
	"DisableFirstLogonAnimation",             # "EnableFirstLogonAnimation",
	"DisableMediaSharing",          # "EnableMediaSharing",
	# "DisableMediaOnlineAccess",           # "EnableMediaOnlineAccess",
	# "UninstallMediaPlayer",       	# "InstallMediaPlayer",
	"UninstallInternetExplorer",  	# "InstallInternetExplorer",
	"UninstallWorkFolders",       	# "InstallWorkFolders",
	"UninstallPowerShellV2",        # "InstallPowerShellV2",
	# "InstallLinuxSubsystem",      # "UninstallLinuxSubsystem",
	"InstallNET23",                 # "UninstallNET23",
	"SetPhotoViewerAssociation",    # "UnsetPhotoViewerAssociation",
	"AddPhotoViewerOpenWith",       # "RemovePhotoViewerOpenWith",
	# "UninstallPDFPrinter",        # "InstallPDFPrinter",
	"UninstallXPSPrinter",          # "InstallXPSPrinter",
	"RemoveFaxPrinter",             # "AddFaxPrinter",
	# "UninstallFaxAndScan",        # "InstallFaxAndScan",

	### Maintenance Tweaks ###
	"ImageCleanup"                  # "InstallFaxAndScan",

	### Server Specific Tweaks ###
	# "HideServerManagerOnLogin",   # "ShowServerManagerOnLogin",
	# "DisableShutdownTracker",     # "EnableShutdownTracker",
	# "DisablePasswordPolicy",      # "EnablePasswordPolicy",
	# "DisableCtrlAltDelLogin",     # "EnableCtrlAltDelLogin",
	# "DisableIEEnhancedSecurity",  # "EnableIEEnhancedSecurity",
	# "EnableAudio",                # "DisableAudio",

	### Unpinning ###
	#"UnpinStartMenuTiles",
	#"UnpinTaskbarIcons",

	### Auxiliary Functions ###
)

#no errors throughout
$ErrorActionPreference = 'SilentlyContinue'



##########
#region Privacy Tweaks
##########

Function DisableTelemetry {
	Write-Output "Disabling Telemetry..."
	Write-Host "Configuring diagnostic data to security only..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection")) {
		New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
	#Disable telemetry in data collection policy
	Write-Host "Disabling telemetry in data collection..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Type "DWORD" -Value 0 -Force
	#Disable Insider Preview Builds
	Write-Output "Disabling Insider Preview Builds..."
	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name AllowBuildPreview -Type "DWORD" -Value 0 -Force
	#Software Protection Platform
	#Opt out of sending KMS client activation data to Microsoft
	Write-Output "Opt out of sending KMS client activation data to Microsoft"
	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoGenTicket -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoAcquireGT -Type "DWORD" -Value 1 -Force
	#Disable Customer Experience Improvement (CEIP/SQM)
	Write-Host "Disabling Customer Experience Improvement (CEIP/SQM) for all users..."
	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type "DWORD" -Value "0" -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0
	#Disable Application Impact Telemetry (AIT)
	Write-Host "Disabling Application Impact Telemetry (AIT)..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type "DWORD" -Value "0" -Force
	#Disable Inventory Collector
	Write-Host "Disabling Inventory Collector..."
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type "DWORD" -Value "1" -Force
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0
	Write-Host "Disabling Compatibility Telemetry..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -Name "CompatTelRunner.exe" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
	Write-Host "Blocking Compatibility Telemetry executable to be running..."
	takeown /f "C:\Windows\System32\CompatTelRunner.exe" /a
	icacls "C:\Windows\System32\CompatTelRunner.exe" /grant:r Administrators:F /c
	taskkill /im CompatTelRunner.exe /f
	Rename-Item "C:\Windows\System32\CompatTelRunner.exe" -NewName "C:\Windows\System32\CompatTelRunner.exe.bak"
	icacls "C:\Windows\System32\CompatTelRunner.exe.bak" /inheritance:r /remove "Administrators" "Authenticated Users" "Users" "System"
	Write-Host "Disabling CompatTelRunner using Windows Registry..."
	# Source for this: https://beebom.com/disable-compattelrunner-exe-windows-10/#:~:text=Disable%20CompatTelRunner%20Using%20Task%20Scheduler%20Open%20Windows%20Task,each%20option%29.%20Disable%20all%20tasks%20in%20that%20folder.
	Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController'
	Rename-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController' -NewName "TelemetryControllerX"
	# Disable Application Experience (Compatibility Telemetry)
	Write-Host "Disabling Application Experience (Compatibility Telemetry) scheduled tasks..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\PcaPatchDbTask" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\StartupAppTask" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\AitAgent" | Out-Null
	#Disable Customer Experience Improvement Program
	Write-Host "Disabling Customer Experience Improvement scheduled tasks..."
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" | Out-Null
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" | Out-Null
	#Disable Webcam Telemetry (devicecensus.exe)
	Write-Host "Disabling Webcam Telemetry (devicecensus.exe) scheduled tasks..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Device Information\Device" | Out-Null
}

Function EnableTelemetry {
	Write-Output "Enabling Telemetry..."
	Write-Host "Configuring diagnostic data to optional..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 3 -Type "DWORD" -Force
	#Enable telemetry in data collection policy
	Write-Host "Enabling telemetry in data collection..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Force -ErrorAction SilentlyContinue
	#Enable Insider Preview Builds
	Write-Output "Enabling Insider Preview Builds..."
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Force -ErrorAction SilentlyContinue
	#Software Protection Platform
	#Opt in of sending KMS client activation data to Microsoft
	Write-Output "Opt in of sending KMS client activation data to Microsoft..."
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force -ErrorAction SilentlyContinue
	#Enable Customer Experience Improvement (CEIP/SQM)
	Write-Host "Enabling Customer Experience Improvement (CEIP/SQM) for all users..."
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Force -ErrorAction SilentlyContinue
	#Enable Application Impact Telemetry (AIT)
	Write-Host "Enabling Application Impact Telemetry (AIT)..."
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Force -ErrorAction SilentlyContinue
	#Enable Inventory Collector
	Write-Host "Enabling Inventory Collector..."
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Force -ErrorAction SilentlyContinue
	Write-Host "Enabling Compatibility Telemetry..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Force -ErrorAction SilentlyContinue
	Write-Host "Allowing Compatibility Telemetry executable to run..."
	takeown /f "C:\Windows\System32\CompatTelRunner.exe.bak" /a
	icacls "C:\Windows\System32\CompatTelRunner.exe.bak" /grant:r Administrators:F /c
	Rename-Item "C:\Windows\System32\CompatTelRunner.exe.bak" -NewName "C:\Windows\System32\CompatTelRunner.exe"
	icacls "C:\Windows\System32\CompatTelRunner.exe" /reset
	Write-Host "Enabling CompatTelRunner using Windows Registry..."
	# Source for this: https://beebom.com/disable-compattelrunner-exe-windows-10/#:~:text=Disable%20CompatTelRunner%20Using%20Task%20Scheduler%20Open%20Windows%20Task,each%20option%29.%20Disable%20all%20tasks%20in%20that%20folder.
	Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController'
	Rename-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryControllerX' -NewName "TelemetryController"
	# Enable Application Experience (Compatibility Telemetry)
	Write-Host "Enabling Application Experience (Compatibility Telemetry) scheduled tasks..."
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\StartupAppTask" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\AitAgent" | Out-Null
	#Enable Customer Experience Improvement Program
	Write-Host "Enabling Customer Experience Improvement scheduled tasks..."
	Enable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Enable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" | Out-Null
	Enable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" | Out-Null
	#Enable Webcam Telemetry (devicecensus.exe)
	Write-Host "Enabling Webcam Telemetry (devicecensus.exe) scheduled tasks..."
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Device Information\Device" | Out-Null
}

# Remove AutoLogger file and restrict directory
Function DisableAutoLogger {
    Write-Host "Removing AutoLogger file and restricting directory..."
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item -Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
}

# Unrestrict AutoLogger directory
Function EnableAutoLogger {
    Write-Host "Unrestricting AutoLogger directory..."
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null
}

Function DisableDataCollection {
	#Disable Data Collection
	Write-Host "Disabling Data Collection..."
	#Disable feedback on write (sending typing info) for current user
	Write-Host "Disabling feedback on write (sending typing info) for current user..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force
	#Disable feedback on write (sending typing info) for all users
	Write-Host "Disabling feedback on write (sending typing info) for all users..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Input\TIPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Input\TIPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force
	#Disable device metadata retrieval (breaks auto updates)
	Write-Host "Disabling device metadata retrieval for all users..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type "DWORD" -Value 1 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type "DWORD" -Value 1 -Force
	#Disable Windows Insider Service
	Write-Host "Disabling Windows Insider service..."
	Stop-Service "wisvc" 
	Set-Service "wisvc" -StartupType Disabled
	#Do not let Microsoft try features on this build
	Write-Host "Preventing Microsoft try features on this Windows build..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Type "DWORD" -Value 0 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Type "DWORD" -Value 0 -Force
	#Remove "Windows Insider Program" from Settings
	Write-Host "Removing getting preview builds of Windows..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value "1" -Force
    # Turn off handwriting recognition error reporting
    Write-Host "Turning off handwriting recognition error reporting..."
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
	# Disabling other data collection stuff
	Write-Host "Disabling active prompting (pings to MSFT NCSI server)..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Value 0 -Type "DWORD" -Force
	#Turn off tracking of app usage
	Write-Host "Disabling tracking of app usage..."
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Type "DWORD" -Value 1 -Force
	#Do not show recent apps when the mouse is pointing to the upper-left corner of the screen
	Write-Host "Disabling show recent apps when the mouse is pointing to the upper-left corner of the screen..."
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableRecentApps" -Type "DWORD" -Value 1 -Force
	#Turn off switching between recent apps
	Write-Host "Turning off switching between recent apps..."
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "TurnOffBackstack" -Type "DWORD" -Value 1 -Force
	#Disable tracking of app starts
	Write-Host "Disabling tracking of app starts..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type "DWORD" -Force
	# Restrict License Manager
	# This can cause an issue when download new apps in Microsoft Store, due the license information that Microsoft Store needs to verify for download new apps and update the apps
	# Write-Output "Restricting License Manager..."
	# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LicenseManager" -Name Start -Type "DWORD" -Value 4 -Force
	#Disable Live Tiles
	Write-Output "Disabling Live Tiles..."
	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Type "DWORD" -Value 1 -Force
	#Disable Live Tiles push notifications
	Write-Output "Disabling Live Tiles push notifications..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type "DWORD" -Value 1 -Force
}

Function EnableDataCollection {
	#Enable Data Collection
	Write-Host "Enabling Data Collection..."
	#Enable feedback on write (sending typing info) for current user
	Write-Host "Enabling feedback on write (sending typing info) for current user..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Force -ErrorAction SilentlyContinue
	#Enable feedback on write (sending typing info) for all users
	Write-Host "Enabling feedback on write (sending typing info) for all users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Force -ErrorAction SilentlyContinue
	#Enable device metadata retrieval
	Write-Host "Enabling device metadata retrieval for all users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Force -ErrorAction SilentlyContinue
	#Enable Windows Insider Service
	Write-Host "Enabling Windows Insider service..."
	Set-Service "wisvc" -StartupType Manual
	Start-Service "wisvc"
	#Let Microsoft try features on this build
	Write-Host "Let Microsoft try features on this Windows build..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Force -ErrorAction SilentlyContinue
	#Restore "Windows Insider Program" from Settings
	Write-Host "Restoring getting preview builds of Windows..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Force -ErrorAction SilentlyContinue
    # Turn on handwriting recognition error reporting
    Write-Host "Restoring handwriting recognition error reporting..."
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Force -ErrorAction SilentlyContinue
	# Enabling other data collection stuff
	Write-Host "Enabling active prompting (pings to MSFT NCSI server)..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Force -ErrorAction SilentlyContinue
	#Turn on tracking of app usage
	Write-Host "Enabling tracking of app usage..."
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Force -ErrorAction SilentlyContinue
	#Show recent apps when the mouse is pointing to the upper-left corner of the screen
	Write-Host "Enabling show recent apps when the mouse is pointing to the upper-left corner of the screen..."
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableRecentApps" -Force -ErrorAction SilentlyContinue
	#Turn on switching between recent apps
	Write-Host "Turning on switching between recent apps..."
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "TurnOffBackstack" -Force -ErrorAction SilentlyContinue
	#Enable tracking of app starts
	Write-Host "Enabling tracking of app starts..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type "DWORD" -Force
	#Enable License Manager
	Write-Output "Enabling License Manager..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LicenseManager" -Name Start -Type "DWORD" -Value 3 -Force
	#Enable Live Tiles
	Write-Output "Enabling Live Tiles..."
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Force -ErrorAction SilentlyContinue
	#Enable Live Tiles push notifications
	Write-Output "Enabling Live Tiles push notifications..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Force -ErrorAction SilentlyContinue
}

Function DisableErrorReporting {
	#Disable error reporting
	Write-Host "Disabling Error Reporting..."
	#Disable Windows Error Reporting (WER)
	Write-Host "Disabling Windows Error Reporting (WER)..."
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value 1 -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value "1" -Force
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value "1" -Force
	#DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
	Write-Host "Changing DefaultConsent to 0..."
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Type "DWORD" -Value "0" -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultOverrideBehavior" -Type "DWORD" -Value "1" -Force
	#Disable WER sending second-level data
	Write-Host "Disabling WER sending second-level data..."
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Type "DWORD" -Value "1" -Force
	#Disable WER crash dialogs, popups
	Write-Host "Disabling WER crash dialogs, popups..."
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Type "DWORD" -Value "1" -Force
	Write-Host "Disabling Windows Error Reporting Tasks..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
	Write-Host "Disabling Windows Error Reporting Services..."
	Stop-Service "WerSvc"
	Set-Service "WerSvc" -StartupType Disabled
	Stop-Service "wercplsupport"
	Set-Service "wercplsupport" -StartupType Disabled
}

Function EnableErrorReporting {
	#Enable error reporting
	Write-Host "Enabling Error Reporting..."
	#Enable Windows Error Reporting (WER)
	Write-Host "Enabling Windows Error Reporting (WER)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Force -ErrorAction SilentlyContinue
	#DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
	Write-Host "Restoring DefaultConsent to Always ask (default)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultOverrideBehavior" -Force -ErrorAction SilentlyContinue
	#Enable WER sending second-level data
	Write-Host "Enabling WER sending second-level data..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Force -ErrorAction SilentlyContinue
	#Enable WER crash dialogs, popups
	Write-Host "Enabling WER crash dialogs, popups..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Force -ErrorAction SilentlyContinue
	Write-Host "Enabling Windows Error Reporting Tasks..."
	Enable-ScheduledTask -TaskName "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
	Write-Host "Enabling Windows Error Reporting Services..."
	Set-Service "WerSvc" -StartupType Manual 
	Set-Service "wercplsupport" -StartupType Manual
}

Function DisableWindowsFeedback {
	Write-Host "Disabling Windows Feedback..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

Function EnableWindowsFeedback {
	Write-Host "Enabling Windows Feedback..." 
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Force -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

Function DisableSignInInfo {
	Write-Host "Disabling Sign In Info..."
	$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID 
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name "OptOut" -Type DWord -Value 1 -Force
}

Function EnableSignInInfo {
	Write-Host "Enabling Sign In Info..."
	$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID 
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name "OptOut" -Force -ErrorAction SilentlyContinue
}

Function DisableLanguageListAccess {
    #Turn off Let websites provide locally relevant content by accessing my language list
	Write-Host "Disabling Language List Access..."
	Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type "DWORD" -Value 1 -Force
}

Function EnableLanguageListAccess {
    #Turn on Let websites provide locally relevant content by accessing my language list
	Write-Host "Enabling Language List Access..."
	Remove-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Force -ErrorAction SilentlyContinue
}

Function DisableAdvertisingID {
	Write-Host "Disabling Advertising ID..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWORD" -Value 0 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type "DWORD" -Value 1 -Force
}

Function EnableAdvertisingID {
	Write-Host "Enabling Advertising ID..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Force -ErrorAction SilentlyContinue
}

Function DisableWelcomeExperience {
	Write-Host "Disabling Welcome Experience..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0 -Force
}

Function EnableWelcomeExperience {
	Write-Host "Enabling Welcome Experience..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 1 -Force
}

Function DisableWindowsTips {
	Write-Host "Disabling Windows Tips..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 -Force
}

Function EnableWindowsTips {
	Write-Host "Enabling Windows Tips..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1 -Force
}

Function DisableSettingsSuggestedContent {
	Write-Host "Disabling Settings Suggested Content..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0 -Force
}

Function EnableSettingsSuggestedContent {
	Write-Host "Enabling Settings Suggested Content..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 1 -Force
}

Function DisableAppsSilentInstalling {
	Write-Host "Disabling silent apps installing and automatic installation of suggest apps..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RemediationRequired" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SlideshowEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-202913Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-202914Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280797Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280811Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280812Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280813Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280814Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280815Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280810Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280817Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310091Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310092Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310094Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314558Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314562Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314563Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314566Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314567Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338380Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338381Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338382Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338386Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-346480Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-346481Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353695Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353697Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353699Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000044Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000045Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000105Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000106Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000161Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000162Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000163Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000164Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000165Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000166Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type "DWORD" -Value 0 -Force
	Write-Host "Removing SuggestedApps..."
	Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Recurse -ErrorAction SilentlyContinue
	#Disable targeted tips
	Write-Host "Disabling targeted tips..."
	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type "DWORD" -Value 1 -Force
	#Disable Windows Ink Workspace
	Write-Host "Disabling Windows Ink Workspace..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0 -Force
}

Function EnableAppsSilentInstalling {
	Write-Host "Enabling silent apps installing and automatic installation of suggest apps..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RemediationRequired" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SlideshowEnabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-202913Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-202914Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280797Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280811Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280812Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280813Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280814Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280815Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280810Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280817Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310091Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310092Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310094Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314558Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314562Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314563Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314566Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314567Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338380Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338381Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338382Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338386Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-346480Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-346481Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353695Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353697Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353699Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000044Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000045Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000105Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000106Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000161Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000162Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000163Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000164Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000165Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000166Enabled" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type "DWORD" -Value 1 -Force
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Force -ErrorAction SilentlyContinue
	Write-Host "Enabling SuggestedApps..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\" -Name "SuggestedApps" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "2FE3CB00.PicsArt-PhotoStudio_crhqpqs3x1ygc" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "5319275A.WhatsAppDesktop_cv1g1gvanyjgm" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "6F71D7A7.HotspotShieldFreeVPN_nsbqstbb9qxb6" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "828B5831.HiddenCityMysteryofShadows_ytsefhwckbdv6" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "9E2F88E3.Twitter_wgeqdkkx372wm" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "AdobeSystemsIncorporated.AdobePhotoshopExpress_ynb6jyjzte8ga" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "DolbyLaboratories.DolbyAccess_rz1tebttyb220" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "HuluLLC.HuluPlus_fphbd361v8tya" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.BingNews_8wekyb3d8bbwe" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.BingWeather_8wekyb3d8bbwe" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.MSPaint_8wekyb3d8bbwe" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.Todos_8wekyb3d8bbwe" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.YourPhone_8wekyb3d8bbwe" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.ZuneVideo_8wekyb3d8bbwe" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Nordcurrent.CookingFever_m9bz608c1b9ra" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "PLRWorldwideSales.FishdomPlayrix_1feq88045d2v2" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "ROBLOXCorporation.ROBLOX_55nm5eh3cm0pr" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "SpotifyAB.SpotifyMusic_zpdnekdrzrea0" -Type "DWORD" -Value 1 -Force
}

Function DisableWhatsNewInWindows {
	Write-Host "Disabling Whats New In Windows..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
	}
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -Type DWord -Value 0 -Force
}

Function EnableWhatsNewInWindows {
	Write-Host "Enabling Whats New In Windows..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
	}
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -Type DWord -Value 1 -Force
}

Function DisableTailoredExperiences {
	Write-Host "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Force | Out-Null
	}
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -Type DWord -Value 0 -Force
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type "DWORD" -Value 1 -Force
	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type "DWORD" -Value 1 -Force
}

Function EnableTailoredExperiences {
	Write-Host "Enabling Tailored Experiences..."
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -Type DWord -Value 1 -Force
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue
}

Function DisableWiFiSense {
	Write-Output "Disabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0 -Force
}

Function EnableWiFiSense {
	Write-Output "Enabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1 -Force
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Force -ErrorAction SilentlyContinue
}

Function DisableCortana {
	Write-Host "Disabling Cortana..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Type "DWORD" -Value 0 -Force
    #Disable search web when searching pc
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type "DWORD" -Value 1 -Force
    #Disable search web when searching pc over metered connections
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Type "DWORD" -Value 0 -Force
    #Disable search indexing encrypted items / stores
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Type "DWORD" -Value 0 -Force
    #Disable location based info in searches
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Type "DWORD" -Value 0 -Force
    #Disable language detection
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AlwaysUseAutoLangDetection" -Type "DWORD" -Value 0 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "value" -Type "DWORD" -Value 0 -Force
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaInAmbientMode" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HasAboveLockTips" -Type "DWORD" -Value 0 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaInAmbientMode" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type "DWORD" -Value 0 -Force
	Write-Host "Disabling Bing Search..."
	New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\" -Name "Search" -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type "DWORD" -Value 0 -Force
	# Let Cortana listen for my commands when I press Windows key + C
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "VoiceShortcut" -Type "DWORD" -Value 0 -Force
	Write-Host "Opt out from Windows privacy consent..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type "DWORD" -Force
	Write-Host "Disabling text and handwriting collection..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type "DWORD" -Value 0 -Force
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 -Force
	Write-Host "Disabling cloud speech recognition for current user..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 0 -Type "DWORD" -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
	}
	Write-Host "Disabling cloud speech recognition for all users..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 0 -Type "DWORD" -Force
	Write-Host "Disabling voice activation and model download for all users..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Force | Out-Null
	}
	# Disable  Let Cortana respond to "Hey Cortana"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationDefaultOn" -Value 0 -Type "DWORD" -Force
	# Disable  Cortana even when my device is locked
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationEnableAboveLockscreen" -Value 0 -Type "DWORD" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Value 0 -Type "DWORD" -Force
    Write-Host "Blocking Cortana UDP/TCP Traffic in Windows Firewall..."
    # Block Cortana ActionUriServer
    New-NetFirewallRule -DisplayName "Block Cortana ActionUriServer.exe" -Description "Block Cortana Outbound UDP/TCP Traffic" -Direction Outbound -Action Block -Protocol Any -LocalPort Any -Program "%SystemRoot%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\ActionUriServer.exe"
    # Block Cortana PlacesServer
    New-NetFirewallRule -DisplayName "Block Cortana PlacesServer.exe" -Description "Block Cortana Outbound UDP/TCP Traffic" -Direction Outbound -Action Block -Protocol Any -LocalPort Any -Program "%SystemRoot%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\PlacesServer.exe"
    # Block Cortana RemindersServer
    New-NetFirewallRule -DisplayName "Block Cortana RemindersServer.exe" -Description "Block Cortana Outbound UDP/TCP Traffic" -Direction Outbound -Action Block -Protocol Any -LocalPort Any -Program "%SystemRoot%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe"
    # Block Cortana RemindersShareTargetApp
    New-NetFirewallRule -DisplayName "Block Cortana RemindersShareTargetApp.exe" -Description "Block Cortana Outbound UDP/TCP Traffic" -Direction Outbound -Action Block -Protocol Any -LocalPort Any -Program "%SystemRoot%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersShareTargetApp.exe"
    # Block Cortana Cortana SearchUI
    New-NetFirewallRule -DisplayName "Block Cortana SearchUI.exe" -Description "Block Cortana Outbound UDP/TCP Traffic" -Direction Outbound -Action Block -Protocol Any -LocalPort Any -Program "%SystemRoot%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe"
    # Block Cortana Cortana Package
    New-NetFirewallRule -DisplayName "Block Cortana Package" -Description "Block Cortana Outbound UDP/TCP Traffic" -Direction Outbound -Action Block -Protocol Any -LocalPort Any -Package "S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742"
    Write-Host "Blocking SearchApp Outbound UDP/TCP Traffic in Windows Firewall..."
    # Block SearchApp
    New-NetFirewallRule -DisplayName "Block SearchApp.exe" -Description "Block SearchApp.exe Outbound UDP/TCP Traffic" -Direction Outbound -Action Block -Protocol Any -LocalPort Any -Program "%SystemRoot%\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe"
    # Block Windows Search Package
    New-NetFirewallRule -DisplayName "Block Windows Search Package" -Description "Block Windows Search Package Outbound UDP/TCP Traffic" -Direction Outbound -Action Block -Protocol Any -LocalPort Any -Package "S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757"
}

Function EnableCortana {
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AlwaysUseAutoLangDetection" -Force -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "value" -Type "DWORD" -Value 1 -Force
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaInAmbientMode" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaInAmbientMode" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Force -ErrorAction SilentlyContinue
	Write-Host "Opt in from Windows privacy consent..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Force -ErrorAction SilentlyContinue
	Write-Host "Enabling text and handwriting collection..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type "DWORD" -Value 0 -Force
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Force -ErrorAction SilentlyContinue
	Write-Host "Enabling cloud speech recognition for current user..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Force -ErrorAction SilentlyContinue
	Write-Host "Enabling cloud speech recognition for all users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Force -ErrorAction SilentlyContinue
	Write-Host "Enabling voice activation and model download for all users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationDefaultOn" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationEnableAboveLockscreen" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Force -ErrorAction SilentlyContinue
    Write-Host "Allowing SearchApp Outbound UDP/TCP Traffic in Windows Firewall..."
    # Allow Cortana ActionUriServer
    Remove-NetFirewallRule -DisplayName "Block Cortana ActionUriServer.exe"
    # Allow Cortana PlacesServer
    Remove-NetFirewallRule -DisplayName "Block Cortana PlacesServer.exe"
    # Allow Cortana RemindersServer
    Remove-NetFirewallRule -DisplayName "Block Cortana RemindersServer.exe"
    # Allow Cortana RemindersShareTargetApp
    Remove-NetFirewallRule -DisplayName "Block Cortana RemindersShareTargetApp.exe"
    # Allow Cortana Cortana SearchUI
    Remove-NetFirewallRule -DisplayName "Block Cortana SearchUI.exe"
    # Allow Cortana Cortana Package
    Remove-NetFirewallRule -DisplayName "Block Cortana Package"
    Write-Host "Allowing SearchApp Outbound UDP/TCP Traffic in Windows Firewall..."
    # Allow SearchApp
    Remove-NetFirewallRule -DisplayName "Block SearchApp.exe"
    # Allow Windows Search Package
    Remove-NetFirewallRule -DisplayName "Block Windows Search Package"
}

Function DisableSearchBoxSuggestions {
	Write-Host "Disabling Search Box Suggestions..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -Type DWord -Value 1 -Force
}

Function EnableSearchBoxSuggestions {
	Write-Host "Enabling Search Box Suggestions..."
	Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -Force -ErrorAction SilentlyContinue
}

Function DisableLocation {
	#Check if Location and Sensors key exist in Windows Registry
	Write-Host "Checking if Location and Sensors key exist in Windows Registry..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	#Turn off Windows Location Provider
	Write-Host "Disabling Windows Location Provider..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type "DWORD" -Value "1" -Force
	#Turn off location scripting
	Write-Host "Disabling location scripting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type "DWORD" -Value "1" -Force
	#Turn off location
	Write-Host "Disabling location..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type "DWORD" -Value "1" -Force
}

Function EnableLocation {
	#Enable Windows Location Provider
	Write-Host "Enabling Windows Location Provider..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Force -ErrorAction SilentlyContinue
	#Enable location scripting
	Write-Host "Enabling location scripting..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Force -ErrorAction SilentlyContinue
	#Enable location
	Write-Host "Enabling location..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Force -ErrorAction SilentlyContinue
}

# Disable Location Tracking
Function DisableLocationTracking {
	Write-Output "Disabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}

# Enable Location Tracking
Function EnableLocationTracking {
	Write-Output "Enabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1
}

# Disable Activity History feed in Task View - Note: The checkbox "Let Windows collect my activities from this PC" remains checked even when the function is disabled
Function DisableActivityHistory {
	Write-Output "Disabling Activity History..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0 -Force
}

# Enable Activity History feed in Task View
Function EnableActivityHistory {
	Write-Output "Enabling Activity History..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -ErrorAction SilentlyContinue
}

# Disable sensor features, such as screen auto rotation
Function DisableSensors {
	Write-Output "Disabling sensors..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1
}

# Enable sensor features
Function EnableSensors {
	Write-Output "Enabling sensors..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -ErrorAction SilentlyContinue
}

Function DisableMapUpdates {
	#Disable Auto Downloading Maps
	Write-Host "Disabling Auto Downloading Maps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AllowUntriggeredNetworkTrafficOnSettingsPage" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Type "DWORD" -Value 0 -Force
	Write-Output "Disabling automatic Maps updates..."
	If (!(Test-Path "HKLM:\SYSTEM\Maps")) {
		New-Item -Path "HKLM:\SYSTEM\Maps" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

Function EnableMapUpdates {
	#Enable Auto Downloading Maps
	Write-Host "Enabling Auto Downloading Maps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AllowUntriggeredNetworkTrafficOnSettingsPage" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Force -ErrorAction SilentlyContinue
	Write-Output "Enable automatic Maps updates..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue
}

# Disable biometric features
# Note: If you log on using biometrics (fingerprint, Windows Hello etc.) it's recommended to create a password recovery disk before applying this tweak.
Function DisableBiometrics {
	Write-Output "Disabling biometric services..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Type DWord -Value 0
}

# Enable biometric features
Function EnableBiometrics {
	Write-Output "Enabling biometric services..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -ErrorAction SilentlyContinue
}

# Disable recent files lists
# Stops creating most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications.
Function DisableRecentFiles {
	Write-Host "Do not keep history of recently opened documents..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type "DWORD" -Value 1 -Force
}

# Enable recent files lists
Function EnableRecentFiles {
	Write-Output "Enabling recent files lists..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -ErrorAction SilentlyContinue
}

# Enable clearing of recent files on exit
# Empties most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications during every logout.
Function EnableClearRecentFiles {
	Write-Output "Enabling clearing of recent files on exit..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type DWord -Value 1
}

# Disable clearing of recent files on exit
Function DisableClearRecentFiles {
	Write-Output "Disabling clearing of recent files on exit..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -ErrorAction SilentlyContinue
}

# Disable Windows Update P2P delivery optimization completely
# Warning: Completely disabling delivery optimization can break Windows Store downloads - see https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/281
Function SetP2PUpdateDisable {
	Write-Output "Disabling Windows Update P2P optimization..."
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
	} Else {
		# Method used since 1511
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 100
	}
}

# Restrict Windows Update P2P delivery optimization to computers in local network - Default since 1703
Function SetP2PUpdateLocal {
	Write-Output "Restricting Windows Update P2P optimization to local network..."
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
	} ElseIf ([System.Environment]::OSVersion.Version.Build -le 14393) {
		# Method used in 1511 and 1607
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 1
	} Else {
		# Method used since 1703
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
	}
}

# Unrestrict Windows Update P2P delivery optimization to both local networks and internet - Default in 1507 - 1607
Function SetP2PUpdateInternet {
	Write-Output "Unrestricting Windows Update P2P optimization to internet..."
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 3
	} ElseIf ([System.Environment]::OSVersion.Version.Build -le 14393) {
		# Method used in 1511 and 1607
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
	} Else {
		# Method used since 1703
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 3
	}
}

# Disable Background application access - ie. if apps can download or update when they aren't used - Cortana is excluded as its inclusion breaks start menu search
Function DisableBackgroundApps {
	Write-Output "Disabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
	}
}

# Enable Background application access
Function EnableBackgroundApps {
	Write-Output "Enabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach {
		Remove-ItemProperty -Path $_.PsPath -Name "Disabled" -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -ErrorAction SilentlyContinue
	}
}

# Disable SmartScreen Filter
Function DisableSmartScreen {
	Write-Output "Disabling SmartScreen Filter..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
}

# Enable SmartScreen Filter
Function EnableSmartScreen {
	Write-Output "Enabling SmartScreen Filter..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue
}

# Disable Web Search in Start Menu
Function DisableWebSearch {
	Write-Output "Disabling Bing Search in Start Menu..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

# Enable Web Search in Start Menu
Function EnableWebSearch {
	Write-Output "Enabling Bing Search in Start Menu..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue
}

Function DisableOfficeTelemetry {
	#Disable Office Telemetry
	Write-Host "Disabling Office Telemetry..."
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "VerboseLogging" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "VerboseLogging" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableLogging" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
}

Function EnableOfficeTelemetry {
	#Enable Office Telemetry
	Write-Host "Enabling Office Telemetry..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "DisableTelemetry" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "VerboseLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "VerboseLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" -Name "EnableLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" -Name "EnableLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" -Name "EnableLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Name "EnableLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableUpload" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableLogging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableUpload" -Force -ErrorAction SilentlyContinue
}

Function DisableOfficeTelemetryAgent {
	#Disable Office Telemetry Agent
	Write-Host "Disabling Office Telemetry Agent..."
	schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
	schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
	schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
	schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
}

Function EnableOfficeTelemetryAgent {
	#Enable Office Telemetry Agent
	Write-Host "Enabling Office Telemetry Agent..."
	schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /ENABLE
	schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /ENABLE
	schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /ENABLE
	schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /ENABLE
}

Function DisableOfficeSubscriptionHeartbeat {
	#Disable Office Subscription Heartbeat
	Write-Host "Disabling Office Telemetry Agent..."
	schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE
	schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE
}

Function EnableOfficeSubscriptionHeartbeat {
	#Enable Office Subscription Heartbeat
	Write-Host "Enabling Office Telemetry Agent..."
	schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /ENABLE
	schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /ENABLE
}

Function DisableOfficeFeedback {
	#Disable Office feedback
	Write-Host "Disabling Office feedback..."
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Name "Enabled" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Name "Enabled" -Type "DWORD" -Value 0 -Force
}

Function EnableOfficeFeedback {
	#Enable Office feedback
	Write-Host "Enabling Office feedback..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Name "Enabled" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Name "Enabled" -Force -ErrorAction SilentlyContinue
}

Function DisableOfficeCEIP {
	#Disable Office Customer Experience Improvement Program
	Write-Host "Disabling Office Customer Experience Improvement Program..."
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Force
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Name "QMEnable" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Name "QMEnable" -Type "DWORD" -Value 0 -Force
}

Function EnableOfficeCEIP {
	#Enable Office Customer Experience Improvement Program
	Write-Host "Enabling Office Customer Experience Improvement Program..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Name "QMEnable" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Name "QMEnable" -Force -ErrorAction SilentlyContinue
}

Function DisableVSCTelemetry {
	#Disable Visual Studio Code Telemetry
	Write-Host "Disabling Office Customer Experience Improvement Program..."
	New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Force
	New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Force
	New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Force
	Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Force
	New-Item -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Force
	New-Item -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
	New-Item -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Force
	New-Item -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name "TurnOffSwitch" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableFeedbackDialog" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableEmailInput" -Type "DWORD" -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableScreenshotCapture" -Type "DWORD" -Value 1 -Force
	Stop-Service "VSStandardCollectorService150"
	Set-Service  "VSStandardCollectorService150" -StartupType Disabled
}

Function EnableVSCTelemetry {
	#Enable Visual Studio Code Telemetry
	Write-Host "Enabling Visual Studio Code Telemetry..."
	Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name "OptIn" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name "OptIn" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Name "OptIn" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Name "OptIn" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name "TurnOffSwitch" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableFeedbackDialog" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableEmailInput" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableScreenshotCapture" -Force -ErrorAction SilentlyContinue
	Set-Service  "VSStandardCollectorService150" -StartupType Manual
	Start-Service "VSStandardCollectorService150"
}

Function DisableNVIDIATelemetry {
    #Opt-out nVidia Telemetry
    If (!(Test-Path "HKLM:\Software\NVIDIA Corporation\Global\FTS")) {
        New-Item -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID44231 -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID64640 -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID66610 -Type "DWORD" -Value 0 -Force
    If (!(Test-Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client")) {
        New-Item -Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Name OptInOrOutPreference -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name Start -Type "DWORD" -Value 4 -Force
    If (!(Test-Path "HKLM:\Software\NVIDIA Corporation\Global\Startup\SendTelemetryData")) {
        New-Item -Path "HKLM:\Software\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Name "(Default)" -Type "DWORD" -Value 0 -Force
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Name "SendTelemetryData" -Type "DWORD" -Value 0 -Force
    Stop-Service NvTelemetryContainer
    Set-Service NvTelemetryContainer -StartupType Disabled
    #Delete NVIDIA residual telemetry files
    Remove-Item -Recurse $env:systemdrive\System32\DriverStore\FileRepository\NvTelemetry*.dll
    Remove-Item -Recurse "$env:ProgramFiles\NVIDIA Corporation\NvTelemetry" | Out-Null
}

Function EnableNVIDIATelemetry {
    #Opt-in nVidia Telemetry
    Remove-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name "EnableRID44231" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name "EnableRID64640" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name "EnableRID66610" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Name "OptInOrOutPreference" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name "Start" -Type "DWORD" -Value 3 -Force
    Remove-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Name "(Default)" -Type "DWORD" -Value 1 -Force
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Name "SendTelemetryData" -Force -ErrorAction SilentlyContinue
    Stop-Service NvTelemetryContainer
    Set-Service NvTelemetryContainer -StartupType Manual
}

# Stop and disable Diagnostics Tracking Service
Function DisableDiagTrack {
	Write-Output "Stopping and disabling Diagnostics Tracking Service..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
}

# Enable and start Diagnostics Tracking Service
Function EnableDiagTrack {
	Write-Output "Enabling and starting Diagnostics Tracking Service..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 2 -Force
	Set-Service "DiagTrack" -StartupType Automatic
	Start-Service "DiagTrack" -WarningAction SilentlyContinue
}

# Stop and disable WAP Push Service
Function DisableWAPPush {
	Write-Output "Stopping and disabling WAP Push Service..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
}

# Enable and start WAP Push Service
Function EnableWAPPush {
	Write-Output "Enabling and starting WAP Push Service..."
	Set-Service "dmwappushservice" -StartupType Automatic
	Start-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 2 -Force 
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 2 -Force
}

# Stop and disable Diagnostic Execution Service
Function DisableDiagSvc {
	Write-Output "Stopping and disabling Diagnostic Execution Service..."
	Stop-Service "diagsvc" -WarningAction SilentlyContinue
	Set-Service "diagsvc" -StartupType Disabled
	Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\diagsvc" -Name "Start" -Type "DWORD" -Value 4 -Force
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagsvc" -Name "Start" -Type "DWORD" -Value 4 -Force
}

# Enable and start Diagnostic Execution Service
Function EnableDiagSvc {
	Write-Output "Enabling and starting Diagnostic Execution Service..."
	Set-Service "diagsvc" -StartupType Manual
	Start-Service "diagsvc" -WarningAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 3 -Force 
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 3 -Force
}

# Stop and disable Microsoft (R) Diagnostics Hub Standard Collector Service
Function DisableDiagHub {
	Write-Output "Stopping and disabling Microsoft (R) Diagnostics Hub Standard Collector Service..."
	Stop-Service "diagnosticshub.standardcollector.service" -WarningAction SilentlyContinue
	Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled
	Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
}

# Enable and start Microsoft (R) Diagnostics Hub Standard Collector Service
Function EnableDiagHub {
	Write-Output "Enabling and starting Microsoft (R) Diagnostics Hub Standard Collector Service..."
	Set-Service "diagnosticshub.standardcollector.service" -StartupType Manual
	Start-Service "diagnosticshub.standardcollector.service" -WarningAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 3 -Force 
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 3 -Force
}

Function DenyAppAccessToLocation {
	Write-Host " "
	$question = 'Do you want to deny app access to location?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 0)
	if ($decision -eq 0) {
		Write-Host "Denying app access to location..."
		#Turn off Windows Location Provider
		Write-Host "Disabling Windows Location Provider..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type "DWORD" -Value "1" -Force
		#Turn off location scripting
		Write-Host "Disabling location scripting..."
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type "DWORD" -Value "1" -Force
		#Turn off location
		Write-Host "Disabling location..."
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type "DWORD" -Value "1" -Force
		#Disable app access to device location for current user
		Write-Host "Disabling app access to device location for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny" -Force
		#Disable app access to device location on this device
		Write-Host "Disabling app access to device location on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny" -Force
		#Deny app access to location for older Windows (before 1903)
		Write-Host "Denying app access to location for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0 -Force
		if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"))
		{
		        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0 -Force
		#Using GPO to deny app access to location (re-activation through GUI is not possible)
        Write-Host "Denying app access to location using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToLocation {
	Write-Host "Allowing app access to location..."
	#Turn on Windows Location Provider
	Write-Host "Enabling Windows Location Provider..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Force -ErrorAction SilentlyContinue
	#Turn on location scripting
	Write-Host "Enabling location scripting..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Force -ErrorAction SilentlyContinue
	#Turn on location
	Write-Host "Enabling location..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Force -ErrorAction SilentlyContinue
	#Enable app access to device location for current user
	Write-Host "Enabling app access to device location for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow" -Force
	#Enable app access to device location on this device
	Write-Host "Enabling app access to device location on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow" -Force
	#Allow app access to location for older Windows (before 1903)
	Write-Host "Allowing app access to location for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1 -Force
	#Using GPO to allow app access to location (re-activation through GUI is possible)
	Write-Host "Allowing app access to location using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToMotionData {
	Write-Host " "
	$question = 'Do you want to deny app access to motion data?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 0)
	if ($decision -eq 0) {
		Write-Host "Denying app access to motion data for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Denying app access to motion data on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Type String -Value "Deny" -Force
		#Using GPO to deny app access to motion data (re-activation through GUI is not possible)
        Write-Host "Denying app access to motion data using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToMotionData {
	Write-Host "Allowing app access to motion data for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Allowing app access to motion data on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Type String -Value "Allow" -Force
	#Using GPO to allow app access to motion data (re-activation through GUI is possible)
	Write-Host "Allowing app access to motion data using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToPhone {
	Write-Host " "
	$question = 'Do you want to deny app access to phone?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		Write-Host "Denying app access to phone..."
		#Using GPO to deny app access to phone (re-activation through GUI is not possible)
        Write-Host "Denying app access to phone data using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToPhone {
	Write-Host "Allowing app access to phone..."
	#Using GPO to allow app access to phone (re-activation through GUI is possible)
	Write-Host "Allowing app access to phone data using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToTrustedDevices {
	Write-Host " "
	$question = 'Do you want to deny app access to trusted devices?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		Write-Host "Denying app access to trusted devices..."
		#Deny app access to trusted devices
		#For older Windows (before 1903)
		Write-Host "Denying app access for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Name "Value" -Type String -Value "Deny" -Force
		#Using GPO to deny app access to trusted devices (re-activation through GUI is not possible)
        Write-Host "Denying app access to trusted devices using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToTrustedDevices {
	Write-Host "Allowing app access to trusted devices..."
	#Allow app access to trusted devices
	#For older Windows (before 1903)
	Write-Host "Allowing app access to trusted devices for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Name "Value" -Type String -Value "Allow" -Force
	#Using GPO to allow app access to trusted devices (re-activation through GUI is possible)
	Write-Host "Allowing app access to trusted devices using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToSyncWithDevices {
	Write-Host " "
	$question = 'Do you want to deny app access to sync with devices?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		Write-Host "Denying app access to sync with devices..."
		#Deny app sync with devices (unpaired, beacons, TVs, etc.)
		#Using GPO to deny app access to sync with devices (re-activation through GUI is not possible)
        Write-Host "Denying app access to sync with devices using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToSyncWithDevices {
	Write-Host "Allowing app access to sync with devices..."
	#Allow app sync with devices (unpaired, beacons, TVs, etc.)
	#Using GPO to allow app access to sync with devices (re-activation through GUI is possible)
	Write-Host "Allowing app access to sync with devices using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToDiagnosticInfo {
	Write-Host " "
	$question = 'Do you want to deny app access to diagnostics info about your other apps?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 0)
	if ($decision -eq 0) {
		Write-Host "Denying app access to diagnostics info about your other apps..."
		#Disable app access to diagnostics information for current user 
		Write-Host "Disabling app access to diagnostics information for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Type String -Value "Deny" -Force
		#Disable app access to diagnostics information on this device 
		Write-Host "Disabling app access to diagnostics information on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Type String -Value "Deny" -Force
		#Using GPO to deny app access to diagnostics info about your other apps (re-activation through GUI is not possible)
        Write-Host "Denying app access to diagnostics info about your other apps using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToDiagnosticInfo {
	Write-Host "Allowing app access to diagnostics info about your other apps..."
	#Enable app access to diagnostics information for current user 
	Write-Host "Enabling app access to diagnostics information for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Type String -Value "Allow" -Force
	#Enable app access to diagnostics information on this device 
	Write-Host "Enabling app access to diagnostics information on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Type String -Value "Allow" -Force
	#Using GPO to allow app access to diagnostics info about your other apps (re-activation through GUI is possible)
	Write-Host "Allowing app access to diagnostics info about your other apps using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToContacts {
	Write-Host " "
	$question = 'Do you want to deny app access to your contacts?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to contacts for current user
		Write-Host "Disabling app access to contacts for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to contacts on this device
		Write-Host "Disabling app access to contacts on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Type String -Value "Deny" -Force

		#Block apps to access your contacts
		Write-Host "Blocking apps to access your contacts for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to your contacts (re-activation through GUI is not possible)
        Write-Host "Denying app access to your contacts using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToContacts {
	#Enable app access to contacts for current user
	Write-Host "Enabling app access to contacts for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to contacts on this device
	Write-Host "Enabling app access to contacts on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Type String -Value "Allow" -Force

	#Allow apps to access your contacts for folder Windows (before 1903)
	Write-Host "Allowing apps to access your contacts for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to your contacts (re-activation through GUI is possible)
	Write-Host "Allowing app access to your contacts using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToNotifications {
	Write-Host " "
	$question = 'Do you want to deny app access to notifications?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 0)
	if ($decision -eq 0) {
		#Disable app access to Notifications for current user
		Write-Host "Disabling app access to Notifications for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to Notifications on this device
		Write-Host "Disabling app access to Notifications on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Type String -Value "Deny" -Force

		#Deny app access to Notifications for older Windows (before 1903)
		Write-Host "Denying app access to Notifications for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to Notifications (re-activation through GUI is not possible)
        Write-Host "Denying app access to Notifications using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToNotifications {
	#Enable app access to Notifications for current user
	Write-Host "Enabling app access to Notifications for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to Notifications on this device
	Write-Host "Enabling app access to Notifications on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Type String -Value "Allow" -Force

	#Allow app access to Notifications for older Windows (before 1903)
	Write-Host "Allowing app access to Notifications for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to Notifications (re-activation through GUI is possible)
	Write-Host "Allowing app access to Notifications using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToCalendar {
	Write-Host " "
	$question = 'Do you want to deny app access to calendar?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		Write-Host "Denying app access to calendar..."
		#Disable app access to calendar for current user
		Write-Host "Disabling app access to calendar for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to calendar on this device
		Write-Host "Disabling app access to calendar on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Type String -Value "Deny" -Force

		#Deny app access to calendar for older Windows (before 1903)
		Write-Host "Denying app access to calendar for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to Notifications (re-activation through GUI is not possible)
        Write-Host "Denying app access to Notifications using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToCalendar {
	Write-Host "Allowing app access to calendar..."
	#Enable app access to calendar for current user
	Write-Host "Enabling app access to calendar for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to calendar on this device
	Write-Host "Enabling app access to calendar on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Type String -Value "Allow" -Force

	#Allow app access to calendar for older Windows (before 1903)
	Write-Host "Allowing app access to calendar for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to Notifications (re-activation through GUI is possible)
	Write-Host "Allowing app access to Notifications using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToCallHistory {
	Write-Host " "
	$question = 'Do you want to deny app access to call history?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		Write-Host "Denying app access to call history..."
		#Disable app access to call history for current user
		Write-Host "Disabling app access to call history for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to call history on this device
		Write-Host "Disabling app access to call history on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Type String -Value "Deny" -Force

		#Deny app access to call history for older Windows (before 1903)
		Write-Host "Denying app access to call history for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to call history (re-activation through GUI is not possible)
        Write-Host "Denying app access to call history using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToCallHistory {
	Write-Host "Allowing app access to call history..."
	#Enable app access to call history for current user
	Write-Host "Enabling app access to call history for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to call history on this device
	Write-Host "Enabling app access to call history on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Type String -Value "Allow" -Force

	#Allow app access to call history for older Windows (before 1903)
	Write-Host "Allowing app access to call history for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to call history (re-activation through GUI is possible)
    Write-Host "Allowing app access to call history using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToEmail {
	Write-Host " "
	$question = 'Do you want to deny app access to email?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		Write-Host "Denying app access to email..."
		#Disable app access to email for current user
		Write-Host "Disabling app access to email for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to email on this device
		Write-Host "Disabling app access to email on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Type String -Value "Deny" -Force

		#Deny app access to email for older Windows (before 1903)
		Write-Host "Denying app access to email for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to email (re-activation through GUI is not possible)
        Write-Host "Denying app access to email using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToEmail {
	Write-Host "Allowing app access to email..."
	#Enable app access to email for current user
	Write-Host "Enabling app access to email for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to email on this device
	Write-Host "Enabling app access to email on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Type String -Value "Allow" -Force

	#Allow app access to email for older Windows (before 1903)
	Write-Host "Allowing app access to email for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to email (re-activation through GUI is possible)
    Write-Host "Allowing app access to email using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToTasks {
	Write-Host " "
	$question = 'Do you want to deny app access to tasks?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		Write-Host "Denying app access to tasks..."
		#Disable app access to tasks for current user
		Write-Host "Disabling app access to tasks for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to tasks on this device
		Write-Host "Disabling app access to tasks on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to tasks (re-activation through GUI is not possible)
		Write-Host "Denying app access to tasks using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToTasks {
	Write-Host "Allowing app access to tasks..."
	#Enable app access to tasks for current user
	Write-Host "Enabling app access to tasks for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to tasks on this device
	Write-Host "Enabling app access to tasks on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to tasks (re-activation through GUI is possible)
	Write-Host "Allowing app access to tasks using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToMessaging {
	Write-Host " "
	$question = 'Do you want to deny app access to messaging (SMS / MMS)?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		Write-Host "Denying app access to messaging (SMS / MMS)..."
		#Disable app access to messaging (SMS / MMS) for current user
		Write-Host "Disabling app access to messaging (SMS / MMS) for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to messaging (SMS / MMS) on this device
		Write-Host "Disabling app access to messaging (SMS / MMS) on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Type String -Value "Deny" -Force

		#Deny app access to messaging (SMS / MMS) for older Windows (before 1903)
		Write-Host "Denying app access to messaging (SMS / MMS) for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Name "Value" -Type String -Value "Deny" -Force
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to messaging (SMS / MMS) (re-activation through GUI is not possible)
		Write-Host "Denying app access to messaging (SMS / MMS) using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToMessaging {
	Write-Host "Allowing app access to messaging (SMS / MMS)..."
	#Enable app access to messaging (SMS / MMS) for current user
	Write-Host "Enabling app access to messaging (SMS / MMS) for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to messaging (SMS / MMS) on this device
	Write-Host "Enabling app access to messaging (SMS / MMS) on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Type String -Value "Allow" -Force

	#Allow app access to messaging (SMS / MMS) for older Windows (before 1903)
	Write-Host "Allowing app access to messaging (SMS / MMS) for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Name "Value" -Type String -Value "Allow" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to messaging (SMS / MMS) (re-activation through GUI is possible)
	Write-Host "Allowing app access to messaging (SMS / MMS) using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToRadios {
	Write-Host " "
	$question = 'Do you want to deny app access to radios?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 0)
	if ($decision -eq 0) {
		#Disable app access to radios for current user
		Write-Host "Disabling app access to radios for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to radios on this device
		Write-Host "Disabling app access to radios on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Type String -Value "Deny" -Force

		#Deny app access to radios for older Windows (before 1903)
		Write-Host "Denying app access to radios for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to radios (re-activation through GUI is not possible)
		Write-Host "Denying app access to radios using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToRadios {
	#Enable app access to radios for current user
	Write-Host "Enabling app access to radios for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to radios on this device
	Write-Host "Enabling app access to radios on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Type String -Value "Allow" -Force

    #Allow app access to radios for older Windows (before 1903)
	Write-Host "Allowing app access to radios for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to radios (re-activation through GUI is possible)
    Write-Host "Allowing app access to radios using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToBluetooth {
	Write-Host " "
	$question = 'Do you want to deny app access to bluetooth devices?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 0)
	if ($decision -eq 0) {
		#Disable app access to bluetooth devices for current user
		Write-Host "Disabling app access to bluetooth devices for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name "Value" -Type String -Value "Deny" -Force

		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to bluetooth devices on this device
		Write-Host "Disabling app access to bluetooth devices on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name "Value" -Type String -Value "Deny" -Force

		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToBluetooth {
	#Enable app access to bluetooth devices for current user
	Write-Host "Enabling app access to bluetooth devices for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name "Value" -Type String -Value "Allow" -Force
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to bluetooth devices on this device
	Write-Host "Enabling app access to bluetooth devices on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name "Value" -Type String -Value "Allow" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToAccountInfo {
	Write-Host " "
	$question = 'Do you want to deny app access to account info, name and picture?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to account info, name and picture for current user
		Write-Host "Disabling app access to info, name and picture for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to account info, name and picture on this device
		Write-Host "Disabling app access to account info, name and picture on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type String -Value "Deny" -Force

		#Deny app access to account info, name and picture for older Windows (before 1903)
		Write-Host "Denying app access to account info, name and picture for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to info, name and picture (re-activation through GUI is not possible)
		Write-Host "Denying app access to info, name and picture using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToAccountInfo {
	#Enable app access to account info, name and picture for current user
	Write-Host "Enabling app access to info, name and picture for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to account info, name and picture on this device
	Write-Host "Enabling app access to account info, name and picture on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type String -Value "Allow" -Force

	#Allow app access to account info, name and picture for older Windows (before 1903)
	Write-Host "Allowing app access to account info, name and picture for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to info, name and picture (re-activation through GUI is possible)
	Write-Host "Allowing app access to info, name and picture using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToCamera {
	Write-Host " "
	$question = 'Do you want to deny app access to camera?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to camera for current user
		Write-Host "Disabling app access to camera for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to camera on this device
		Write-Host "Disabling app access to camera on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Deny" -Force

		#Deny app access to camera for older Windows (before 1903)
		Write-Host "Denying app access to camera for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to camera (re-activation through GUI is not possible)
		Write-Host "Denying app access to camera using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToCamera {
	#Enable app access to camera for current user
	Write-Host "Enabling app access to camera for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to camera on this device
	Write-Host "Enabling app access to camera on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Allow" -Force

	#Allow app access to camera for older Windows (before 1903)
	Write-Host "Allowing app access to camera for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to camera (re-activation through GUI is possible)
	Write-Host "Allowing app access to camera using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToMicrophone {
	Write-Host " "
	$question = 'Do you want to deny app access to microphone?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to microphone for current user
		Write-Host "Disabling app access to microphone for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to microphone on this device
		Write-Host "Disabling app access to microphone on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Deny" -Force

		#Deny app access to microphone for older Windows (before 1903)
		Write-Host "Denying app access to microphone for older Windows (before 1903)..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to microphone (re-activation through GUI is not possible)
		Write-Host "Denying app access to microphone using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToMicrophone {
	#Enable app access to microphone for current user
	Write-Host "Enabling app access to microphone for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to microphone on this device
	Write-Host "Enabling app access to microphone on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Allow" -Force

	#Allow app access to microphone for older Windows (before 1903)
	Write-Host "Allowing app access to microphone for older Windows (before 1903)..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to microphone (re-activation through GUI is possible)
	Write-Host "Allowing app access to microphone using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToAppShareAndSync {
	Write-Host " "
	$question = 'Do you want to deny app access to apps share and sync non-explicitly paired wireless devices over uPnP?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable apps share and sync non-explicitly paired wireless devices over uPnP for current user
		Write-Host "Disable apps share and sync non-explicitly paired wireless devices over uPnP for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToAppShareAndSync {
	#Enable apps share and sync non-explicitly paired wireless devices over uPnP for current user
	Write-Host "Enable apps share and sync non-explicitly paired wireless devices over uPnP for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToDocuments {
	Write-Host " "
	$question = 'Do you want to deny app access to documents?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to documents folder for current user
		Write-Host "Disabling app access to documents folder for current user..."
		if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary"))
		{
		        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to documents folder on this device
		Write-Host "Disabling app access to documents folder on this device..."
		if (-not (Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary"))
		{
		        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToDocuments {
	#Enable app access to documents folder for current user
	Write-Host "Enabling app access to documents folder for current user..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to documents folder on this device
	Write-Host "Enabling app access to documents folder on this device..."
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToPictures {
	Write-Host " "
	$question = 'Do you want to deny app access to pictures folder?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to pictures folder for current user
		Write-Host "Disabling app access to pictures folder for current user..."
		if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary"))
		{
		        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to pictures folder on this device
		Write-Host "Disabling app access to pictures folder on this device..."
		if (-not (Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary"))
		{
		        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToPictures {
	#Enable app access to pictures folder for current user
	Write-Host "Enabling app access to pictures folder for current user..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to pictures folder on this device
	Write-Host "Enabling app access to pictures folder on this device..."
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToVideos {
	Write-Host " "
	$question = 'Do you want to deny app access to videos folder?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to videos folder for current user
		Write-Host "Disabling app access to videos folder for current user..."
		if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary"))
		{
		        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to videos folder on this device
		Write-Host "Disabling app access to videos folder on this device..."
		if (-not (Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary"))
		{
		        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToVideos {
	#Enable app access to videos folder for current user
	Write-Host "Enabling app access to videos folder for current user..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to videos folder on this device
	Write-Host "Enabling app access to videos folder on this device..."
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToFileSystem {
	Write-Host " "
	$question = 'Do you want to deny app access to other filesystem?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to other filesystem for current user
		Write-Host "Disabling app access to other filesystem for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to other filesystem on this device
		Write-Host "Disabling app access to other filesystem on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToFileSystem {
	#Enable app access to other filesystem for current user
	Write-Host "Enabling app access to other filesystem for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to other filesystem on this device
	Write-Host "Enabling app access to other filesystem on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToCellularData {
	Write-Host " "
	$question = 'Do you want to deny app access to cellular data?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to cellular data for current user
		Write-Host "Disabling app access to cellular data for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to cellular data on this device
		Write-Host "Disabling app access to cellular data on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToCellularData {
	#Enable app access to cellular data for current user
	Write-Host "Enabling app access to cellular data for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to cellular data on this device
	Write-Host "Enabling app access to cellular data on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToWiFiData {
	Write-Host " "
	$question = 'Do you want to deny app access to WiFi Data?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to WiFi Data for current user
		Write-Host "Disabling app access to WiFi Data for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to WiFi Data on this device
		Write-Host "Disabling app access to WiFi Data on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToWiFiData {
	#Enable app access to WiFi Data for current user
	Write-Host "Enabling app access to WiFi Data for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to WiFi Data on this device
	Write-Host "Enabling app access to WiFi Data on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToWiFiDirect {
	Write-Host " "
	$question = 'Do you want to deny app access to WiFi Direct?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to WiFi Direct for current user
		Write-Host "Disabling app access to WiFi Direct for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to WiFi Direct on this device
		Write-Host "Disabling app access to WiFi Direct on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToWiFiDirect {
	#Enable app access to WiFi Direct for current user
	Write-Host "Enabling app access to WiFi Direct for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to WiFi Direct on this device
	Write-Host "Enabling app access to WiFi Direct on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToDownloads {
	Write-Host " "
	$question = 'Do you want to deny app access to downloads folder?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to Downloads folder for current user
		Write-Host "Disabling app access to Downloads folder for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to Downloads folder on this device
		Write-Host "Disabling app access to Downloads folder on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" -Name "Value" -Type String -Value "Deny" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToDownloads {
	#Enable app access to Downloads folder for current user
	Write-Host "Enabling app access to Downloads folder for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to Downloads folder on this device
	Write-Host "Enabling app access to Downloads folder on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" -Name "Value" -Type String -Value "Allow" -Force
	Write-Host "Done."
}

Function DenyAppAccessToEyeTracker {
	Write-Host " "
	$question = 'Do you want to deny app access to eye tracker device?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 0)
	if ($decision -eq 0) {
		#Disable app access to eye tracker device for current user
		Write-Host "Disabling app access to eye tracker device for current user..."
		if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput"))
		{
		        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" -Name "Value" -Type String -Value "Deny" -Force

		#Disable app access to eye tracker device on this device
		Write-Host "Disabling app access to eye tracker device on this device..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" -Name "Value" -Type String -Value "Deny" -Force

		#Using GPO to deny app access to eye tracker device (re-activation through GUI is not possible)
		Write-Host "Denying app access to eye tracker device using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessGazeInput" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessGazeInput_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessGazeInput_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessGazeInput_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToEyeTracker {
	#Enable app access to eye tracker device for current user
	Write-Host "Enabling app access to eye tracker device for current user..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" -Name "Value" -Type String -Value "Allow" -Force

	#Enable app access to eye tracker device on this device
	Write-Host "Enabling app access to eye tracker device on this device..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" -Name "Value" -Type String -Value "Allow" -Force

	#Using GPO to allow app access to eye tracker device (re-activation through GUI is possible)
	Write-Host "Allowing app access to eye tracker device using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessGazeInput" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessGazeInput_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessGazeInput_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessGazeInput_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToVoice {
	Write-Host " "
	$question = 'Do you want to deny app access to use voice activation?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		#Disable app access to voice activation using GPO (re-activation through GUI is not possible)
		Write-Host "Disabling app access to voice activation using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToVoice {
	#Enable app access to voice activation using GPO (re-activation through GUI is possible)
	Write-Host "Enabling app access to voice activation using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

Function DenyAppAccessToVoiceLocked {
	Write-Host " "
	$question = 'Do you want to deny app access to use voice activation when device is locked?'
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 0)
	if ($decision -eq 0) {
		#Disable app access to voice activation when device is locked using GPO (re-activation through GUI is not possible)
		Write-Host "Disabling app access to voice activation when device is locked using GPO (re-activation through GUI is not possible)..."
		if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"))
		{
		        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Type DWord -Value 2 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock_UserInControlOfTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock_ForceAllowTheseApps" -Value "" -Type "MultiString" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock_ForceDenyTheseApps" -Value "" -Type "MultiString" -Force
		Write-Host "Done."
	}
}

Function AllowAppAccessToVoiceLocked {
	#Enable app access to voice activation when device is locked using GPO (re-activation through GUI is possible)
	Write-Host "Enabling app access to voice activation when device is locked using GPO (re-activation through GUI is possible)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock_UserInControlOfTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock_ForceAllowTheseApps" -Force -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock_ForceDenyTheseApps" -Force -ErrorAction SilentlyContinue
	Write-Host "Done."
}

##########
#endregion Privacy Tweaks
##########



##########
#region Security Tweaks
##########

# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
	Write-Output "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

# Raise UAC level
Function SetUACHigh {
	Write-Output "Raising UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}

# Default UAC level
Function SetUACDefault {
	Write-Output "Restoring UAC level to default setting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1 -Force
}

# Enable sharing mapped drives between users
Function EnableSharingMappedDrives {
	Write-Output "Enabling sharing mapped drives between users..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
}

# Disable sharing mapped drives between users
Function DisableSharingMappedDrives {
	Write-Output "Disabling sharing mapped drives between users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}

# Disable implicit administrative shares
Function DisableAdminShares {
	Write-Output "Disabling implicit administrative shares..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}

# Enable implicit administrative shares
Function EnableAdminShares {
	Write-Output "Enabling implicit administrative shares..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue
}

# Disable Firewall
Function DisableFirewall {
	Write-Output "Disabling Firewall..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
}

# Enable Firewall
Function EnableFirewall {
	Write-Output "Enabling Firewall..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
}

# Hide Windows Defender SysTray icon
Function HideDefenderTrayIcon {
	Write-Output "Hiding Windows Defender SysTray icon..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	}
}

# Show Windows Defender SysTray icon
Function ShowDefenderTrayIcon {
	Write-Output "Showing Windows Defender SysTray icon..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -ErrorAction SilentlyContinue
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 17134) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%ProgramFiles%\Windows Defender\MSASCuiL.exe"
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe"
	}
}

# Disable Windows Defender
Function DisableDefender {
	Write-Output "Disabling Windows Defender..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	}
}

# Enable Windows Defender
Function EnableDefender {
	Write-Output "Enabling Windows Defender..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 17134) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%ProgramFiles%\Windows Defender\MSASCuiL.exe"
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe"
	}
}

# Disable Windows Defender Cloud
Function DisableDefenderCloud {
	Write-Output "Disabling Windows Defender Cloud..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
}

# Enable Windows Defender Cloud
Function EnableDefenderCloud {
	Write-Output "Enabling Windows Defender Cloud..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
}

# Enable Controlled Folder Access (Defender Exploit Guard feature) - Applicable to 1709 or newer, requires Windows Defender to be enabled
Function EnableCtrldFolderAccess {
	Write-Output "Enabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Enabled
}

# Disable Controlled Folder Access (Defender Exploit Guard feature) - Applicable to 1709 or newer, requires Windows Defender to be enabled
Function DisableCtrldFolderAccess {
	Write-Output "Disabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Disabled
}

# Enable Core Isolation Memory Integrity - Part of Windows Defender System Guard virtualization-based security - Applicable since 1803
# Warning: This may cause old applications and drivers to crash or even cause BSOD
# Problems were confirmed with old video drivers (Intel HD Graphics for 2nd gen., Radeon HD 6850), and old antivirus software (Kaspersky Endpoint Security 10.2, 11.2)
Function EnableCIMemoryIntegrity {
	Write-Output "Enabling Core Isolation Memory Integrity..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
}

# Disable Core Isolation Memory Integrity - Applicable since 1803
Function DisableCIMemoryIntegrity {
	Write-Output "Disabling Core Isolation Memory Integrity..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
}

# Enable Windows Defender Application Guard - Applicable since 1709 Enterprise and 1803 Pro. Not applicable to Server
# Not supported on VMs and VDI environment. Check requirements on https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard
Function EnableDefenderAppGuard {
	Write-Output "Enabling Windows Defender Application Guard..."
	Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Disable Windows Defender Application Guard - Applicable since 1709 Enterprise and 1803 Pro. Not applicable to Server
Function DisableDefenderAppGuard {
	Write-Output "Disabling Windows Defender Application Guard..."
	Disable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Hide Account Protection warning in Defender about not using a Microsoft account
Function HideAccountProtectionWarn {
	Write-Output "Hiding Account Protection warning..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows Security Health\State")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Force | Out-Null
	}
	Set-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1
}

# Show Account Protection warning in Defender
Function ShowAccountProtectionWarn {
	Write-Output "Showing Account Protection warning..."
	Remove-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue
}

# Disable blocking of downloaded files (i.e. storing zone information - no need to do File\Properties\Unblock)
Function DisableDownloadBlocking {
	Write-Output "Disabling blocking of downloaded files..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1
}

# Enable blocking of downloaded files
Function EnableDownloadBlocking {
	Write-Output "Enabling blocking of downloaded files..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
}

# Disable Windows Script Host (execution of *.vbs scripts and alike)
Function DisableScriptHost {
	Write-Output "Disabling Windows Script Host..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
}

# Enable Windows Script Host
Function EnableScriptHost {
	Write-Output "Enabling Windows Script Host..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
}

# Enable strong cryptography for old versions of .NET Framework (4.6 and newer have strong crypto enabled by default)
# https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls#schusestrongcrypto
Function EnableDotNetStrongCrypto {
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name SchUseStrongCrypto -Type "DWORD" -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name SystemDefaultTlsVersions -Type "DWORD" -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Name SchUseStrongCrypto -Type "DWORD" -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Name SystemDefaultTlsVersions -Type "DWORD" -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto -Type "DWORD" -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SystemDefaultTlsVersions -Type "DWORD" -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Name SchUseStrongCrypto -Type "DWORD" -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Name SystemDefaultTlsVersions -Type "DWORD" -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Name SchUseStrongCrypto -Type "DWORD" -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Name SystemDefaultTlsVersions -Type "DWORD" -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto -Type "DWORD" -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name SystemDefaultTlsVersions -Type "DWORD" -Value 1
}

# Disable strong cryptography for old versions of .NET Framework
Function DisableDotNetStrongCrypto {
	Write-output "Disabling .NET strong cryptography..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name SystemDefaultTlsVersions -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Name SystemDefaultTlsVersions -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SystemDefaultTlsVersions -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Name SystemDefaultTlsVersions -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Name SystemDefaultTlsVersions -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name SystemDefaultTlsVersions -ErrorAction SilentlyContinue
}

# Enable Meltdown (CVE-2017-5754) compatibility flag - Required for January and February 2018 Windows updates
# This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
# Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all.
# As of March 2018, the compatibility check has been lifted for security updates.
# See https://support.microsoft.com/en-us/help/4072699/windows-security-updates-and-antivirus-software for details
Function EnableMeltdownCompatFlag {
	Write-Output "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

# Disable Meltdown (CVE-2017-5754) compatibility flag
Function DisableMeltdownCompatFlag {
	Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue
}

# Enable F8 boot menu options
Function EnableF8BootMenu {
	Write-Output "Enabling F8 boot menu options..."
	bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
}

# Disable F8 boot menu options
Function DisableF8BootMenu {
	Write-Output "Disabling F8 boot menu options..."
	bcdedit /set `{current`} bootmenupolicy Standard | Out-Null
}

# Disable automatic recovery mode during boot
# This causes boot process to always ignore startup errors and attempt to boot normally
# It is still possible to interrupt the boot and enter recovery mode manually. In order to disable even that, apply also DisableRecoveryAndReset tweak
Function DisableBootRecovery {
	Write-Output "Disabling automatic recovery mode during boot..."
	bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures | Out-Null
}

# Enable automatic entering recovery mode during boot
# This allows the boot process to automatically enter recovery mode when it detects startup errors (default behavior)
Function EnableBootRecovery {
	Write-Output "Enabling automatic recovery mode during boot..."
	bcdedit /deletevalue `{current`} BootStatusPolicy | Out-Null
}

# Disable System Recovery and Factory reset
# Warning: This tweak completely removes the option to enter the system recovery during boot and the possibility to perform a factory reset
Function DisableRecoveryAndReset {
	Write-Output "Disabling System Recovery and Factory reset..."
	reagentc /disable 2>&1 | Out-Null
}

# Enable System Recovery and Factory reset
Function EnableRecoveryAndReset {
	Write-Output "Enabling System Recovery and Factory reset..."
	reagentc /enable 2>&1 | Out-Null
}

# Set Data Execution Prevention (DEP) policy to OptOut - Turn on DEP for all 32-bit applications except manually excluded. 64-bit applications have DEP always on.
Function SetDEPOptOut {
	Write-Output "Setting Data Execution Prevention (DEP) policy to OptOut..."
	bcdedit /set `{current`} nx OptOut | Out-Null
}

# Set Data Execution Prevention (DEP) policy to OptIn - Turn on DEP only for essential 32-bit Windows executables and manually included applications. 64-bit applications have DEP always on.
Function SetDEPOptIn {
	Write-Output "Setting Data Execution Prevention (DEP) policy to OptIn..."
	bcdedit /set `{current`} nx OptIn | Out-Null
}

Function SetDEPAlwaysOn {
	Write-Output "Setting Data Execution Prevention (DEP) policy to Always On..."
	bcdedit /set `{current`} nx AlwaysOn | Out-Null
}

##########
#endregion Security Tweaks
##########



##########
#region Network Tweaks
##########

# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
	Write-Output "Setting current network profile to public..."
	Set-NetConnectionProfile -NetworkCategory Public
}

# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate {
	Write-Output "Setting current network profile to private..."
	Set-NetConnectionProfile -NetworkCategory Private
}

# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic {
	Write-Output "Setting unknown networks profile to public..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}

# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate {
	Write-Output "Setting unknown networks profile to private..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1
}

# Disable automatic installation of network devices
Function DisableNetDevicesAutoInst {
	Write-Output "Disabling automatic installation of network devices..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}

# Enable automatic installation of network devices
Function EnableNetDevicesAutoInst {
	Write-Output "Enabling automatic installation of network devices..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue
}

# Stop and disable Home Groups services - Not applicable since 1803. Not applicable to Server
Function DisableHomeGroups {
	Write-Output "Stopping and disabling Home Groups services..."
	If (Get-Service "HomeGroupListener" -ErrorAction SilentlyContinue) {
		Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
		Set-Service "HomeGroupListener" -StartupType Disabled
	}
	If (Get-Service "HomeGroupProvider" -ErrorAction SilentlyContinue) {
		Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
		Set-Service "HomeGroupProvider" -StartupType Disabled
	}
}

# Enable and start Home Groups services - Not applicable since 1803. Not applicable to Server
Function EnableHomeGroups {
	Write-Output "Starting and enabling Home Groups services..."
	Set-Service "HomeGroupListener" -StartupType Manual
	Set-Service "HomeGroupProvider" -StartupType Manual
	Start-Service "HomeGroupProvider" -WarningAction SilentlyContinue
}

# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
	Write-Output "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1 {
	Write-Output "Enabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}

# Disable SMB Server - Completely disables file and printer sharing, but leaves the system able to connect to another SMB server as a client
# Note: Do not run this if you plan to use Docker and Shared Drives (as it uses SMB internally), see https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/216
Function DisableSMBServer {
	Write-Output "Disabling SMB Server..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}

# Enable SMB Server
Function EnableSMBServer {
	Write-Output "Enabling SMB Server..."
	Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}

# Disable NetBIOS over TCP/IP on all currently installed network interfaces
Function DisableNetBIOS {
	Write-Output "Disabling NetBIOS over TCP/IP..."
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 2
}

# Enable NetBIOS over TCP/IP on all currently installed network interfaces
Function EnableNetBIOS {
	Write-Output "Enabling NetBIOS over TCP/IP..."
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 0
}

# Disable LMHOSTS lookup
Function DisableLMHOSTS {
	Write-Output "Disabling LMHOSTS lookup..."
	$nicClass = Get-WmiObject -list Win32_NetworkAdapterConfiguration
	$nicClass.enablewins($false,$false)
}

# Enable LMHOSTS lookup
Function EnableLMHOSTS {
	Write-Output "Enabling LMHOSTS lookup..."
	$nicClass = Get-WmiObject -list Win32_NetworkAdapterConfiguration
	$nicClass.enablewins($true,$true)
}

# Disable Link-Local Multicast Name Resolution (LLMNR) protocol
Function DisableLLMNR {
	Write-Output "Disabling Link-Local Multicast Name Resolution (LLMNR)..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
}

# Enable Link-Local Multicast Name Resolution (LLMNR) protocol
Function EnableLLMNR {
	Write-Output "Enabling Link-Local Multicast Name Resolution (LLMNR)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
}

# Disable smart multi-homed name resolution
Function DisableSmartNameResolution {
	Write-Output "Disabling smart multi-homed name resolution..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -Type DWord -Value 1
}

# Enable smart multi-homed name resolution
Function EnableSmartNameResolution {
	Write-Output "Enabling smart multi-homed name resolution..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -ErrorAction SilentlyContinue
}

# Disable smart protocol reordering
Function DisableProtocolReordering {
	Write-Output "Disabling smart protocol reordering..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartProtocolReordering" -Type DWord -Value 1
}

# Enable smart protocol reordering
Function EnableProtocolReordering {
	Write-Output "Enabling smart protocol reordering..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartProtocolReordering" -ErrorAction SilentlyContinue
}

# Enable update security level to Only secure
Function EnableSecureUpdateLevel {
	Write-Output "Enabling update security level to Only secure..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "UpdateSecurityLevel" -Type DWord -Value 256
}

# Disable update security level
Function DisableSecureUpdateLevel {
	Write-Output "Disabling update security level to Only secure..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "UpdateSecurityLevel" -ErrorAction SilentlyContinue
}

# Disable Local-Link Discovery Protocol (LLDP) for all installed network interfaces
Function DisableLLDP {
	Write-Output "Disabling Local-Link Discovery Protocol (LLDP)..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"
}

# Enable Local-Link Discovery Protocol (LLDP) for all installed network interfaces
Function EnableLLDP {
	Write-Output "Enabling Local-Link Discovery Protocol (LLDP)..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"
}

# Disable Local-Link Topology Discovery (LLTD) for all installed network interfaces
Function DisableLLTD {
	Write-Output "Disabling Local-Link Topology Discovery (LLTD)..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"
}

# Enable Local-Link Topology Discovery (LLTD) for all installed network interfaces
Function EnableLLTD {
	Write-Output "Enabling Local-Link Topology Discovery (LLTD)..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"
}

# Disable Client for Microsoft Networks for all installed network interfaces
Function DisableMSNetClient {
	Write-Output "Disabling Client for Microsoft Networks..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"
}

# Enable Client for Microsoft Networks for all installed network interfaces
Function EnableMSNetClient {
	Write-Output "Enabling Client for Microsoft Networks..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"
}

# Disable Quality of Service (QoS) packet scheduler for all installed network interfaces
Function DisableQoS {
	Write-Output "Disabling Quality of Service (QoS) packet scheduler..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"
}

# Enable Quality of Service (QoS) packet scheduler for all installed network interfaces
Function EnableQoS {
	Write-Output "Enabling Quality of Service (QoS) packet scheduler..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"
}

# Disable IPv4 stack for all installed network interfaces
Function DisableIPv4 {
	Write-Output "Disabling IPv4 stack..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip"
}

# Enable IPv4 stack for all installed network interfaces
Function EnableIPv4 {
	Write-Output "Enabling IPv4 stack..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip"
}

# Disable IPv6 stack for all installed network interfaces
Function DisableIPv6 {
	Write-Output "Disabling IPv6 stack..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
}

# Enable IPv6 stack for all installed network interfaces
Function EnableIPv6 {
	Write-Output "Enabling IPv6 stack..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
}

# Disable Network Connectivity Status Indicator active test
# Note: This may reduce the ability of OS and other components to determine internet access, however protects against a specific type of zero-click attack.
# See https://github.com/Disassembler0/Win10-Initial-Setup-Script/pull/111 for details
Function DisableNCSIProbe {
	Write-Output "Disabling Network Connectivity Status Indicator (NCSI) active test..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Type DWord -Value 1
}

# Enable Network Connectivity Status Indicator active test
Function EnableNCSIProbe {
	Write-Output "Enabling Network Connectivity Status Indicator (NCSI) active test..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -ErrorAction SilentlyContinue
}

# Disable Internet Connection Sharing (e.g. mobile hotspot)
Function DisableConnectionSharing {
	Write-Output "Disabling Internet Connection Sharing..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Type DWord -Value 0
}

# Enable Internet Connection Sharing (e.g. mobile hotspot)
Function EnableConnectionSharing {
	Write-Output "Enabling Internet Connection Sharing..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -ErrorAction SilentlyContinue
}

# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
	Write-Output "Disabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Remove-WindowsCapability -Online | Out-Null
}

# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
	Write-Output "Enabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Add-WindowsCapability -Online | Out-Null
}

# Enable Remote Desktop
Function EnableRemoteDesktop {
	Write-Output "Enabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Enable-NetFirewallRule -Name "RemoteDesktop*"
}

# Disable Remote Desktop
Function DisableRemoteDesktop {
	Write-Output "Disabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
	Disable-NetFirewallRule -Name "RemoteDesktop*"
}

##########
#endregion Network Tweaks
##########



##########
#region Service Tweaks
##########

# Enable offering of Malicious Software Removal Tool through Windows Update
Function EnableUpdateMSRT {
	Write-Output "Enabling Malicious Software Removal Tool offering..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}

# Disable offering of Malicious Software Removal Tool through Windows Update
Function DisableUpdateMSRT {
	Write-Output "Disabling Malicious Software Removal Tool offering..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}

# Disable offering of drivers through Windows Update
# Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
# Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
Function DisableUpdateDriver {
	Write-Output "Disabling driver offering through Windows Update..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Update")) {
		New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\" -Name "Update" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update\" -Name "ExcludeWUDriversInQualityUpdate" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" -Name Value -Type "DWORD" -Value 1 -Force
	If (!(Test-Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings")) {
		New-Item -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
}

# Enable offering of drivers through Windows Update
Function EnableUpdateDriver {
	Write-Output "Enabling driver offering through Windows Update..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" -Name Value -Type "DWORD" -Value 0 -Force
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name ExcludeWUDriversInQualityUpdate -ErrorAction SilentlyContinue
}

# Disable Windows Update automatic downloads
Function DisableUpdateAutoDownload {
	Write-Output "Disabling Windows Update automatic downloads..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
}

# Enable Windows Update automatic downloads
Function EnableUpdateAutoDownload {
	Write-Output "Enabling Windows Update automatic downloads..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
}

# Disable automatic restart after Windows Update installation
# The tweak is slightly experimental, as it registers a dummy debugger for MusNotification.exe
# which blocks the restart prompt executable from running, thus never schedulling the restart
Function DisableUpdateRestart {
	Write-Output "Disabling Windows Update automatic restart..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -Type String -Value "cmd.exe"
}

# Enable automatic restart after Windows Update installation
Function EnableUpdateRestart {
	Write-Output "Enabling Windows Update automatic restart..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -ErrorAction SilentlyContinue
}

Function DisableFeatureUpdates {
	# Configure Windows Update to only install Security Updates Windows 10 1709,1809
	If ([System.Environment]::OSVersion.Version.Build -eq 16299) {
	    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
	        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Type DWord -Value 0
	    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
	        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Type DWord -Value 0
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
	    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
	        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Type DWord -Value 0
	    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
	        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -Type String -Value 1809
	}
	# Configure Windows Update to only install Security Updates Windows 10 1903
	If ([System.Environment]::OSVersion.Version.Build -eq 18362) {
	    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
	        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Type DWord -Value 0
	    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
	        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -Type String -Value 1903
	}
	# Configure Windows Update to only install Security Updates Windows 10 1909,2004
	If ([System.Environment]::OSVersion.Version.Build -eq 18363) {
	    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
	        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Type DWord -Value 0
	    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
	        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -Type String -Value 1909
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 19041) {
	    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
	        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Type DWord -Value 0
	    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
	        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -Type String -Value 2004
	}
	# Configure Windows Update to only install Security Updates Windows 10 20H2
	If ([System.Environment]::OSVersion.Version.Build -eq 19042) {
	    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
	        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Type DWord -Value 0
	    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
	        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
	    }
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -Type DWord -Value 20
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Type DWord -Value 0
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -Type DWord -Value 1
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -Type String -Value '20H2'
	}
}

Function EnableFeatureUpdates {
	# Configure Windows Update to install Feature and Security Updates Windows 10 1709,1809
	If ([System.Environment]::OSVersion.Version.Build -eq 16299) {
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
	}
	# Configure Windows Update to install Feature and Security Updates Windows 10 1903
	If ([System.Environment]::OSVersion.Version.Build -eq 18362) {
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
	}
	# Configure Windows Update to install Feature and Security Updates Windows 10 1909,2004
	If ([System.Environment]::OSVersion.Version.Build -eq 18363) {
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 19041) {
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
	}
	# Configure Windows Update to install Feature and Security Updates Windows 10 20H2
	If ([System.Environment]::OSVersion.Version.Build -eq 19042) {
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "InsiderProgramEnabled" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
	    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
	}
}

Function DisableForcedFeatureUpdates {
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableOSUpgrade" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Name "AllowOSUpgrade" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Name "ReservationsAllowed" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SYSTEM\Setup\UpgradeNotification")) {
		New-Item -Path "HKLM:\SYSTEM\Setup\UpgradeNotification" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\Setup\UpgradeNotification" -Name "UpgradeAvailable" -Type DWord -Value 0
}

Function EnableForcedFeatureUpdates {
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableOSUpgrade" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Name "AllowOSUpgrade" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Name "ReservationsAllowed" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SYSTEM\Setup\UpgradeNotification" -Name "UpgradeAvailable" -ErrorAction SilentlyContinue
}

# Disable nightly wake-up for Automatic Maintenance and Windows Updates
Function DisableMaintenanceWakeUp {
	Write-Output "Disabling nightly wake-up for Automatic Maintenance..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -Type DWord -Value 0
}

# Enable nightly wake-up for Automatic Maintenance and Windows Updates
Function EnableMaintenanceWakeUp {
	Write-Output "Enabling nightly wake-up for Automatic Maintenance..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -ErrorAction SilentlyContinue
}

# Disable Automatic Restart Sign-on - Applicable since 1903
# See https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/winlogon-automatic-restart-sign-on--arso-
Function DisableAutoRestartSignOn {
	Write-Output "Disabling Automatic Restart Sign-on..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Type DWord -Value 1
}

# Enable Automatic Restart Sign-on - Applicable since 1903
Function EnableAutoRestartSignOn {
	Write-Output "Enabling Automatic Restart Sign-on..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -ErrorAction SilentlyContinue
}

# Disable Shared Experiences - Applicable since 1703. Not applicable to Server
# This setting can be set also via GPO, however doing so causes reset of Start Menu cache. See https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/145 for details
Function DisableSharedExperiences {
	Write-Output "Disabling Shared Experiences..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 0
}

# Enable Shared Experiences - Applicable since 1703. Not applicable to Server
Function EnableSharedExperiences {
	Write-Output "Enabling Shared Experiences..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 1
}

#Disabling Device Search History.
Function DisableSearchHistory {
	Write-Output "Disabling Search Histroy..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0
}

#Enabling Device Search History.
Function EnableSearchHistory {
	Write-Output "Disabling Search Histroy..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 1
}

# Enable Clipboard History - Applicable since 1809. Not applicable to Server
Function EnableClipboardHistory {
	Write-Output "Enabling Clipboard History..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 1
}

# Disable Clipboard History - Applicable since 1809. Not applicable to Server
Function DisableClipboardHistory {
	Write-Output "Disabling Clipboard History..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue
}

# Disable Autoplay
Function DisableAutoplay {
	Write-Output "Disabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}

# Enable Autoplay
Function EnableAutoplay {
	Write-Output "Enabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
}

# Disable Autorun for all drives
Function DisableAutorun {
	Write-Output "Disabling Autorun for all drives..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

# Enable Autorun for removable drives
Function EnableAutorun {
	Write-Output "Enabling Autorun for all drives..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
}

# Enable Storage Sense - automatic disk cleanup - Applicable since 1703
Function EnableStorageSense {
	Write-Output "Enabling Storage Sense..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1
}

# Disable Storage Sense - Applicable since 1703
Function DisableStorageSense {
	Write-Output "Disabling Storage Sense..."
	Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

# Disable scheduled defragmentation task
Function DisableDefragmentation {
	Write-Output "Disabling scheduled defragmentation..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Enable scheduled defragmentation task
Function EnableDefragmentation {
	Write-Output "Enabling scheduled defragmentation..."
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Stop and disable Superfetch service
Function DisableSuperfetch {
	Write-Output "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
}

# Start and enable Superfetch service
Function EnableSuperfetch {
	Write-Output "Starting and enabling Superfetch service..."
	Set-Service "SysMain" -StartupType Automatic
	Start-Service "SysMain" -WarningAction SilentlyContinue
}

# Stop and disable Windows Search indexing service
Function DisableIndexing {
	Write-Output "Stopping and disabling Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
}

# Start and enable Windows Search indexing service
Function EnableIndexing {
	Write-Output "Starting and enabling Windows Search indexing service..."
	Set-Service "WSearch" -StartupType Automatic
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
	Start-Service "WSearch" -WarningAction SilentlyContinue
}

# Set BIOS time to UTC
Function SetBIOSTimeUTC {
	Write-Output "Setting BIOS time to UTC..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
}

# Set BIOS time to local time
Function SetBIOSTimeLocal {
	Write-Output "Setting BIOS time to Local time..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
}

# Disable Hibernation
Function DisableHibernation {
	Write-Output "Disabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
	powercfg /HIBERNATE OFF 2>&1 | Out-Null
}

# Enable Hibernation - Do not use on Server with automatically started Hyper-V hvboot service as it may lead to BSODs (Win10 with Hyper-V is fine)
Function EnableHibernation {
	Write-Output "Enabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 1
	powercfg /HIBERNATE ON 2>&1 | Out-Null
}

# Disable Sleep start menu and keyboard button
Function DisableSleepButton {
	Write-Output "Disabling Sleep start menu and keyboard button..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
}

# Enable Sleep start menu and keyboard button
Function EnableSleepButton {
	Write-Output "Enabling Sleep start menu and keyboard button..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 1
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
}

# Disable display and sleep mode timeouts
Function DisableSleepTimeout {
	Write-Output "Disabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0
}

# Enable display and sleep mode timeouts
Function EnableSleepTimeout {
	Write-Output "Enabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 10
	powercfg /X monitor-timeout-dc 5
	powercfg /X standby-timeout-ac 30
	powercfg /X standby-timeout-dc 15
}

# Disable Fast Startup
Function DisableFastStartup {
	Write-Output "Disabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

# Enable Fast Startup
Function EnableFastStartup {
	Write-Output "Enabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
}

# Disable automatic reboot on crash (BSOD)
Function DisableAutoRebootOnCrash {
	Write-Output "Disabling automatic reboot on crash (BSOD)..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 0
}

# Enable automatic reboot on crash (BSOD)
Function EnableAutoRebootOnCrash {
	Write-Output "Enabling automatic reboot on crash (BSOD)..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 1
}

##########
#endregion Service Tweaks
##########



##########
#region UI Tweaks
##########

# Disable Action Center (Notification Center)
Function DisableActionCenter {
	Write-Output "Disabling Action Center (Notification Center)..."
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
}

# Enable Action Center (Notification Center)
Function EnableActionCenter {
	Write-Output "Enabling Action Center (Notification Center)..."
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue
}

# Disable Lock screen
Function DisableLockScreen {
	Write-Output "Disabling Lock screen..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
}

# Enable Lock screen
Function EnableLockScreen {
	Write-Output "Enabling Lock screen..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}

# Disable Lock screen - Anniversary Update workaround. The GPO used in DisableLockScreen has been broken in 1607 and fixed again in 1803
Function DisableLockScreenRS1 {
	Write-Output "Disabling Lock screen using scheduler workaround..."
	$service = New-Object -com Schedule.Service
	$service.Connect()
	$task = $service.NewTask(0)
	$task.Settings.DisallowStartIfOnBatteries = $false
	$trigger = $task.Triggers.Create(9)
	$trigger = $task.Triggers.Create(11)
	$trigger.StateChange = 8
	$action = $task.Actions.Create(0)
	$action.Path = "reg.exe"
	$action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
	$service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
}

# Enable Lock screen - Anniversary Update workaround. The GPO used in DisableLockScreen has been broken in 1607 and fixed again in 1803
Function EnableLockScreenRS1 {
	Write-Output "Enabling Lock screen (removing scheduler workaround)..."
	Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction SilentlyContinue
}

# Hide network options from Lock Screen
Function HideNetworkFromLockScreen {
	Write-Output "Hiding network options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1
}

# Show network options on lock screen
Function ShowNetworkOnLockScreen {
	Write-Output "Showing network options on Lock Screen..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
}

# Hide shutdown options from Lock Screen
Function HideShutdownFromLockScreen {
	Write-Output "Hiding shutdown options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0
}

# Show shutdown options on lock screen
Function ShowShutdownOnLockScreen {
	Write-Output "Showing shutdown options on Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1
}

# Disable Lock screen Blur - Applicable since 1903
Function DisableLockScreenBlur {
	Write-Output "Disabling Lock screen Blur..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type DWord -Value 1
}

# Enable Lock screen Blur - Applicable since 1903
Function EnableLockScreenBlur {
	Write-Output "Enabling Lock screen Blur..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -ErrorAction SilentlyContinue
}

# Disable Aero Shake (minimizing other windows when one is dragged by mouse and shaken)
Function DisableAeroShake {
	Write-Output "Disabling Aero Shake..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1
}

# Enable Aero Shake
Function EnableAeroShake {
	Write-Output "Enabling Aero Shake..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -ErrorAction SilentlyContinue
}

# Disable accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)
Function DisableAccessibilityKeys {
	Write-Output "Disabling accessibility keys prompts..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122"
}

# Enable accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)
Function EnableAccessibilityKeys {
	Write-Output "Enabling accessibility keys prompts..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "62"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "126"
}

# Show Task Manager details - Applicable since 1607
# Although this functionality exist even in earlier versions, the Task Manager's behavior is different there and is not compatible with this tweak
Function ShowTaskManagerDetails {
	Write-Output "Showing task manager details..."
	$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
	$timeout = 30000
	$sleep = 100
	Do {
		Start-Sleep -Milliseconds $sleep
		$timeout -= $sleep
		$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	} Until ($preferences -or $timeout -le 0)
	Stop-Process $taskmgr
	If ($preferences) {
		$preferences.Preferences[28] = 0
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
	}
}

# Hide Task Manager details - Applicable since 1607
Function HideTaskManagerDetails {
	Write-Output "Hiding task manager details..."
	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	If ($preferences) {
		$preferences.Preferences[28] = 1
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
	}
}

# Show file operations details
Function ShowFileOperationsDetails {
	Write-Output "Showing file operations details..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}

# Hide file operations details
Function HideFileOperationsDetails {
	Write-Output "Hiding file operations details..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -ErrorAction SilentlyContinue
}

# Enable file delete confirmation dialog
Function EnableFileDeleteConfirm {
	Write-Output "Enabling file delete confirmation dialog..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
}

# Disable file delete confirmation dialog
Function DisableFileDeleteConfirm {
	Write-Output "Disabling file delete confirmation dialog..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue
}

# Hide Taskbar Search icon / box
# This causing issue in Windows 10 2004 and 20H2, windows search goes full screen randomly.
# See: https://www.tenforums.com/general-support/167541-windows-search-taskbar-goes-full-screen-randomly.html
Function HideTaskbarSearch {
	Write-Output "Hiding Taskbar Search icon / box..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

# Show Taskbar Search icon
Function ShowTaskbarSearchIcon {
	Write-Output "Showing Taskbar Search icon..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
}

# Show Taskbar Search box
Function ShowTaskbarSearchBox {
	Write-Output "Showing Taskbar Search box..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 2
}

# Hide Task View button
Function HideTaskView {
	Write-Output "Hiding Task View button..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

# Show Task View button
Function ShowTaskView {
	Write-Output "Showing Task View button..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
}

# Show large icons in taskbar
Function ShowLargeTaskbarIcons {
	Write-Output "Showing large icons in taskbar..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -ErrorAction SilentlyContinue
}

# Show small icons in taskbar
Function ShowSmallTaskbarIcons {
	Write-Output "Showing small icons in taskbar..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
}

# Set taskbar buttons to always combine and hide labels
Function SetTaskbarCombineAlways {
	Write-Output "Setting taskbar buttons to always combine, hide labels..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -ErrorAction SilentlyContinue
}

# Set taskbar buttons to show labels and combine when taskbar is full
Function SetTaskbarCombineWhenFull {
	Write-Output "Setting taskbar buttons to combine when taskbar is full..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 1
}

# Set taskbar buttons to show labels and never combine
Function SetTaskbarCombineNever {
	Write-Output "Setting taskbar buttons to never combine..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 2
}

# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
	Write-Output "Hiding People icon..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}

# Show Taskbar People icon
Function ShowTaskbarPeopleIcon {
	Write-Output "Showing People icon..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -ErrorAction SilentlyContinue
}

# Show all tray icons
Function ShowTrayIcons {
	Write-Output "Showing all tray icons..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
}

# Hide tray icons as needed
Function HideTrayIcons {
	Write-Output "Hiding tray icons..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -ErrorAction SilentlyContinue
}

# Show seconds in taskbar
Function ShowSecondsInTaskbar {
	Write-Output "Showing seconds in taskbar..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type DWord -Value 1
}

# Hide seconds from taskbar
Function HideSecondsFromTaskbar {
	Write-Output "Hiding seconds from taskbar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -ErrorAction SilentlyContinue
}

# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore {
	Write-Output "Disabling search for app in store for unknown extensions..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

# Enable search for app in store for unknown extensions
Function EnableSearchAppInStore {
	Write-Output "Enabling search for app in store for unknown extensions..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
}

# Disable 'How do you want to open this file?' prompt
Function DisableNewAppPrompt {
	Write-Output "Disabling 'How do you want to open this file?' prompt..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
}

# Enable 'How do you want to open this file?' prompt
Function EnableNewAppPrompt {
	Write-Output "Enabling 'How do you want to open this file?' prompt..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction SilentlyContinue
}

# Hide 'Recently added' list from the Start Menu
Function HideRecentlyAddedApps {
	Write-Output "Hiding 'Recently added' list from the Start Menu..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
}

# Show 'Recently added' list in the Start Menu
Function ShowRecentlyAddedApps {
	Write-Output "Showing 'Recently added' list in the Start Menu..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -ErrorAction SilentlyContinue
}

# Hide 'Most used' apps list from the Start Menu - Applicable until 1703 (hidden by default since then)
Function HideMostUsedApps {
	Write-Output "Hiding 'Most used' apps list from the Start Menu..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Type DWord -Value 1
}

# Show 'Most used' apps list in the Start Menu - Applicable until 1703 (GPO broken since then)
Function ShowMostUsedApps {
	Write-Output "Showing 'Most used' apps list in the Start Menu..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -ErrorAction SilentlyContinue
}

# Set PowerShell instead of Command prompt in Start Button context menu (Win+X) - Default since 1703
Function SetWinXMenuPowerShell {
	Write-Output "Setting PowerShell instead of Command prompt in WinX menu..."
	If ([System.Environment]::OSVersion.Version.Build -le 14393) {
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Type DWord -Value 0
	} Else {
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -ErrorAction SilentlyContinue
	}
}

# Set Command prompt instead of PowerShell in Start Button context menu (Win+X) - Default in 1507 - 1607
Function SetWinXMenuCmd {
	Write-Output "Setting Command prompt instead of PowerShell in WinX menu..."
	If ([System.Environment]::OSVersion.Version.Build -le 14393) {
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -ErrorAction SilentlyContinue
	} Else {
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Type DWord -Value 1
	}
}

# Set Control Panel view to categories
Function SetControlPanelCategories {
	Write-Output "Setting Control Panel view to categories..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -ErrorAction SilentlyContinue
}

# Set Control Panel view to Large icons (Classic)
Function SetControlPanelLargeIcons {
	Write-Output "Setting Control Panel view to large icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0
}

# Set Control Panel view to Small icons (Classic)
Function SetControlPanelSmallIcons {
	Write-Output "Setting Control Panel view to small icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1
}

# Disable adding '- shortcut' to shortcut name
Function DisableShortcutInName {
	Write-Output "Disabling adding '- shortcut' to shortcut name..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0))
}

# Enable adding '- shortcut' to shortcut name
Function EnableShortcutInName {
	Write-Output "Enabling adding '- shortcut' to shortcut name..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -ErrorAction SilentlyContinue
}

# Hide shortcut icon arrow
Function HideShortcutArrow {
	Write-Output "Hiding shortcut icon arrow..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Type String -Value "%SystemRoot%\System32\imageres.dll,-1015"
}

# Show shortcut icon arrow
Function ShowShortcutArrow {
	Write-Output "Showing shortcut icon arrow..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -ErrorAction SilentlyContinue
}

# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
	Write-Output "Adjusting visual effects for performance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 100
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

# Adjusts visual effects for appearance
Function SetVisualFXAppearance {
	Write-Output "Adjusting visual effects for appearance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90,0x12,0x07,0x80,0x10,0x00,0x00,0x00))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

# Enable window title bar color according to prevalent background color
Function EnableTitleBarColor {
	Write-Output "Enabling window title bar color..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 1
}

# Disable window title bar color
Function DisableTitleBarColor {
	Write-Output "Disabling window title bar color..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 0
}

# Set Dark Mode for Applications
Function SetAppsDarkMode {
	Write-Output "Setting Dark Mode for Applications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
}

# Set Light Mode for Applications
Function SetAppsLightMode {
	Write-Output "Setting Light Mode for Applications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1
}

# Set Dark Mode for System - Applicable since 1903
Function SetSystemDarkMode {
	Write-Output "Setting Dark Mode for System..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
}

# Set Light Mode for System - Applicable since 1903
Function SetSystemLightMode {
	Write-Output "Setting Light Mode for System..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 1
}

# Add secondary en-US keyboard
Function AddENKeyboard {
	Write-Output "Adding secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	$langs.Add("en-US")
	Set-WinUserLanguageList $langs -Force
}

# Remove secondary en-US keyboard
Function RemoveENKeyboard {
	Write-Output "Removing secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | Where-Object {$_.LanguageTag -ne "en-US"}) -Force
}

# Enable NumLock after startup
Function EnableNumlock {
	Write-Output "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}

# Disable NumLock after startup
Function DisableNumlock {
	Write-Output "Disabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
	Add-Type -AssemblyName System.Windows.Forms
	If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}

# Disable enhanced pointer precision
Function DisableEnhPointerPrecision {
	Write-Output "Disabling enhanced pointer precision..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"
}

# Enable enhanced pointer precision
Function EnableEnhPointerPrecision {
	Write-Output "Enabling enhanced pointer precision..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "1"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "6"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "10"
}

# Set sound scheme to No Sounds
Function SetSoundSchemeNone {
	Write-Output "Setting sound scheme to No Sounds..."
	$SoundScheme = ".None"
	Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps\*\*" | ForEach-Object {
		# If scheme keys do not exist in an event, create empty ones (similar behavior to Sound control panel).
		If (!(Test-Path "$($_.PsPath)\$($SoundScheme)")) {
			New-Item -Path "$($_.PsPath)\$($SoundScheme)" | Out-Null
		}
		If (!(Test-Path "$($_.PsPath)\.Current")) {
			New-Item -Path "$($_.PsPath)\.Current" | Out-Null
		}
		# Get a regular string from any possible kind of value, i.e. resolve REG_EXPAND_SZ, copy REG_SZ or empty from non-existing.
		$Data = (Get-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
		# Replace any kind of value with a regular string (similar behavior to Sound control panel).
		Set-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -Type String -Value $Data
		# Copy data from source scheme to current.
		Set-ItemProperty -Path "$($_.PsPath)\.Current" -Name "(Default)" -Type String -Value $Data
	}
	Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Type String -Value $SoundScheme
}

# Set sound scheme to Windows Default
Function SetSoundSchemeDefault {
	Write-Output "Setting sound scheme to Windows Default..."
	$SoundScheme = ".Default"
	Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps\*\*" | ForEach-Object {
		# If scheme keys do not exist in an event, create empty ones (similar behavior to Sound control panel).
		If (!(Test-Path "$($_.PsPath)\$($SoundScheme)")) {
			New-Item -Path "$($_.PsPath)\$($SoundScheme)" | Out-Null
		}
		If (!(Test-Path "$($_.PsPath)\.Current")) {
			New-Item -Path "$($_.PsPath)\.Current" | Out-Null
		}
		# Get a regular string from any possible kind of value, i.e. resolve REG_EXPAND_SZ, copy REG_SZ or empty from non-existing.
		$Data = (Get-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
		# Replace any kind of value with a regular string (similar behavior to Sound control panel).
		Set-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -Type String -Value $Data
		# Copy data from source scheme to current.
		Set-ItemProperty -Path "$($_.PsPath)\.Current" -Name "(Default)" -Type String -Value $Data
	}
	Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Type String -Value $SoundScheme
}

# Disable playing Windows Startup sound
Function DisableStartupSound {
	Write-Output "Disabling Windows Startup sound..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 1
}

# Enable playing Windows Startup sound
Function EnableStartupSound {
	Write-Output "Enabling Windows Startup sound..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 0
}

# Disable changing sound scheme
Function DisableChangingSoundScheme {
	Write-Output "Disabling changing sound scheme..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -Type DWord -Value 1
}

# Enable changing sound scheme
Function EnableChangingSoundScheme {
	Write-Output "Enabling changing sound scheme..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -ErrorAction SilentlyContinue
}

# Enable verbose startup/shutdown status messages
Function EnableVerboseStatus {
	Write-Output "Enabling verbose startup/shutdown status messages..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 1
	} Else {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue
	}
}

# Disable verbose startup/shutdown status messages
Function DisableVerboseStatus {
	Write-Output "Disabling verbose startup/shutdown status messages..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue
	} Else {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 0
	}
}

# Disable F1 Help key in Explorer and on the Desktop
Function DisableF1HelpKey {
	Write-Output "Disabling F1 Help key..."
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32")) {
		New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -Type "String" -Value ""
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64")) {
		New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type "String" -Value ""
}

# Enable F1 Help key in Explorer and on the Desktop
Function EnableF1HelpKey {
	Write-Output "Enabling F1 Help key..."
	Remove-Item "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0" -Recurse -ErrorAction SilentlyContinue
}

##########
#endregion UI Tweaks
##########



##########
#region Explorer UI Tweaks
##########

# Show known file extensions
Function ShowKnownExtensions {
	Write-Output "Showing known file extensions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

# Hide known file extensions
Function HideKnownExtensions {
	Write-Output "Hiding known file extensions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
}

# Show hidden files
Function ShowHiddenFiles {
	Write-Output "Showing hidden files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}

# Hide hidden files
Function HideHiddenFiles {
	Write-Output "Hiding hidden files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}

# Hide sync provider notifications
Function HideSyncNotifications {
	Write-Output "Hiding sync provider notifications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

# Show sync provider notifications
Function ShowSyncNotifications {
	Write-Output "Showing sync provider notifications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 1
}

# Hide recently and frequently used item shortcuts in Explorer
# Note: This is only UI tweak to hide the shortcuts. In order to stop creating most recently used (MRU) items lists everywhere, use privacy tweak 'DisableRecentFiles' instead.
Function HideRecentShortcuts {
	Write-Output "Hiding recent shortcuts in Explorer..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}

# Show recently and frequently used item shortcuts in Explorer
Function ShowRecentShortcuts {
	Write-Output "Showing recent shortcuts in Explorer..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue
}

# Change default Explorer view to This PC
Function SetExplorerThisPC {
	Write-Output "Changing default Explorer view to This PC..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

# Change default Explorer view to Quick Access
Function SetExplorerQuickAccess {
	Write-Output "Changing default Explorer view to Quick Access..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -ErrorAction SilentlyContinue
}

# Show This PC shortcut on desktop
Function ShowThisPCOnDesktop {
	Write-Output "Showing This PC shortcut on desktop..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}

# Hide This PC shortcut from desktop
Function HideThisPCFromDesktop {
	Write-Output "Hiding This PC shortcut from desktop..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
}

# Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
Function Hide3DObjectsFromThisPC {
	Write-Output "Hiding 3D Objects icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

# Show 3D Objects icon in This PC
Function Show3DObjectsInThisPC {
	Write-Output "Showing 3D Objects icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" | Out-Null
	}
}

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function Hide3DObjectsFromExplorer {
	Write-Output "Hiding 3D Objects icon from Explorer namespace..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show 3D Objects icon in Explorer namespace
Function Show3DObjectsInExplorer {
	Write-Output "Showing 3D Objects icon in Explorer namespace..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue
}

# Hide Desktop icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideDesktopFromThisPC {
	Write-Output "Hiding Desktop icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
}

# Show Desktop icon in This PC
Function ShowDesktopInThisPC {
	Write-Output "Showing Desktop icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" | Out-Null
	}
}

# Hide Desktop icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideDesktopFromExplorer {
	Write-Output "Hiding Desktop icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Desktop icon in Explorer namespace
Function ShowDesktopInExplorer {
	Write-Output "Showing Desktop icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Documents icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideDocumentsFromThisPC {
	Write-Output "Hiding Documents icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
}

# Show Documents icon in This PC
Function ShowDocumentsInThisPC {
	Write-Output "Showing Documents icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" | Out-Null
	}
}

# Hide Documents icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideDocumentsFromExplorer {
	Write-Output "Hiding Documents icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Documents icon in Explorer namespace
Function ShowDocumentsInExplorer {
	Write-Output "Showing Documents icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Downloads icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideDownloadsFromThisPC {
	Write-Output "Hiding Downloads icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue
}

# Show Downloads icon in This PC
Function ShowDownloadsInThisPC {
	Write-Output "Showing Downloads icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" | Out-Null
	}
}

# Hide Downloads icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideDownloadsFromExplorer {
	Write-Output "Hiding Downloads icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Downloads icon in Explorer namespace
Function ShowDownloadsInExplorer {
	Write-Output "Showing Downloads icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Music icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideMusicFromThisPC {
	Write-Output "Hiding Music icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
}

# Show Music icon in This PC
Function ShowMusicInThisPC {
	Write-Output "Showing Music icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" | Out-Null
	}
}

# Hide Music icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideMusicFromExplorer {
	Write-Output "Hiding Music icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Music icon in Explorer namespace
Function ShowMusicInExplorer {
	Write-Output "Showing Music icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Pictures icon from This PC - The icon remains in personal folders and open/save dialogs
Function HidePicturesFromThisPC {
	Write-Output "Hiding Pictures icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
}

# Show Pictures icon in This PC
Function ShowPicturesInThisPC {
	Write-Output "Showing Pictures icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" | Out-Null
	}
}

# Hide Pictures icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HidePicturesFromExplorer {
	Write-Output "Hiding Pictures icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Pictures icon in Explorer namespace
Function ShowPicturesInExplorer {
	Write-Output "Showing Pictures icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Videos icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideVideosFromThisPC {
	Write-Output "Hiding Videos icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
}

# Show Videos icon in This PC
Function ShowVideosInThisPC {
	Write-Output "Showing Videos icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" | Out-Null
	}
}

# Hide Videos icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideVideosFromExplorer {
	Write-Output "Hiding Videos icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Videos icon in Explorer namespace
Function ShowVideosInExplorer {
	Write-Output "Showing Videos icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Disable thumbnails, show only file extension icons
Function DisableThumbnails {
	Write-Output "Disabling thumbnails..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1
}

# Enable thumbnails
Function EnableThumbnails {
	Write-Output "Enabling thumbnails..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
}

# Disable creation of thumbnail cache files
Function DisableThumbnailCache {
	Write-Output "Disabling creation of thumbnail cache files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
}

# Enable creation of thumbnail cache files
Function EnableThumbnailCache {
	Write-Output "Enabling creation of thumbnail cache files..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction SilentlyContinue
}

# Disable creation of Thumbs.db thumbnail cache files on network folders
Function DisableThumbsDBOnNetwork {
	Write-Output "Disabling creation of Thumbs.db on network folders..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
}

# Enable creation of Thumbs.db thumbnail cache files on network folders
Function EnableThumbsDBOnNetwork {
	Write-Output "Enabling creation of Thumbs.db on network folders..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction SilentlyContinue
}

##########
#endregion Explorer UI Tweaks
##########



##########
#region Application Tweaks
##########

# Disable OneDrive
Function DisableOneDrive {
	Write-Output "Disabling OneDrive..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
}

# Enable OneDrive
Function EnableOneDrive {
	Write-Output "Enabling OneDrive..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
}

# Uninstall OneDrive - Not applicable to Server
Function UninstallOneDrive {
	Write-Output "Uninstalling OneDrive..."
	Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
	Stop-Process -Name "Explorer" -Force -ErrorAction SilentlyContinue
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
	#check if directory is empty before removing:
	Write-Output "Checking if directory is empty before removing..."
	If ((Get-ChildItem -Path "$env:USERPROFILE\OneDrive" -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
		Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	}
	Write-Output "Disabling OneDrive via Group Policies..."
	Mkdir -Force  "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
	Set-ItemProperty "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
	Write-Output "Removing Onedrive from explorer sidebar..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Write-Output "Removing run hook for new users..."
	reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
	reg delete "HKEY_USERS\Default\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
	reg unload "hku\Default"
	Write-Output "Removing startmenu entry..."
	Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
	Write-Output "Removing scheduled task..."
	Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
	Write-Output "Restarting explorer..."
	Start-Process "explorer.exe"
	Write-Output "Waiting for explorer to complete loading..."
	Start-Sleep 10
	Write-Output "Removing additional OneDrive leftovers..."
	foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
        Takeown-Folder $item.FullName
        Remove-Item -Recurse -Force $item.FullName
	}
}

# Install OneDrive - Not applicable to Server
Function InstallOneDrive {
	Write-Output "Installing OneDrive..."
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive -NoNewWindow
}

# Uninstall default Microsoft applications for Current User
Function UninstallMsftBloat {
	Write-Output "Uninstalling default Microsoft applications for current user..."
	$Bloatware = @(
        #default Windows 10 apps
        "Microsoft.3DBuilder"                       # Microsoft 3D Builder app
        "Microsoft.Advertising.JavaScript"          # Advertising framework
        "Microsoft.AppConnector"                    # App Connector app
        "BrowserChoice"                             # "Browser Choice" screen required by the EU antitrust regulation
        "Microsoft.BingFinance"                     # Money app - Financial news (MSN Money app)
        "Microsoft.BingFoodAndDrink"                # Food and Drink app
        "Microsoft.BingHealthAndFitness"            # Health and Fitness app
        "Microsoft.BingMaps"
        "Microsoft.BingNews"                        # Generic news app (MSN News app)
        "Microsoft.BingSports"                      # Sports app - Sports news (MSN Sports app)
        "Microsoft.BingTranslator"                  # Translator app - Bing Translate
        "Microsoft.BingTravel"                      # Travel app
        "Microsoft.BingWeather"                     # MSN Weather app
        "Microsoft.CommsPhone"                      # Communications - Phone app
        "Microsoft.549981C3F5F10"                   # Cortana app
        "Microsoft.DiagnosticDataViewer"
        "Microsoft.ForzaHorizon3Demo"
        "Microsoft.ForzaMotorsport7Demo"
        "Microsoft.GamingApp"
        "Microsoft.HoganThreshold"
        "Microsoft.ConnectivityStore"               # Microsoft Wi-Fi App
        "Microsoft.FreshPaint"                      # Canvas app
        "Microsoft.GetHelp"                         # Get Help app
        "Microsoft.Getstarted"                      # Microsoft Tips app
        "Microsoft.HelpAndTips"
        "Microsoft.Media.PlayReadyClient.2"
        "Microsoft.Messaging"                       # Messaging app
        "Microsoft.Microsoft3DViewer"               # 3D Viewer app
        "Microsoft.Lucille"                         # "Browser Choice" screen required by the EU antitrust regulation
        "Microsoft.MicrosoftOfficeHub"              # My Office app
        "Microsoft.MicrosoftPowerBIForWindows"      # Power BI app - Business analytics
        "Microsoft.MicrosoftRewards"
        "Microsoft.MicrosoftSudoku"
        "Microsoft.MicrosoftSolitaireCollection"    # Solitaire collection app
        "Microsoft.MicrosoftStickyNotes"            # Sticky Notes app
        "Microsoft.MinecraftUWP"                    # Minecraft for Windows 10 app
        "Microsoft.MovieMoments"
        "Microsoft.MixedReality.Portal"             # Mixed Reality Portal app
        "Microsoft.MoCamera"
        "Microsoft.MSPaint"                         # MS Paint (Paint 3D)
        "Microsoft.NetworkSpeedTest"                # Network Speed Test app
        "Microsoft.OfficeLens"
        "Microsoft.MicrosoftJackpot"                # Jackpot app
        "Microsoft.MicrosoftJigsaw"                 # Jigsaw app
        "Microsoft.Office.OneNote"                  # OneNote app
        "Microsoft.Office.Sway"                     # Sway app
        "Microsoft.OneConnect"                      # Paid Wi-Fi & Cellular app (Mobile Plans app)
        "Microsoft.MicrosoftMahjong"                # Advertising framework
        "Microsoft.People"                          # People app
        "Microsoft.Print3D"                         # Print 3D app
        "Microsoft.Reader"
        "Microsoft.RemoteDesktop"                   # Remote Desktop app
        "Microsoft.SkypeApp"                        # Get Skype link
        "Microsoft.SkypeWiFi"
        "Microsoft.Studios.Wordament"
        "Microsoft.GroupMe10"                       # GroupMe app
        "Microsoft.WindowsReadingList"
        "Microsoft.WorldNationalParks"
        "Windows.ContactSupport"
        "Microsoft.Windows.FeatureOnDemand.InsiderHub"
        "Microsoft.Todos"                           # Microsoft To Do app
        "Microsoft.Wallet"                          # Microsoft Pay app
        "Microsoft.WebMediaExtensions"              # Web Media Extensions app
        "Microsoft.WebpImageExtension"              # Webp Image Extensions app
        "Microsoft.VP9VideoExtensions"              # VP9 Video Extensions app
        "Microsoft.HEIFImageExtension"              # HEIF Image Extensions app
        "Microsoft.ScreenSketch"                    # Snip & Sketch app
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"                   # Alarms and Clock app
        "Microsoft.WindowsCamera"                   # Camera app
        "microsoft.windowscommunicationsapps"       # Calendar and Mail app
        "Microsoft.WindowsFeedbackHub"              # Feedback Hub app
        "Microsoft.WindowsMaps"                     # Windows Maps app
        "Microsoft.WindowsPhone"                    # Your Phone Companion app
        "Microsoft.Windows.Phone"                   # Your Phone Companion app
        "Microsoft.Windows.Photos"                  # Microsoft Photos app
        "Microsoft.WindowsReadingList"
        "Microsoft.WindowsScan"
        "Microsoft.WindowsSoundRecorder"            # Sound Recorder app
        "Microsoft.WindowsCalculator"               # Calculator app
        "Microsoft.WinJS.1.0"
        "Microsoft.WinJS.2.0"
        "Microsoft.YourPhone"                       # Your Phone app
        "Microsoft.ZuneMusic"                       # Groove Music app
        "Microsoft.ZuneVideo"                       # Movies and TV app
        "Microsoft.Advertising.Xaml"                # Dependency for microsoft.windowscommunicationsapps, Microsoft.BingWeather
    )
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $App | Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $App."
    }
}

# Install default Microsoft applications
Function InstallMsftBloat {
	Write-Output "Installing default Microsoft applications..."
	$Bloatware = @(
        "Microsoft.3DBuilder"                       # Microsoft 3D Builder app
        "Microsoft.Advertising.JavaScript"          # Advertising framework
        "Microsoft.AppConnector"                    # App Connector app
        "BrowserChoice"                             # "Browser Choice" screen required by the EU antitrust regulation
        "Microsoft.BingFinance"                     # Money app - Financial news (MSN Money app)
        "Microsoft.BingFoodAndDrink"                # Food and Drink app
        "Microsoft.BingHealthAndFitness"            # Health and Fitness app
        "Microsoft.BingMaps"
        "Microsoft.BingNews"                        # Generic news app (MSN News app)
        "Microsoft.BingSports"                      # Sports app - Sports news (MSN Sports app)
        "Microsoft.BingTranslator"                  # Translator app - Bing Translate
        "Microsoft.BingTravel"                      # Travel app
        "Microsoft.BingWeather"                     # MSN Weather app
        "Microsoft.CommsPhone"                      # Communications - Phone app
        "Microsoft.549981C3F5F10"                   # Cortana app
        "Microsoft.DiagnosticDataViewer"
        "Microsoft.ForzaHorizon3Demo"
        "Microsoft.ForzaMotorsport7Demo"
        "Microsoft.GamingApp"
        "Microsoft.HoganThreshold"
        "Microsoft.ConnectivityStore"               # Microsoft Wi-Fi App
        "Microsoft.FreshPaint"                      # Canvas app
        "Microsoft.GetHelp"                         # Get Help app
        "Microsoft.Getstarted"                      # Microsoft Tips app
        "Microsoft.HelpAndTips"
        "Microsoft.Media.PlayReadyClient.2"
        "Microsoft.Messaging"                       # Messaging app
        "Microsoft.Microsoft3DViewer"               # 3D Viewer app
        "Microsoft.Lucille"                         # "Browser Choice" screen required by the EU antitrust regulation
        "Microsoft.MicrosoftOfficeHub"              # My Office app
        "Microsoft.MicrosoftPowerBIForWindows"      # Power BI app - Business analytics
        "Microsoft.MicrosoftRewards"
        "Microsoft.MicrosoftSudoku"
        "Microsoft.MicrosoftSolitaireCollection"    # Solitaire collection app
        "Microsoft.MicrosoftStickyNotes"            # Sticky Notes app
        "Microsoft.MinecraftUWP"                    # Minecraft for Windows 10 app
        "Microsoft.MovieMoments"
        "Microsoft.MixedReality.Portal"             # Mixed Reality Portal app
        "Windows.CBSPreview"
        "Microsoft.MoCamera"
        "Microsoft.MSPaint"                         # MS Paint (Paint 3D)
        "Microsoft.NetworkSpeedTest"                # Network Speed Test app
        "Microsoft.OfficeLens"
        "Microsoft.MicrosoftJackpot"                # Jackpot app
        "Microsoft.MicrosoftJigsaw"                 # Jigsaw app
        "Microsoft.Office.OneNote"                  # OneNote app
        "Microsoft.Office.Sway"                     # Sway app
        "Microsoft.OneConnect"                      # Paid Wi-Fi & Cellular app (Mobile Plans app)
        "Microsoft.MicrosoftMahjong"                # Advertising framework
        "Microsoft.People"                          # People app
        "Microsoft.Print3D"                         # Print 3D app
        "Microsoft.Reader"
        "Microsoft.RemoteDesktop"                   # Remote Desktop app
        "Microsoft.SkypeApp"                        # Get Skype link
        "Microsoft.SkypeWiFi"
        "Microsoft.Studios.Wordament"
        "Microsoft.GroupMe10"                       # GroupMe app
        "Microsoft.WindowsReadingList"
        "Microsoft.WorldNationalParks"
        "Windows.ContactSupport"
        "Microsoft.Windows.FeatureOnDemand.InsiderHub"
        "Microsoft.Todos"                           # Microsoft To Do app
        "Microsoft.Wallet"                          # Microsoft Pay app
        "Microsoft.WebMediaExtensions"              # Web Media Extensions app
        "Microsoft.WebpImageExtension"              # Webp Image Extensions app
        "Microsoft.VP9VideoExtensions"              # VP9 Video Extensions app
        "Microsoft.HEIFImageExtension"              # HEIF Image Extensions app
        "Microsoft.ScreenSketch"                    # Snip & Sketch app
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"                   # Alarms and Clock app
        "Microsoft.WindowsCamera"                   # Camera app
        "microsoft.windowscommunicationsapps"       # Calendar and Mail app
        "Microsoft.WindowsFeedbackHub"              # Feedback Hub app
        "Microsoft.WindowsMaps"                     # Windows Maps app
        "Microsoft.WindowsPhone"                    # Your Phone Companion app
        "Microsoft.Windows.Phone"                   # Your Phone Companion app
        "Microsoft.Windows.Photos"                  # Microsoft Photos app
        "Microsoft.WindowsReadingList"
        "Microsoft.WindowsScan"
        "Microsoft.WindowsSoundRecorder"            # Sound Recorder app
        "Microsoft.WindowsCalculator"               # Calculator app
        "Microsoft.WinJS.1.0"
        "Microsoft.WinJS.2.0"
        "Microsoft.YourPhone"                       # Your Phone app
        "Microsoft.ZuneMusic"                       # Groove Music app
        "Microsoft.ZuneVideo"                       # Movies and TV app
        "Microsoft.Advertising.Xaml"                # Dependency for microsoft.windowscommunicationsapps, Microsoft.BingWeather
    )
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -AllUsers $Bloat | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Write-Host "Trying to reinstall $Bloat."
    }
}

# Uninstall default third party applications for current user
function UninstallThirdParty {
	Write-Output "Uninstalling default third party applications for current user..."
	$apps = @(
        "2414FC7A.Viber"
        "4DF9E0F8.Netflix"
        "CAF9E577.Plex"
        "Fitbit.FitbitCoach"
        "*DragonManiaLegends"
        "*HiddenCityMysteryofShadows"
        "*MarchofEmpires"
        "*toolbar*"
        "06DAC6F6.StumbleUpon"
        "09B6C2D8.TheTreasuresofMontezuma3"
        "0E3921EB.sMedioTrueDVDforHP"
        "10084FinerCode.ChessTactics"
        "11416StephenToub.SudokuClassic"
        "11508Heptazane.GPXPlayer"
        "11610RobertVarga.StopwatchFree"
        "12176PicturePerfectApps.GIFMaker-PhotostoGIFVideot"
        "12262FiveStarGames.CrossyChickenRoad"
        "12726CosmosChong.AdvancedEnglishDictionary"
        "128374E71F94E.SamsungStore"
        "12926CandyKingStudio.StickmanWarriorsFighting"
        "134D4F5B.Box*"
        "1430GreenfieldTechnologie.PuzzleTouch*"
        "145844925F2BF.Mahjong"
        "17036IYIA.StorySaverperInstagram"
        "17539gfyjwcs.SmartDwarfs"
        "181132B7.ZUUS"
        "184MagikHub.TextizeMindMap"
        "1867LennardSprong.PortablePuzzleCollection"
        "19965MattHafner.WifiAnalyzer"
        "20815shootingapp.AirFileViewer"
        "21090PaddyXu.QuickLook"
        "2121MagicCraftGames.ExplorationLiteCraftMining"
        "2164RexileStudios.FastYoutubeDownloader"
        "21824TapFunGames.DashImpossibleGeometryLite"
        "22062EdgeWaySoftware.TheLogosQuiz"
        "22094SynapticsIncorporate.AudioControls"
        "22094SynapticsIncorporate.SmartAudio2"
        "22094SynapticsIncorporate.SmartAudio3"
        "22380CatalanHilton.SolitaireDeluxe2019"
        "22450.BestVideoConverter"
        "24712m1dfmmengesha.TestFrameworkBP052015"
        "24712m1dfmmengesha.TestFrameworkBackpublish050515"
        "24712m1dfmmengesha.TestFrameworkwin81appxneutral06"
        "24712m1dfmmengesha.mxtest2"
        "24728AkshatKumarSingh.30376E696B184"
        "25231MatthiasShapiro.BrickInstructions"
        "25529kineapps.MyCalendar"
        "25920Bala04.Mideo-VideoPlayer"
        "26334ZenStudioGames.GachaLifeDangerousTravel"
        "26334ZenStudioGames.GachalifeStories"
        "26334ZenStudioGames.YandereSimulatorWarriorGacha"
        "26704KathyGrobbelaar.GPSRoutes"
        "26720RandomSaladGamesLLC.CribbageDeluxe"
        "26720RandomSaladGamesLLC.HeartsDeluxe*"
        "26720RandomSaladGamesLLC.Hexter"
        "26720RandomSaladGamesLLC.SimpleMahjong"
        "26720RandomSaladGamesLLC.SimpleMinesweeper"
        "26720RandomSaladGamesLLC.SimpleSolitaire*"
        "26720RandomSaladGamesLLC.SimpleSpiderSolitaire"
        "26720RandomSaladGamesLLC.Spades"
        "26720RandomSaladGamesLLC.Sudoku-Pro"
        "2703103D.McAfeeCentral"
        "27182KingdomEntertainment.Bubble.io-Agario"
        "27182KingdomEntertainment.FlippyKnife3D"
        "27182KingdomEntertainment.PixelGun3DPocketCrafting"
        "2724RoyaleDragonPacoGames.SpaceFrontierFree"
        "27345RickyWalker.BlackjackMaster3"
        "28287mfYSoftware.MiniRadioPlayer"
        "29313JVGoldSoft.5962504421940"
        "29534ukaszKurant.Logicos"
        "29534ukaszKurant.Logicos2"
        "29814LackoLuboslav.Bluetoothanalyzer"
        "29982CsabaHarmath.UnCompress*"
        "2CB8455F.Tanks"
        "2FE3CB00.PICSART-PHOTOSTUDIO"
        "2FE3CB00.PicsArt-PhotoStudio*"
        "30472FranciscoRodrigues.14392819EE0CF"
        "31653Sparkx.DrakeVideos"
        "32004CLEVERBIT.49301721A13B4"
        "32443PocketNet.Paper.io"
        "32940RyanW.Fiorini.BeyonceUltimate"
        "32940RyanW.Fiorini.PinkUltimate"
        "32988BernardoZamora.BackgammonPro"
        "32988BernardoZamora.SolitaireHD"
        "33916DoortoApps.HillClimbSimulation4x4"
        "34697joal.EasyMovieMaker"
        "35229MihaiM.QuizforGeeks"
        "35300Kubajzl.MCGuide"
        "35300Kubajzl.Slitherio"
        "37162EcsolvoTechnologies.UltraStopwatchTimer"
        "37442SublimeCo.AlarmClockForYou"
        "37457BenoitRenaud.HexWar"
        "37733Eiki184.Simple-TypephotoViewer"
        "37806WilhelmsenStudios.NowyouareinOrbit"
        "39492FruitCandy.VideocompressorTrimmer"
        "39674HytoGame.TexasHoldemOnline"
        "3973catalinux.BackgammonReloaded"
        "39806kalinnikol.FreeCellSolitaireHD"
        "39806kalinnikol.FreeHeartsHD"
        "39806kalinnikol.TheSpiderSolitaireHD"
        "401053BladeGames.3DDungeonEscape"
        "40459File-New-Project.EarTrumpet"
        "40538vasetest101.TESTFRAMEWORKABO2"
        "41038AXILESOFT.ACGMEDIAPLAYER"
        "41879VbfnetApps.FileDownloader"
        "42569AlexisPayendelaGaran.OtakuAssistant"
        "4262TopFreeGamesCOC.RunSausageRun"
        "4408APPStar.RiderUWP"
        "44218hungrymousegames.Mou"
        "44352GadgetWE.UnitConversion"
        "45375MiracleStudio.Splix.io"
        "45515SkyLineGames.Backgammon.free"
        "45604EntertainmentandMusi.Open7-Zip"
        "46928bounde.EclipseManager*"
        "47404LurkingDarknessOfRoy.SimpleStrategyRTS"
        "48682KiddoTest.Frameworkuapbase"
        "48938DngVnPhcThin.Deeep.io"
        "4961ThePlaymatE.DigitalImagination"
        "4AE8B7C2.Booking.comPartnerApp"
        "4AE8B7C2.Booking.comPartnerEdition*"
        "50856m1dfLL.TestFrameworkProd06221501"
        "51248Raximus.Dobryplan"
        "5269FriedChicken.YouTubeVideosDownloader*"
        "52755VolatileDove.LovingCubeEngine-experimentaledi"
        "55407EducationLife.LearntoMicrosoftAccess2010forBe"
        "55627FortrinexTechnology.PuzzleGallery"
        "55648JonathanPierce.RemindMeforWindows"
        "5603MorganMaurice.Caf-MonCompte"
        "56081SweetGamesBox.SlitherSnake.io"
        "56491SimulationFarmGames.100BallsOriginal"
        "57591LegendsSonicSagaGame.Twenty48Solitaire"
        "57689BIGWINStudio.Rider3D"
        "57868Codaapp.UploadforInstagram"
        "58033franckdakam.4KHDFreeWallpapers"
        "58255annmobile999.MusicMp3VideoDownload"
        "58539F3C.LexmarkPrinterHome"
        "5895BlastCrushGames.ExtremeCarDrivingSimulator2"
        "59091GameDesignStudio.HeartsUnlimited"
        "59091GameDesignStudio.MahjongDe*"
        "59169Willpowersystems.BlueSkyBrowser"
        "5A894077.McAfeeSecurity"
        "5CB722CC.CookingDiaryTastyHills"
        "60311BAFDEV.MyVideoDownloaderforYouTube"
        "62535WambaDev.FastYouTubeDownloaderFREE"
        "64885BlueEdge.OneCalendar*"
        "65284GameCabbage.OffRoadDriftSeries"
        "65327Damicolo.BartSimpsonSkateMania"
        "664D3057.MahjongDeluxeFree"
        "6E04A0BD.PhotoEditor"
        "6Wunderkinder.Wunderlist"
        "73F5BF5E.TwoDots"
        "7475BEDA.BitcoinMiner"
        "780F5C7B.FarmUp"
        "7906AAC0.TOSHIBACanadaPartners*"
        "7906AAC0.ToshibaCanadaWarrantyService*"
        "7906AAC0.TruRecorder"
        "7EE7776C.LinkedInforWindows"
        "7digitalLtd.7digitalMusicStore*"
        "81295E39.AnimalPuzzle"
        "828B5831.HiddenCityMysteryofShadows"
        "88449BC3.TodoistTo-DoListTaskManager"
        "89006A2E.AutodeskSketchBook*"
        "8bitSolutionsLLC.bitwardendesktop"
        "8tracksradio.8tracksradio"
        "9393SKYFamily.RollyVortex"
        "9426MICRO-STARINTERNATION.DragonCenter"
        "95FE1D22.VUDUMoviesandTV"
        "9E2F88E3.Twitter"
        "9FD20106.MediaPlayerQueen"
        "9FDF1AF1.HPImprezaPen"
        "A-Volute.Nahimic"
        "A025C540.Yandex.Music"
        "A278AB0D.DisneyMagicKingdoms"
        "A278AB0D.DragonManiaLegends*"
        "A278AB0D.GameloftGames"
        "A278AB0D.MarchofEmpires"
        "A278AB0D.PaddingtonRun"
        "A34E4AAB.YogaChef*"
        "A8C75DD4.Therefore"
        "A97ECD55.KYOCERAPrintCenter"
        "AD2F1837.BOAudioControl"
        "AD2F1837.BangOlufsenAudioControl"
        "AD2F1837.DiscoverHPTouchpointManager"
        "AD2F1837.GettingStartedwithWindows8"
        "AD2F1837.HPAudioCenter"
        "AD2F1837.HPBusinessSlimKeyboard"
        "AD2F1837.HPClassroomManager"
        "AD2F1837.HPConnectedMusic"
        "AD2F1837.HPConnectedPhotopoweredbySnapfish"
        "AD2F1837.HPCoolSense"
        "AD2F1837.HPFileViewer"
        "AD2F1837.HPGames"
        "AD2F1837.HPInc.EnergyStar"
        "AD2F1837.HPInteractiveLight"
        "AD2F1837.HPJumpStart"
        "AD2F1837.HPJumpStarts"
        "AD2F1837.HPPCHardwareDiagnosticsWindows"
        "AD2F1837.HPPhoneWise"
        "AD2F1837.HPPowerManager"
        "AD2F1837.HPPrimeFree"
        "AD2F1837.HPPrimeGraphingCalculator"
        "AD2F1837.HPPrivacySettings"
        "AD2F1837.HPProgrammableKey"
        "AD2F1837.HPRegistration"
        "AD2F1837.HPScanandCapture"
        "AD2F1837.HPSupportAssistant"
        "AD2F1837.HPSureShieldAI"
        "AD2F1837.HPSystemEventUtility"
        "AD2F1837.HPSystemInformation"
        "AD2F1837.HPThermalControl"
        "AD2F1837.HPWelcome"
        "AD2F1837.HPWorkWell"
        "AD2F1837.HPWorkWise"
        "AD2F1837.SavingsCenterFeaturedOffers"
        "AD2F1837.SmartfriendbyHPCare"
        "AD2F1837.bulbDigitalPortfolioforHPSchoolPack"
        "ASUSCloudCorporation.MobileFileExplorer"
        "AccuWeather.AccuWeatherforWindows8*"
        "AcerIncorporated*"
        "AcerIncorporated.AcerCareCenter"
        "AcerIncorporated.AcerCareCenterS"
        "AcerIncorporated.AcerCollection"
        "AcerIncorporated.AcerCollectionS"
        "AcerIncorporated.AcerExplorer"
        "AcerIncorporated.AcerRegistration"
        "AcerIncorporated.PredatorSenseV30"
        "AcerIncorporated.PredatorSenseV31"
        "AcerIncorporated.QuickAccess"
        "AcerIncorporated.UserExperienceImprovementProgram"
        "AcrobatNotificationClient"
        "ActiproSoftwareLLC*"
        "ActiproSoftwareLLC.562882FEEB491"
        "Adictiz.SpaceDogRun"
        "AdobeNotificationClient"
        "AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "AdobeSystemsIncorporated.AdobeRevel*"
        "AdvancedMicroDevicesInc-2.59462344778C5"
        "AdvancedMicroDevicesInc-2.AMDDisplayEnhance"
        "AeriaCanadaStudioInc.BlockWarsSurvivalGames"
        "AeriaCanadaStudioInc.CopsVsRobbersJailBreak"
        "Amazon.com.Amazon*"
        "Aol.AOLOn"
        "AppUp.IntelAppUpCatalogueAppWorldwideEdition*"
        "AppUp.IntelGraphicsExperience"
        "AppUp.IntelManagementandSecurityStatus"
        "AppUp.IntelOptaneMemoryandStorageManagement"
        "AppUp.ThunderboltControlCenter"
        "AppleInc.iCloud"
        "B9ECED6F.ASUSBatteryHealthCharging"
        "B9ECED6F.ASUSCalculator"
        "B9ECED6F.ASUSFiveinARow"
        "B9ECED6F.ASUSGIFTBOX*"
        "B9ECED6F.ASUSPCAssistant"
        "B9ECED6F.ASUSProductRegistrationProgram"
        "B9ECED6F.ASUSTutor"
        "B9ECED6F.ASUSTutorial"
        "B9ECED6F.ASUSWelcome"
        "B9ECED6F.ArmouryCrate"
        "B9ECED6F.AsusConverter"
        "B9ECED6F.GameVisual"
        "B9ECED6F.MyASUS"
        "B9ECED6F.TheWorldClock"
        "B9ECED6F.eManual"
        "BD9B8345.AlbumbySony*"
        "BD9B8345.MusicbySony*"
        "BD9B8345.Socialife*"
        "BD9B8345.VAIOCare*"
        "BD9B8345.VAIOMessageCenter*"
        "BooStudioLLC.8ZipLite"
        "BooStudioLLC.TorrexLite-TorrentDownloader"
        "BrowseTechLLC.AdRemover"
        "C27EB4BA.DROPBOX"
        "C27EB4BA.DropboxOEM"
        "COMPALELECTRONICSINC.AlienwareOSDKits"
        "COMPALELECTRONICSINC.AlienwareTypeCaccessory"
        "COMPALELECTRONICSINC.Alienwaredockingaccessory"
        "ChaChaSearch.ChaChaPushNotification*"
        "CirqueCorporation.DellPointStick"
        "ClearChannelRadioDigital.iHeartRadio*"
        "CrackleInc.Crackle*"
        "CreativeTechnologyLtd.SoundBlasterConnect"
        "CyberLink.PowerDirectorforMSI"
        "CyberLinkCorp.ac.AcerCrystalEye*"
        "CyberLinkCorp.ac.PhotoDirectorforacerDesktop"
        "CyberLinkCorp.ac.PowerDirectorforacerDesktop"
        "CyberLinkCorp.ac.SocialJogger*"
        "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC"
        "CyberLinkCorp.hs.YouCamforHP*"
        "CyberLinkCorp.id.PowerDVDforLenovoIdea*"
        "CyberLinkCorp.ss.SCamera"
        "CyberLinkCorp.ss.SGallery"
        "CyberLinkCorp.ss.SPlayer"
        "CyberLinkCorp.th.Power2GoforLenovo"
        "CyberLinkCorp.th.PowerDVDforLenovo"
        "D52A8D61.FarmVille2CountryEscape*"
        "D5BE6627.CompuCleverITHMBViewer"
        "D5BE6627.UltraBlu-rayPlayerSupportsDVD"
        "D5BE6627.UltraDVDPlayerPlatinum"
        "D5EA27B7.Duolingo-LearnLanguagesforFree*"
        "DB6EA5DB.CyberLinkMediaSuiteEssentials*"
        "DB6EA5DB.MediaSuiteEssentialsforDell"
        "DB6EA5DB.Power2GoforDell"
        "DB6EA5DB.PowerDirectorforDell"
        "DB6EA5DB.PowerMediaPlayerforDell"
        "DBA41F73.ColorNoteNotepadNotes"
        "DTSInc.51789B84BE3D7"
        "DTSInc.DTSCustomforAsus"
        "DTSInc.DTSHeadphoneXv1"
        "DailymotionSA.Dailymotion*"
        "DellInc.AlienwareCommandCenter"
        "DellInc.AlienwareCustomerConnect"
        "DellInc.AlienwareProductRegistration"
        "DellInc.DellCinemaGuide"
        "DellInc.DellCommandUpdate"
        "DellInc.DellCustomerConnect"
        "DellInc.DellDigitalDelivery"
        "DellInc.DellGettingStartedwithWindows8"
        "DellInc.DellHelpSupport"
        "DellInc.DellPowerManager"
        "DellInc.DellProductRegistration"
        "DellInc.DellShop"
        "DellInc.DellSupportAssistforPCs"
        "DellInc.DellUpdate"
        "DellInc.MyDell"
        "DellInc.PartnerPromo"
        "DellPrinter.DellDocumentHub"
        "DeviceDoctor.RAROpener"
        "DevolverDigital.MyFriendPedroWin10"
        "DolbyLaboratories.DolbyAccess*"
        "DolbyLaboratories.DolbyAtmosSoundSystem"
        "DolbyLaboratories.DolbyAtmosforGaming"
        "DolbyLaboratories.DolbyAudioPremium"
        "Drawboard.DrawboardPDF*"
        "DriverToaster*"
        "E046963F.LenovoCompanion*"
        "E046963F.LenovoSupport*"
        "E0469640.CameraMan*"
        "E0469640.DeviceCollaboration*"
        "E0469640.LenovoRecommends*"
        "E0469640.LenovoUtility"
        "E0469640.NerveCenter"
        "E0469640.YogaCameraMan*"
        "E0469640.YogaPhoneCompanion*"
        "E0469640.YogaPicks*"
        "E3D1C1C1.MEOGO"
        "E97CB0A1.LogitechCameraController"
        "ELANMicroelectronicsCorpo.ELANTouchpadSetting"
        "ELANMicroelectronicsCorpo.ELANTouchpadforThinkpad"
        "ESPNInc.WatchESPN*"
        "Ebates.EbatesCashBack"
        "EncyclopaediaBritannica.EncyclopaediaBritannica*"
        "EnnovaResearch.ToshibaPlaces"
        "Evernote.Evernote"
        "Evernote.Skitch*"
        "EvilGrogGamesGmbH.WorldPeaceGeneral2017"
        "F223684A.SkateboardParty2Lite"
        "F5080380.ASUSPowerDirector*"
        "FACEBOOK.317180B0BB486"
        "FINGERSOFT.HILLCLIMBRACING"
        "Facebook.317180B0BB486"
        "Facebook.Facebook"
        "Facebook.InstagramBeta*"
        "FilmOnLiveTVFree.FilmOnLiveTVFree*"
        "Fingersoft.HillClimbRacing"
        "Fingersoft.HillClimbRacing2"
        "FingertappsInstruments*"
        "FingertappsOrganizer*"
        "Flipboard.Flipboard*"
        "FreshPaint*"
        "GAMELOFTSA.Asphalt8Airborne*"
        "GAMELOFTSA.DespicableMeMinionRush"
        "GAMELOFTSA.GTRacing2TheRealCarExperience"
        "GAMELOFTSA.SharkDash*"
        "GIANTSSoftware.FarmingSimulator14"
        "GameCircusLLC.CoinDozer"
        "GameGeneticsApps.FreeOnlineGamesforLenovo*"
        "GettingStartedwithWindows8*"
        "GoogleInc.GoogleSearch"
        "HPConnectedMusic*"
        "HPConnectedPhotopoweredbySnapfish*"
        "HPRegistration*"
        "HuluLLC.HuluPlus*"
        "ICEpower.AudioWizard"
        "InsightAssessment.CriticalThinkingInsight"
        "JigsWar*"
        "K-NFBReadingTechnologiesI.BookPlace*"
        "KasperskyLab.KasperskyNow*"
        "KeeperSecurityInc.Keeper"
        "KindleforWindows8*"
        "Kortext.Kortext"
        "LGElectronics.LGControlCenter"
        "LGElectronics.LGEasyGuide2.0"
        "LGElectronics.LGOSD3"
        "LGElectronics.LGReaderMode"
        "LGElectronics.LGTroubleShooting2.0"
        "LenovoCorporation.LenovoID*"
        "LenovoCorporation.LenovoSettings*"
        "MAGIX.MusicMakerJam*"
        "MAXONComputerGmbH.Cinebench"
        "MSWP.DellTypeCStatus"
        "McAfeeInc.01.McAfeeSecurityAdvisorforDell"
        "McAfeeInc.05.McAfeeSecurityAdvisorforASUS"
        "McAfeeInc.06.McAfeeSecurityAdvisorforLenovo"
        "Mobigame.ZombieTsunami"
        "MobileFileExplorer*"
        "MobilesRepublic.NewsRepublic"
        "MobirateLtd.ParkingMania"
        "MusicMakerJam*"
        "NAMCOBANDAIGamesInc.PAC-MANChampionshipEditionDXfo*"
        "NAVER.LINEwin8*"
        "NBCUniversalMediaLLC.NBCSportsLiveExtra*"
        "NORDCURRENT.COOKINGFEVER"
        "NevosoftLLC.MushroomAge"
        "NextGenerationGames.WildDinosaurSniperHuntingHuntt"
        "NextIssue.NextIssueMagazine"
        "Nordcurrent.CookingFever"
        "OCS.OCS"
        "Ookla.SpeedtestbyOokla"
        "OrangeFrance.MaLivebox"
        "OrangeFrance.MailOrange"
        "OrangeFrance.TVdOrange"
        "PLRWorldwideSales.Gardenscapes-NewAcres"
        "PORTOEDITORA.EVe-Manuais"
        "PandoraMediaInc.29680B314EFC2"
        "PhotoAndVideoLabsLLC.MakeaPoster-ContinuumMediaSer"
        "PinballFx2*"
        "Pinterest.PinItButton"
        "Playtika.CaesarsSlotsFreeCasino*"
        "Pleemploi.Pleemploi"
        "PortraitDisplays.DellCinemaColor"
        "Priceline"
        "PricelinePartnerNetwork.Booking.comBigsavingsonhot"
        "PricelinePartnerNetwork.Booking.comEMEABigsavingso"
        "PricelinePartnerNetwork.Booking.comUSABigsavingson"
        "PricelinePartnerNetwork.Priceline.comTheBestDealso"
        "PublicationsInternational.iCookbookSE*"
        "ROBLOXCorporation.ROBLOX"
        "RandomSaladGamesLLC.GinRummyProforHP*"
        "RandomSaladGamesLLC.HeartsforHP"
        "ReaderNotificationClient"
        "RealtekSemiconductorCorp.HPAudioControl"
        "RealtekSemiconductorCorp.RealtekAudioControl"
        "Relay.com.KiosqueRelay"
        "RivetNetworks.KillerControlCenter"
        "RivetNetworks.SmartByte"
        "RollingDonutApps.JewelStar"
        "RoomAdjustment"
        "RubenGerlach.Solitaire-Palace"
        "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService"
        "SAMSUNGELECTRONICSCO.LTD.PCGallery"
        "SAMSUNGELECTRONICSCO.LTD.PCMessage"
        "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner"
        "SAMSUNGELECTRONICSCO.LTD.SamsungPrinterExperience"
        "SAMSUNGELECTRONICSCO.LTD.Wi-FiTransfer"
        "SAMSUNGELECTRONICSCoLtd.SamsungFlux"
        "STMicroelectronicsMEMS.DellFreeFallDataProtection"
        "ScreenovateTechnologies.DellMobileConnect"
        "SegaNetworksInc.56538047DFC80"
        "ShazamEntertainmentLtd.Shazam*"
        "SilverCreekEntertainment.HardwoodHearts"
        "SkisoSoft.FireEngineSimulator"
        "SkisoSoft.TrashTruckSimulator"
        "SocialQuantumIreland.WildWestNewFrontier"
        "SolidRhino.SteelTactics"
        "SonicWALL.MobileConnect"
        "SpotifyAB.SpotifyMusic"
        "SprakelsoftUG.CrocsWorld"
        "SprakelsoftUG.FlapFlapFlap"
        "SymantecCorporation.5478111E43ACF"
        "SymantecCorporation.NortonSafeWeb"
        "SymantecCorporation.NortonStudio*"
        "SynapticsIncorporated.SynHPCommercialDApp"
        "SynapticsIncorporated.SynHPCommercialStykDApp"
        "SynapticsIncorporated.SynHPConsumerDApp"
        "TOSHIBATEC.ToshibaPrintExperience"
        "TeenGamesLLC.HelicopterSimulator3DFree-ContinuumRe"
        "TelegraphMediaGroupLtd.TheTelegraphforLenovo*"
        "TelltaleGames.MinecraftStoryMode-ATelltaleGamesSer"
        "TheNewYorkTimes.NYTCrossword*"
        "ThumbmunkeysLtd.PhototasticCollage"
        "ThumbmunkeysLtd.PhototasticCollage*"
        "ToshibaAmericaInformation.ToshibaCentral*"
        "TreeCardGames.HeartsFree"
        "TriPlayInc.MyMusicCloud-Toshiba"
        "TripAdvisorLLC.TripAdvisorHotelsFlightsRestaurants*"
        "TuneIn.TuneInRadio*"
        "UniversalMusicMobile.HPLOUNGE"
        "UptoElevenDigitalSolution.mysms-Textanywhere*"
        "VectorUnit.BeachBuggyRacing"
        "Vimeo.Vimeo*"
        "WavesAudio.MaxxAudioProforDell2019"
        "WavesAudio.MaxxAudioProforDell2020"
        "WavesAudio.WavesMaxxAudioProforDell"
        "Weather.TheWeatherChannelforHP*"
        "Weather.TheWeatherChannelforLenovo*"
        "WeatherBug.a.WeatherBug"
        "WhatsNew"
        "WildTangentGames*"
        "WildTangentGames.-GamesApp-"
        "WildTangentGames.63435CFB65F55"
        "WinZipComputing.WinZipUniversal*"
        "XINGAG.XING"
        "XLabzTechnologies.22450B0065C6A"
        "XeroxCorp.PrintExperience"
        "YahooInc.54977BD360724"
        "YouSendIt.HighTailForLenovo*"
        "ZapposIPInc.Zappos.com"
        "ZeptoLabUKLimited.CutTheRope"
        "ZhuhaiKingsoftOfficeSoftw.WPSOffice"
        "ZhuhaiKingsoftOfficeSoftw.WPSOffice2019"
        "ZhuhaiKingsoftOfficeSoftw.WPSOfficeforFree"
        "ZinioLLC.Zinio*"
        "Zolmo.JamiesRecipes"
        "avonmobility.EnglishClub"
        "eBayInc.eBay*"
        "esobiIncorporated.newsXpressoMetro*"
        "fingertappsASUS.FingertappsInstrumentsrecommendedb*"
        "fingertappsASUS.JigsWarrecommendedbyASUS*"
        "fingertappsasus.FingertappsOrganizerrecommendedbyA*"
        "flaregamesGmbH.RoyalRevolt2*"
        "king.com*"
        "king.com.BubbleWitch3Saga"
        "king.com.CandyCrushFriends"
        "king.com.CandyCrushJellySaga"
        "king.com.CandyCrushSaga"
        "king.com.CandyCrushSodaSaga"
        "king.com.FarmHeroesSaga"
        "king.com.ParadiseBay"
        "n-tvNachrichtenfernsehenG.n-tvNachrichten"
        "rara.com.rara.com"
        "sMedioforHP.sMedio360*"
        "sMedioforToshiba.TOSHIBAMediaPlayerbysMedioTrueLin*"
        "www.cyberlink.com.AudioDirectorforLGE"
        "www.cyberlink.com.ColorDirectorforLGE"
        "www.cyberlink.com.PhotoDirectorforLGE"
        "www.cyberlink.com.PowerDirectorforLGE"
        "www.cyberlink.com.PowerMediaPlayerforLGE"
        "zuukaInc.iStoryTimeLibrary*"
    )
    foreach ($App in $Apps) {
        Get-AppxPackage -Name $App | Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $App."
    }
}

# Install default third party applications
Function InstallThirdParty {
	Write-Output "Installing default third party applications..."
	$apps = @(
        "2414FC7A.Viber"
        "4DF9E0F8.Netflix"
        "CAF9E577.Plex"
        "Fitbit.FitbitCoach"
        "*DragonManiaLegends"
        "*HiddenCityMysteryofShadows"
        "*MarchofEmpires"
        "*toolbar*"
        "06DAC6F6.StumbleUpon"
        "09B6C2D8.TheTreasuresofMontezuma3"
        "0E3921EB.sMedioTrueDVDforHP"
        "10084FinerCode.ChessTactics"
        "11416StephenToub.SudokuClassic"
        "11508Heptazane.GPXPlayer"
        "11610RobertVarga.StopwatchFree"
        "12176PicturePerfectApps.GIFMaker-PhotostoGIFVideot"
        "12262FiveStarGames.CrossyChickenRoad"
        "12726CosmosChong.AdvancedEnglishDictionary"
        "128374E71F94E.SamsungStore"
        "12926CandyKingStudio.StickmanWarriorsFighting"
        "134D4F5B.Box*"
        "1430GreenfieldTechnologie.PuzzleTouch*"
        "145844925F2BF.Mahjong"
        "17036IYIA.StorySaverperInstagram"
        "17539gfyjwcs.SmartDwarfs"
        "181132B7.ZUUS"
        "184MagikHub.TextizeMindMap"
        "1867LennardSprong.PortablePuzzleCollection"
        "19965MattHafner.WifiAnalyzer"
        "20815shootingapp.AirFileViewer"
        "21090PaddyXu.QuickLook"
        "2121MagicCraftGames.ExplorationLiteCraftMining"
        "2164RexileStudios.FastYoutubeDownloader"
        "21824TapFunGames.DashImpossibleGeometryLite"
        "22062EdgeWaySoftware.TheLogosQuiz"
        "22094SynapticsIncorporate.AudioControls"
        "22094SynapticsIncorporate.SmartAudio2"
        "22094SynapticsIncorporate.SmartAudio3"
        "22380CatalanHilton.SolitaireDeluxe2019"
        "22450.BestVideoConverter"
        "24712m1dfmmengesha.TestFrameworkBP052015"
        "24712m1dfmmengesha.TestFrameworkBackpublish050515"
        "24712m1dfmmengesha.TestFrameworkwin81appxneutral06"
        "24712m1dfmmengesha.mxtest2"
        "24728AkshatKumarSingh.30376E696B184"
        "25231MatthiasShapiro.BrickInstructions"
        "25529kineapps.MyCalendar"
        "25920Bala04.Mideo-VideoPlayer"
        "26334ZenStudioGames.GachaLifeDangerousTravel"
        "26334ZenStudioGames.GachalifeStories"
        "26334ZenStudioGames.YandereSimulatorWarriorGacha"
        "26704KathyGrobbelaar.GPSRoutes"
        "26720RandomSaladGamesLLC.CribbageDeluxe"
        "26720RandomSaladGamesLLC.HeartsDeluxe*"
        "26720RandomSaladGamesLLC.Hexter"
        "26720RandomSaladGamesLLC.SimpleMahjong"
        "26720RandomSaladGamesLLC.SimpleMinesweeper"
        "26720RandomSaladGamesLLC.SimpleSolitaire*"
        "26720RandomSaladGamesLLC.SimpleSpiderSolitaire"
        "26720RandomSaladGamesLLC.Spades"
        "26720RandomSaladGamesLLC.Sudoku-Pro"
        "2703103D.McAfeeCentral"
        "27182KingdomEntertainment.Bubble.io-Agario"
        "27182KingdomEntertainment.FlippyKnife3D"
        "27182KingdomEntertainment.PixelGun3DPocketCrafting"
        "2724RoyaleDragonPacoGames.SpaceFrontierFree"
        "27345RickyWalker.BlackjackMaster3"
        "28287mfYSoftware.MiniRadioPlayer"
        "29313JVGoldSoft.5962504421940"
        "29534ukaszKurant.Logicos"
        "29534ukaszKurant.Logicos2"
        "29814LackoLuboslav.Bluetoothanalyzer"
        "29982CsabaHarmath.UnCompress*"
        "2CB8455F.Tanks"
        "2FE3CB00.PICSART-PHOTOSTUDIO"
        "2FE3CB00.PicsArt-PhotoStudio*"
        "30472FranciscoRodrigues.14392819EE0CF"
        "31653Sparkx.DrakeVideos"
        "32004CLEVERBIT.49301721A13B4"
        "32443PocketNet.Paper.io"
        "32940RyanW.Fiorini.BeyonceUltimate"
        "32940RyanW.Fiorini.PinkUltimate"
        "32988BernardoZamora.BackgammonPro"
        "32988BernardoZamora.SolitaireHD"
        "33916DoortoApps.HillClimbSimulation4x4"
        "34697joal.EasyMovieMaker"
        "35229MihaiM.QuizforGeeks"
        "35300Kubajzl.MCGuide"
        "35300Kubajzl.Slitherio"
        "37162EcsolvoTechnologies.UltraStopwatchTimer"
        "37442SublimeCo.AlarmClockForYou"
        "37457BenoitRenaud.HexWar"
        "37733Eiki184.Simple-TypephotoViewer"
        "37806WilhelmsenStudios.NowyouareinOrbit"
        "39492FruitCandy.VideocompressorTrimmer"
        "39674HytoGame.TexasHoldemOnline"
        "3973catalinux.BackgammonReloaded"
        "39806kalinnikol.FreeCellSolitaireHD"
        "39806kalinnikol.FreeHeartsHD"
        "39806kalinnikol.TheSpiderSolitaireHD"
        "401053BladeGames.3DDungeonEscape"
        "40459File-New-Project.EarTrumpet"
        "40538vasetest101.TESTFRAMEWORKABO2"
        "41038AXILESOFT.ACGMEDIAPLAYER"
        "41879VbfnetApps.FileDownloader"
        "42569AlexisPayendelaGaran.OtakuAssistant"
        "4262TopFreeGamesCOC.RunSausageRun"
        "4408APPStar.RiderUWP"
        "44218hungrymousegames.Mou"
        "44352GadgetWE.UnitConversion"
        "45375MiracleStudio.Splix.io"
        "45515SkyLineGames.Backgammon.free"
        "45604EntertainmentandMusi.Open7-Zip"
        "46928bounde.EclipseManager*"
        "47404LurkingDarknessOfRoy.SimpleStrategyRTS"
        "48682KiddoTest.Frameworkuapbase"
        "48938DngVnPhcThin.Deeep.io"
        "4961ThePlaymatE.DigitalImagination"
        "4AE8B7C2.Booking.comPartnerApp"
        "4AE8B7C2.Booking.comPartnerEdition*"
        "50856m1dfLL.TestFrameworkProd06221501"
        "51248Raximus.Dobryplan"
        "5269FriedChicken.YouTubeVideosDownloader*"
        "52755VolatileDove.LovingCubeEngine-experimentaledi"
        "55407EducationLife.LearntoMicrosoftAccess2010forBe"
        "55627FortrinexTechnology.PuzzleGallery"
        "55648JonathanPierce.RemindMeforWindows"
        "5603MorganMaurice.Caf-MonCompte"
        "56081SweetGamesBox.SlitherSnake.io"
        "56491SimulationFarmGames.100BallsOriginal"
        "57591LegendsSonicSagaGame.Twenty48Solitaire"
        "57689BIGWINStudio.Rider3D"
        "57868Codaapp.UploadforInstagram"
        "58033franckdakam.4KHDFreeWallpapers"
        "58255annmobile999.MusicMp3VideoDownload"
        "58539F3C.LexmarkPrinterHome"
        "5895BlastCrushGames.ExtremeCarDrivingSimulator2"
        "59091GameDesignStudio.HeartsUnlimited"
        "59091GameDesignStudio.MahjongDe*"
        "59169Willpowersystems.BlueSkyBrowser"
        "5A894077.McAfeeSecurity"
        "5CB722CC.CookingDiaryTastyHills"
        "60311BAFDEV.MyVideoDownloaderforYouTube"
        "62535WambaDev.FastYouTubeDownloaderFREE"
        "64885BlueEdge.OneCalendar*"
        "65284GameCabbage.OffRoadDriftSeries"
        "65327Damicolo.BartSimpsonSkateMania"
        "664D3057.MahjongDeluxeFree"
        "6E04A0BD.PhotoEditor"
        "6Wunderkinder.Wunderlist"
        "73F5BF5E.TwoDots"
        "7475BEDA.BitcoinMiner"
        "780F5C7B.FarmUp"
        "7906AAC0.TOSHIBACanadaPartners*"
        "7906AAC0.ToshibaCanadaWarrantyService*"
        "7906AAC0.TruRecorder"
        "7EE7776C.LinkedInforWindows"
        "7digitalLtd.7digitalMusicStore*"
        "81295E39.AnimalPuzzle"
        "828B5831.HiddenCityMysteryofShadows"
        "88449BC3.TodoistTo-DoListTaskManager"
        "89006A2E.AutodeskSketchBook*"
        "8bitSolutionsLLC.bitwardendesktop"
        "8tracksradio.8tracksradio"
        "9393SKYFamily.RollyVortex"
        "9426MICRO-STARINTERNATION.DragonCenter"
        "95FE1D22.VUDUMoviesandTV"
        "9E2F88E3.Twitter"
        "9FD20106.MediaPlayerQueen"
        "9FDF1AF1.HPImprezaPen"
        "A-Volute.Nahimic"
        "A025C540.Yandex.Music"
        "A278AB0D.DisneyMagicKingdoms"
        "A278AB0D.DragonManiaLegends*"
        "A278AB0D.GameloftGames"
        "A278AB0D.MarchofEmpires"
        "A278AB0D.PaddingtonRun"
        "A34E4AAB.YogaChef*"
        "A8C75DD4.Therefore"
        "A97ECD55.KYOCERAPrintCenter"
        "AD2F1837.BOAudioControl"
        "AD2F1837.BangOlufsenAudioControl"
        "AD2F1837.DiscoverHPTouchpointManager"
        "AD2F1837.GettingStartedwithWindows8"
        "AD2F1837.HPAudioCenter"
        "AD2F1837.HPBusinessSlimKeyboard"
        "AD2F1837.HPClassroomManager"
        "AD2F1837.HPConnectedMusic"
        "AD2F1837.HPConnectedPhotopoweredbySnapfish"
        "AD2F1837.HPCoolSense"
        "AD2F1837.HPFileViewer"
        "AD2F1837.HPGames"
        "AD2F1837.HPInc.EnergyStar"
        "AD2F1837.HPInteractiveLight"
        "AD2F1837.HPJumpStart"
        "AD2F1837.HPJumpStarts"
        "AD2F1837.HPPCHardwareDiagnosticsWindows"
        "AD2F1837.HPPhoneWise"
        "AD2F1837.HPPowerManager"
        "AD2F1837.HPPrimeFree"
        "AD2F1837.HPPrimeGraphingCalculator"
        "AD2F1837.HPPrivacySettings"
        "AD2F1837.HPProgrammableKey"
        "AD2F1837.HPRegistration"
        "AD2F1837.HPScanandCapture"
        "AD2F1837.HPSupportAssistant"
        "AD2F1837.HPSureShieldAI"
        "AD2F1837.HPSystemEventUtility"
        "AD2F1837.HPSystemInformation"
        "AD2F1837.HPThermalControl"
        "AD2F1837.HPWelcome"
        "AD2F1837.HPWorkWell"
        "AD2F1837.HPWorkWise"
        "AD2F1837.SavingsCenterFeaturedOffers"
        "AD2F1837.SmartfriendbyHPCare"
        "AD2F1837.bulbDigitalPortfolioforHPSchoolPack"
        "ASUSCloudCorporation.MobileFileExplorer"
        "AccuWeather.AccuWeatherforWindows8*"
        "AcerIncorporated*"
        "AcerIncorporated.AcerCareCenter"
        "AcerIncorporated.AcerCareCenterS"
        "AcerIncorporated.AcerCollection"
        "AcerIncorporated.AcerCollectionS"
        "AcerIncorporated.AcerExplorer"
        "AcerIncorporated.AcerRegistration"
        "AcerIncorporated.PredatorSenseV30"
        "AcerIncorporated.PredatorSenseV31"
        "AcerIncorporated.QuickAccess"
        "AcerIncorporated.UserExperienceImprovementProgram"
        "AcrobatNotificationClient"
        "ActiproSoftwareLLC*"
        "ActiproSoftwareLLC.562882FEEB491"
        "Adictiz.SpaceDogRun"
        "AdobeNotificationClient"
        "AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "AdobeSystemsIncorporated.AdobeRevel*"
        "AdvancedMicroDevicesInc-2.59462344778C5"
        "AdvancedMicroDevicesInc-2.AMDDisplayEnhance"
        "AeriaCanadaStudioInc.BlockWarsSurvivalGames"
        "AeriaCanadaStudioInc.CopsVsRobbersJailBreak"
        "Amazon.com.Amazon*"
        "Aol.AOLOn"
        "AppUp.IntelAppUpCatalogueAppWorldwideEdition*"
        "AppUp.IntelGraphicsExperience"
        "AppUp.IntelManagementandSecurityStatus"
        "AppUp.IntelOptaneMemoryandStorageManagement"
        "AppUp.ThunderboltControlCenter"
        "AppleInc.iCloud"
        "B9ECED6F.ASUSBatteryHealthCharging"
        "B9ECED6F.ASUSCalculator"
        "B9ECED6F.ASUSFiveinARow"
        "B9ECED6F.ASUSGIFTBOX*"
        "B9ECED6F.ASUSPCAssistant"
        "B9ECED6F.ASUSProductRegistrationProgram"
        "B9ECED6F.ASUSTutor"
        "B9ECED6F.ASUSTutorial"
        "B9ECED6F.ASUSWelcome"
        "B9ECED6F.ArmouryCrate"
        "B9ECED6F.AsusConverter"
        "B9ECED6F.GameVisual"
        "B9ECED6F.MyASUS"
        "B9ECED6F.TheWorldClock"
        "B9ECED6F.eManual"
        "BD9B8345.AlbumbySony*"
        "BD9B8345.MusicbySony*"
        "BD9B8345.Socialife*"
        "BD9B8345.VAIOCare*"
        "BD9B8345.VAIOMessageCenter*"
        "BooStudioLLC.8ZipLite"
        "BooStudioLLC.TorrexLite-TorrentDownloader"
        "BrowseTechLLC.AdRemover"
        "C27EB4BA.DROPBOX"
        "C27EB4BA.DropboxOEM"
        "COMPALELECTRONICSINC.AlienwareOSDKits"
        "COMPALELECTRONICSINC.AlienwareTypeCaccessory"
        "COMPALELECTRONICSINC.Alienwaredockingaccessory"
        "ChaChaSearch.ChaChaPushNotification*"
        "CirqueCorporation.DellPointStick"
        "ClearChannelRadioDigital.iHeartRadio*"
        "CrackleInc.Crackle*"
        "CreativeTechnologyLtd.SoundBlasterConnect"
        "CyberLink.PowerDirectorforMSI"
        "CyberLinkCorp.ac.AcerCrystalEye*"
        "CyberLinkCorp.ac.PhotoDirectorforacerDesktop"
        "CyberLinkCorp.ac.PowerDirectorforacerDesktop"
        "CyberLinkCorp.ac.SocialJogger*"
        "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC"
        "CyberLinkCorp.hs.YouCamforHP*"
        "CyberLinkCorp.id.PowerDVDforLenovoIdea*"
        "CyberLinkCorp.ss.SCamera"
        "CyberLinkCorp.ss.SGallery"
        "CyberLinkCorp.ss.SPlayer"
        "CyberLinkCorp.th.Power2GoforLenovo"
        "CyberLinkCorp.th.PowerDVDforLenovo"
        "D52A8D61.FarmVille2CountryEscape*"
        "D5BE6627.CompuCleverITHMBViewer"
        "D5BE6627.UltraBlu-rayPlayerSupportsDVD"
        "D5BE6627.UltraDVDPlayerPlatinum"
        "D5EA27B7.Duolingo-LearnLanguagesforFree*"
        "DB6EA5DB.CyberLinkMediaSuiteEssentials*"
        "DB6EA5DB.MediaSuiteEssentialsforDell"
        "DB6EA5DB.Power2GoforDell"
        "DB6EA5DB.PowerDirectorforDell"
        "DB6EA5DB.PowerMediaPlayerforDell"
        "DBA41F73.ColorNoteNotepadNotes"
        "DTSInc.51789B84BE3D7"
        "DTSInc.DTSCustomforAsus"
        "DTSInc.DTSHeadphoneXv1"
        "DailymotionSA.Dailymotion*"
        "DellInc.AlienwareCommandCenter"
        "DellInc.AlienwareCustomerConnect"
        "DellInc.AlienwareProductRegistration"
        "DellInc.DellCinemaGuide"
        "DellInc.DellCommandUpdate"
        "DellInc.DellCustomerConnect"
        "DellInc.DellDigitalDelivery"
        "DellInc.DellGettingStartedwithWindows8"
        "DellInc.DellHelpSupport"
        "DellInc.DellPowerManager"
        "DellInc.DellProductRegistration"
        "DellInc.DellShop"
        "DellInc.DellSupportAssistforPCs"
        "DellInc.DellUpdate"
        "DellInc.MyDell"
        "DellInc.PartnerPromo"
        "DellPrinter.DellDocumentHub"
        "DeviceDoctor.RAROpener"
        "DevolverDigital.MyFriendPedroWin10"
        "DolbyLaboratories.DolbyAccess*"
        "DolbyLaboratories.DolbyAtmosSoundSystem"
        "DolbyLaboratories.DolbyAtmosforGaming"
        "DolbyLaboratories.DolbyAudioPremium"
        "Drawboard.DrawboardPDF*"
        "DriverToaster*"
        "E046963F.LenovoCompanion*"
        "E046963F.LenovoSupport*"
        "E0469640.CameraMan*"
        "E0469640.DeviceCollaboration*"
        "E0469640.LenovoRecommends*"
        "E0469640.LenovoUtility"
        "E0469640.NerveCenter"
        "E0469640.YogaCameraMan*"
        "E0469640.YogaPhoneCompanion*"
        "E0469640.YogaPicks*"
        "E3D1C1C1.MEOGO"
        "E97CB0A1.LogitechCameraController"
        "ELANMicroelectronicsCorpo.ELANTouchpadSetting"
        "ELANMicroelectronicsCorpo.ELANTouchpadforThinkpad"
        "ESPNInc.WatchESPN*"
        "Ebates.EbatesCashBack"
        "EncyclopaediaBritannica.EncyclopaediaBritannica*"
        "EnnovaResearch.ToshibaPlaces"
        "Evernote.Evernote"
        "Evernote.Skitch*"
        "EvilGrogGamesGmbH.WorldPeaceGeneral2017"
        "F223684A.SkateboardParty2Lite"
        "F5080380.ASUSPowerDirector*"
        "FACEBOOK.317180B0BB486"
        "FINGERSOFT.HILLCLIMBRACING"
        "Facebook.317180B0BB486"
        "Facebook.Facebook"
        "Facebook.InstagramBeta*"
        "FilmOnLiveTVFree.FilmOnLiveTVFree*"
        "Fingersoft.HillClimbRacing"
        "Fingersoft.HillClimbRacing2"
        "FingertappsInstruments*"
        "FingertappsOrganizer*"
        "Flipboard.Flipboard*"
        "FreshPaint*"
        "GAMELOFTSA.Asphalt8Airborne*"
        "GAMELOFTSA.DespicableMeMinionRush"
        "GAMELOFTSA.GTRacing2TheRealCarExperience"
        "GAMELOFTSA.SharkDash*"
        "GIANTSSoftware.FarmingSimulator14"
        "GameCircusLLC.CoinDozer"
        "GameGeneticsApps.FreeOnlineGamesforLenovo*"
        "GettingStartedwithWindows8*"
        "GoogleInc.GoogleSearch"
        "HPConnectedMusic*"
        "HPConnectedPhotopoweredbySnapfish*"
        "HPRegistration*"
        "HuluLLC.HuluPlus*"
        "ICEpower.AudioWizard"
        "InsightAssessment.CriticalThinkingInsight"
        "JigsWar*"
        "K-NFBReadingTechnologiesI.BookPlace*"
        "KasperskyLab.KasperskyNow*"
        "KeeperSecurityInc.Keeper"
        "KindleforWindows8*"
        "Kortext.Kortext"
        "LGElectronics.LGControlCenter"
        "LGElectronics.LGEasyGuide2.0"
        "LGElectronics.LGOSD3"
        "LGElectronics.LGReaderMode"
        "LGElectronics.LGTroubleShooting2.0"
        "LenovoCorporation.LenovoID*"
        "LenovoCorporation.LenovoSettings*"
        "MAGIX.MusicMakerJam*"
        "MAXONComputerGmbH.Cinebench"
        "MSWP.DellTypeCStatus"
        "McAfeeInc.01.McAfeeSecurityAdvisorforDell"
        "McAfeeInc.05.McAfeeSecurityAdvisorforASUS"
        "McAfeeInc.06.McAfeeSecurityAdvisorforLenovo"
        "Mobigame.ZombieTsunami"
        "MobileFileExplorer*"
        "MobilesRepublic.NewsRepublic"
        "MobirateLtd.ParkingMania"
        "MusicMakerJam*"
        "NAMCOBANDAIGamesInc.PAC-MANChampionshipEditionDXfo*"
        "NAVER.LINEwin8*"
        "NBCUniversalMediaLLC.NBCSportsLiveExtra*"
        "NORDCURRENT.COOKINGFEVER"
        "NevosoftLLC.MushroomAge"
        "NextGenerationGames.WildDinosaurSniperHuntingHuntt"
        "NextIssue.NextIssueMagazine"
        "Nordcurrent.CookingFever"
        "OCS.OCS"
        "Ookla.SpeedtestbyOokla"
        "OrangeFrance.MaLivebox"
        "OrangeFrance.MailOrange"
        "OrangeFrance.TVdOrange"
        "PLRWorldwideSales.Gardenscapes-NewAcres"
        "PORTOEDITORA.EVe-Manuais"
        "PandoraMediaInc.29680B314EFC2"
        "PhotoAndVideoLabsLLC.MakeaPoster-ContinuumMediaSer"
        "PinballFx2*"
        "Pinterest.PinItButton"
        "Playtika.CaesarsSlotsFreeCasino*"
        "Pleemploi.Pleemploi"
        "PortraitDisplays.DellCinemaColor"
        "Priceline"
        "PricelinePartnerNetwork.Booking.comBigsavingsonhot"
        "PricelinePartnerNetwork.Booking.comEMEABigsavingso"
        "PricelinePartnerNetwork.Booking.comUSABigsavingson"
        "PricelinePartnerNetwork.Priceline.comTheBestDealso"
        "PublicationsInternational.iCookbookSE*"
        "ROBLOXCorporation.ROBLOX"
        "RandomSaladGamesLLC.GinRummyProforHP*"
        "RandomSaladGamesLLC.HeartsforHP"
        "ReaderNotificationClient"
        "RealtekSemiconductorCorp.HPAudioControl"
        "RealtekSemiconductorCorp.RealtekAudioControl"
        "Relay.com.KiosqueRelay"
        "RivetNetworks.KillerControlCenter"
        "RivetNetworks.SmartByte"
        "RollingDonutApps.JewelStar"
        "RoomAdjustment"
        "RubenGerlach.Solitaire-Palace"
        "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService"
        "SAMSUNGELECTRONICSCO.LTD.PCGallery"
        "SAMSUNGELECTRONICSCO.LTD.PCMessage"
        "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner"
        "SAMSUNGELECTRONICSCO.LTD.SamsungPrinterExperience"
        "SAMSUNGELECTRONICSCO.LTD.Wi-FiTransfer"
        "SAMSUNGELECTRONICSCoLtd.SamsungFlux"
        "STMicroelectronicsMEMS.DellFreeFallDataProtection"
        "ScreenovateTechnologies.DellMobileConnect"
        "SegaNetworksInc.56538047DFC80"
        "ShazamEntertainmentLtd.Shazam*"
        "SilverCreekEntertainment.HardwoodHearts"
        "SkisoSoft.FireEngineSimulator"
        "SkisoSoft.TrashTruckSimulator"
        "SocialQuantumIreland.WildWestNewFrontier"
        "SolidRhino.SteelTactics"
        "SonicWALL.MobileConnect"
        "SpotifyAB.SpotifyMusic"
        "SprakelsoftUG.CrocsWorld"
        "SprakelsoftUG.FlapFlapFlap"
        "SymantecCorporation.5478111E43ACF"
        "SymantecCorporation.NortonSafeWeb"
        "SymantecCorporation.NortonStudio*"
        "SynapticsIncorporated.SynHPCommercialDApp"
        "SynapticsIncorporated.SynHPCommercialStykDApp"
        "SynapticsIncorporated.SynHPConsumerDApp"
        "TOSHIBATEC.ToshibaPrintExperience"
        "TeenGamesLLC.HelicopterSimulator3DFree-ContinuumRe"
        "TelegraphMediaGroupLtd.TheTelegraphforLenovo*"
        "TelltaleGames.MinecraftStoryMode-ATelltaleGamesSer"
        "TheNewYorkTimes.NYTCrossword*"
        "ThumbmunkeysLtd.PhototasticCollage"
        "ThumbmunkeysLtd.PhototasticCollage*"
        "ToshibaAmericaInformation.ToshibaCentral*"
        "TreeCardGames.HeartsFree"
        "TriPlayInc.MyMusicCloud-Toshiba"
        "TripAdvisorLLC.TripAdvisorHotelsFlightsRestaurants*"
        "TuneIn.TuneInRadio*"
        "UniversalMusicMobile.HPLOUNGE"
        "UptoElevenDigitalSolution.mysms-Textanywhere*"
        "VectorUnit.BeachBuggyRacing"
        "Vimeo.Vimeo*"
        "WavesAudio.MaxxAudioProforDell2019"
        "WavesAudio.MaxxAudioProforDell2020"
        "WavesAudio.WavesMaxxAudioProforDell"
        "Weather.TheWeatherChannelforHP*"
        "Weather.TheWeatherChannelforLenovo*"
        "WeatherBug.a.WeatherBug"
        "WhatsNew"
        "WildTangentGames*"
        "WildTangentGames.-GamesApp-"
        "WildTangentGames.63435CFB65F55"
        "WinZipComputing.WinZipUniversal*"
        "XINGAG.XING"
        "XLabzTechnologies.22450B0065C6A"
        "XeroxCorp.PrintExperience"
        "YahooInc.54977BD360724"
        "YouSendIt.HighTailForLenovo*"
        "ZapposIPInc.Zappos.com"
        "ZeptoLabUKLimited.CutTheRope"
        "ZhuhaiKingsoftOfficeSoftw.WPSOffice"
        "ZhuhaiKingsoftOfficeSoftw.WPSOffice2019"
        "ZhuhaiKingsoftOfficeSoftw.WPSOfficeforFree"
        "ZinioLLC.Zinio*"
        "Zolmo.JamiesRecipes"
        "avonmobility.EnglishClub"
        "eBayInc.eBay*"
        "esobiIncorporated.newsXpressoMetro*"
        "fingertappsASUS.FingertappsInstrumentsrecommendedb*"
        "fingertappsASUS.JigsWarrecommendedbyASUS*"
        "fingertappsasus.FingertappsOrganizerrecommendedbyA*"
        "flaregamesGmbH.RoyalRevolt2*"
        "king.com*"
        "king.com.BubbleWitch3Saga"
        "king.com.CandyCrushFriends"
        "king.com.CandyCrushJellySaga"
        "king.com.CandyCrushSaga"
        "king.com.CandyCrushSodaSaga"
        "king.com.FarmHeroesSaga"
        "king.com.ParadiseBay"
        "n-tvNachrichtenfernsehenG.n-tvNachrichten"
        "rara.com.rara.com"
        "sMedioforHP.sMedio360*"
        "sMedioforToshiba.TOSHIBAMediaPlayerbysMedioTrueLin*"
        "www.cyberlink.com.AudioDirectorforLGE"
        "www.cyberlink.com.ColorDirectorforLGE"
        "www.cyberlink.com.PhotoDirectorforLGE"
        "www.cyberlink.com.PowerDirectorforLGE"
        "www.cyberlink.com.PowerMediaPlayerforLGE"
        "zuukaInc.iStoryTimeLibrary*"
    )
    foreach ($App in $Apps) {
        Get-AppxPackage -AllUsers $App | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Write-Host "Trying to reinstall $App."
    }
}

# Uninstall default Microsoft applications for All Users
Function DebloatMsftApps {
	Write-Output "Uninstalling default Microsoft applications for all users..."
	$Bloatware = @(
        #default Windows 10 apps
        "Microsoft.3DBuilder"                       # Microsoft 3D Builder app
        "Microsoft.Advertising.JavaScript"          # Advertising framework
        "Microsoft.AppConnector"                    # App Connector app
        "BrowserChoice"                             # "Browser Choice" screen required by the EU antitrust regulation
        "Microsoft.BingFinance"                     # Money app - Financial news (MSN Money app)
        "Microsoft.BingFoodAndDrink"                # Food and Drink app
        "Microsoft.BingHealthAndFitness"            # Health and Fitness app
        "Microsoft.BingMaps"
        "Microsoft.BingNews"                        # Generic news app (MSN News app)
        "Microsoft.BingSports"                      # Sports app - Sports news (MSN Sports app)
        "Microsoft.BingTranslator"                  # Translator app - Bing Translate
        "Microsoft.BingTravel"                      # Travel app
        "Microsoft.BingWeather"                     # MSN Weather app
        "Microsoft.CommsPhone"                      # Communications - Phone app
        "Microsoft.549981C3F5F10"                   # Cortana app
        "Microsoft.DiagnosticDataViewer"
        "Microsoft.ForzaHorizon3Demo"
        "Microsoft.ForzaMotorsport7Demo"
        "Microsoft.GamingApp"
        "Microsoft.DesktopAppInstaller"             # App Installer
        "Microsoft.Services.Store.Engagement"
        "Microsoft.StorePurchaseApp"
        "Microsoft.WindowsStore"                    # Microsoft Store, if removed can't be reinstalled (To reinstall you will need a .appxbundle file)
        "Microsoft.XboxApp"                         # Xbox Console Companion
        "Microsoft.XboxIdentityProvider"            # Xbox Identity Provider (Required by Xbox Console Companion to sign in to xbox account)
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.Xbox.TCUI"
        "Microsoft.HoganThreshold"
        "Microsoft.ConnectivityStore"               # Microsoft Wi-Fi App
        "Microsoft.FreshPaint"                      # Canvas app
        "Microsoft.GetHelp"                         # Get Help app
        "Microsoft.Getstarted"                      # Microsoft Tips app
        "Microsoft.HelpAndTips"
        "Microsoft.Media.PlayReadyClient.2"
        "Microsoft.Messaging"                       # Messaging app
        "Microsoft.Microsoft3DViewer"               # 3D Viewer app
        "Microsoft.Lucille"                         # "Browser Choice" screen required by the EU antitrust regulation
        "Microsoft.MicrosoftOfficeHub"              # My Office app
        "Microsoft.MicrosoftPowerBIForWindows"      # Power BI app - Business analytics
        "Microsoft.MicrosoftRewards"
        "Microsoft.MicrosoftSudoku"
        "Microsoft.MicrosoftSolitaireCollection"    # Solitaire collection app
        "Microsoft.MicrosoftStickyNotes"            # Sticky Notes app
        "Microsoft.MinecraftUWP"                    # Minecraft for Windows 10 app
        "Microsoft.MovieMoments"
        "Microsoft.MixedReality.Portal"             # Mixed Reality Portal app
        "Windows.CBSPreview"
        "Microsoft.MoCamera"
        "Microsoft.MSPaint"                         # MS Paint (Paint 3D)
        "Microsoft.NetworkSpeedTest"                # Network Speed Test app
        "Microsoft.OfficeLens"
        "Microsoft.MicrosoftJackpot"                # Jackpot app
        "Microsoft.MicrosoftJigsaw"                 # Jigsaw app
        "Microsoft.Office.OneNote"                  # OneNote app
        "Microsoft.Office.Sway"                     # Sway app
        "Microsoft.OneConnect"                      # Paid Wi-Fi & Cellular app (Mobile Plans app)
        "Microsoft.MicrosoftMahjong"                # Advertising framework
        "Microsoft.People"                          # People app
        "Microsoft.Print3D"                         # Print 3D app
        "Microsoft.Reader"
        "Microsoft.RemoteDesktop"                   # Remote Desktop app
        "Microsoft.SkypeApp"                        # Get Skype link
        "Microsoft.SkypeWiFi"
        "Microsoft.Studios.Wordament"
        "Microsoft.GroupMe10"                       # GroupMe app
        "Microsoft.WindowsReadingList"
        "Microsoft.WorldNationalParks"
        "Windows.ContactSupport"
        "Microsoft.Windows.FeatureOnDemand.InsiderHub"
        "Microsoft.Todos"                           # Microsoft To Do app
        "Microsoft.Wallet"                          # Microsoft Pay app
        "Microsoft.WebMediaExtensions"              # Web Media Extensions app
        "Microsoft.WebpImageExtension"              # Webp Image Extensions app
        "Microsoft.VP9VideoExtensions"              # VP9 Video Extensions app
        "Microsoft.HEIFImageExtension"              # HEIF Image Extensions app
        "Microsoft.ScreenSketch"                    # Snip & Sketch app
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"                   # Alarms and Clock app
        "Microsoft.WindowsCamera"                   # Camera app
        "microsoft.windowscommunicationsapps"       # Calendar and Mail app
        "Microsoft.WindowsFeedbackHub"              # Feedback Hub app
        "Microsoft.WindowsMaps"                     # Windows Maps app
        "Microsoft.WindowsPhone"                    # Your Phone Companion app
        "Microsoft.Windows.Phone"                   # Your Phone Companion app
        "Microsoft.Windows.Photos"                  # Microsoft Photos app
        "Microsoft.WindowsReadingList"
        "Microsoft.WindowsScan"
        "Microsoft.WindowsSoundRecorder"            # Sound Recorder app
        "Microsoft.WindowsCalculator"               # Calculator app
        "Microsoft.WinJS.1.0"
        "Microsoft.WinJS.2.0"
        "Microsoft.YourPhone"                       # Your Phone app
        "Microsoft.ZuneMusic"                       # Groove Music app
        "Microsoft.ZuneVideo"                       # Movies and TV app
        "Microsoft.Advertising.Xaml"                # Dependency for microsoft.windowscommunicationsapps, Microsoft.BingWeather
    )
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxPackage -Name $Bloat -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        Write-Host "Trying to remove $Bloat."
    }
}

# Uninstall default third party applications for all users
Function DebloatThirdPartyApps {
	Write-Output "Uninstalling default third party applications for all users..."
	$apps = @(
        "2414FC7A.Viber"
        "4DF9E0F8.Netflix"
        "CAF9E577.Plex"
        "Fitbit.FitbitCoach"
        "*DragonManiaLegends"
        "*HiddenCityMysteryofShadows"
        "*MarchofEmpires"
        "*toolbar*"
        "06DAC6F6.StumbleUpon"
        "09B6C2D8.TheTreasuresofMontezuma3"
        "0E3921EB.sMedioTrueDVDforHP"
        "10084FinerCode.ChessTactics"
        "11416StephenToub.SudokuClassic"
        "11508Heptazane.GPXPlayer"
        "11610RobertVarga.StopwatchFree"
        "12176PicturePerfectApps.GIFMaker-PhotostoGIFVideot"
        "12262FiveStarGames.CrossyChickenRoad"
        "12726CosmosChong.AdvancedEnglishDictionary"
        "128374E71F94E.SamsungStore"
        "12926CandyKingStudio.StickmanWarriorsFighting"
        "134D4F5B.Box*"
        "1430GreenfieldTechnologie.PuzzleTouch*"
        "145844925F2BF.Mahjong"
        "17036IYIA.StorySaverperInstagram"
        "17539gfyjwcs.SmartDwarfs"
        "181132B7.ZUUS"
        "184MagikHub.TextizeMindMap"
        "1867LennardSprong.PortablePuzzleCollection"
        "19965MattHafner.WifiAnalyzer"
        "20815shootingapp.AirFileViewer"
        "21090PaddyXu.QuickLook"
        "2121MagicCraftGames.ExplorationLiteCraftMining"
        "2164RexileStudios.FastYoutubeDownloader"
        "21824TapFunGames.DashImpossibleGeometryLite"
        "22062EdgeWaySoftware.TheLogosQuiz"
        "22094SynapticsIncorporate.AudioControls"
        "22094SynapticsIncorporate.SmartAudio2"
        "22094SynapticsIncorporate.SmartAudio3"
        "22380CatalanHilton.SolitaireDeluxe2019"
        "22450.BestVideoConverter"
        "24712m1dfmmengesha.TestFrameworkBP052015"
        "24712m1dfmmengesha.TestFrameworkBackpublish050515"
        "24712m1dfmmengesha.TestFrameworkwin81appxneutral06"
        "24712m1dfmmengesha.mxtest2"
        "24728AkshatKumarSingh.30376E696B184"
        "25231MatthiasShapiro.BrickInstructions"
        "25529kineapps.MyCalendar"
        "25920Bala04.Mideo-VideoPlayer"
        "26334ZenStudioGames.GachaLifeDangerousTravel"
        "26334ZenStudioGames.GachalifeStories"
        "26334ZenStudioGames.YandereSimulatorWarriorGacha"
        "26704KathyGrobbelaar.GPSRoutes"
        "26720RandomSaladGamesLLC.CribbageDeluxe"
        "26720RandomSaladGamesLLC.HeartsDeluxe*"
        "26720RandomSaladGamesLLC.Hexter"
        "26720RandomSaladGamesLLC.SimpleMahjong"
        "26720RandomSaladGamesLLC.SimpleMinesweeper"
        "26720RandomSaladGamesLLC.SimpleSolitaire*"
        "26720RandomSaladGamesLLC.SimpleSpiderSolitaire"
        "26720RandomSaladGamesLLC.Spades"
        "26720RandomSaladGamesLLC.Sudoku-Pro"
        "2703103D.McAfeeCentral"
        "27182KingdomEntertainment.Bubble.io-Agario"
        "27182KingdomEntertainment.FlippyKnife3D"
        "27182KingdomEntertainment.PixelGun3DPocketCrafting"
        "2724RoyaleDragonPacoGames.SpaceFrontierFree"
        "27345RickyWalker.BlackjackMaster3"
        "28287mfYSoftware.MiniRadioPlayer"
        "29313JVGoldSoft.5962504421940"
        "29534ukaszKurant.Logicos"
        "29534ukaszKurant.Logicos2"
        "29814LackoLuboslav.Bluetoothanalyzer"
        "29982CsabaHarmath.UnCompress*"
        "2CB8455F.Tanks"
        "2FE3CB00.PICSART-PHOTOSTUDIO"
        "2FE3CB00.PicsArt-PhotoStudio*"
        "30472FranciscoRodrigues.14392819EE0CF"
        "31653Sparkx.DrakeVideos"
        "32004CLEVERBIT.49301721A13B4"
        "32443PocketNet.Paper.io"
        "32940RyanW.Fiorini.BeyonceUltimate"
        "32940RyanW.Fiorini.PinkUltimate"
        "32988BernardoZamora.BackgammonPro"
        "32988BernardoZamora.SolitaireHD"
        "33916DoortoApps.HillClimbSimulation4x4"
        "34697joal.EasyMovieMaker"
        "35229MihaiM.QuizforGeeks"
        "35300Kubajzl.MCGuide"
        "35300Kubajzl.Slitherio"
        "37162EcsolvoTechnologies.UltraStopwatchTimer"
        "37442SublimeCo.AlarmClockForYou"
        "37457BenoitRenaud.HexWar"
        "37733Eiki184.Simple-TypephotoViewer"
        "37806WilhelmsenStudios.NowyouareinOrbit"
        "39492FruitCandy.VideocompressorTrimmer"
        "39674HytoGame.TexasHoldemOnline"
        "3973catalinux.BackgammonReloaded"
        "39806kalinnikol.FreeCellSolitaireHD"
        "39806kalinnikol.FreeHeartsHD"
        "39806kalinnikol.TheSpiderSolitaireHD"
        "401053BladeGames.3DDungeonEscape"
        "40459File-New-Project.EarTrumpet"
        "40538vasetest101.TESTFRAMEWORKABO2"
        "41038AXILESOFT.ACGMEDIAPLAYER"
        "41879VbfnetApps.FileDownloader"
        "42569AlexisPayendelaGaran.OtakuAssistant"
        "4262TopFreeGamesCOC.RunSausageRun"
        "4408APPStar.RiderUWP"
        "44218hungrymousegames.Mou"
        "44352GadgetWE.UnitConversion"
        "45375MiracleStudio.Splix.io"
        "45515SkyLineGames.Backgammon.free"
        "45604EntertainmentandMusi.Open7-Zip"
        "46928bounde.EclipseManager*"
        "47404LurkingDarknessOfRoy.SimpleStrategyRTS"
        "48682KiddoTest.Frameworkuapbase"
        "48938DngVnPhcThin.Deeep.io"
        "4961ThePlaymatE.DigitalImagination"
        "4AE8B7C2.Booking.comPartnerApp"
        "4AE8B7C2.Booking.comPartnerEdition*"
        "50856m1dfLL.TestFrameworkProd06221501"
        "51248Raximus.Dobryplan"
        "5269FriedChicken.YouTubeVideosDownloader*"
        "52755VolatileDove.LovingCubeEngine-experimentaledi"
        "55407EducationLife.LearntoMicrosoftAccess2010forBe"
        "55627FortrinexTechnology.PuzzleGallery"
        "55648JonathanPierce.RemindMeforWindows"
        "5603MorganMaurice.Caf-MonCompte"
        "56081SweetGamesBox.SlitherSnake.io"
        "56491SimulationFarmGames.100BallsOriginal"
        "57591LegendsSonicSagaGame.Twenty48Solitaire"
        "57689BIGWINStudio.Rider3D"
        "57868Codaapp.UploadforInstagram"
        "58033franckdakam.4KHDFreeWallpapers"
        "58255annmobile999.MusicMp3VideoDownload"
        "58539F3C.LexmarkPrinterHome"
        "5895BlastCrushGames.ExtremeCarDrivingSimulator2"
        "59091GameDesignStudio.HeartsUnlimited"
        "59091GameDesignStudio.MahjongDe*"
        "59169Willpowersystems.BlueSkyBrowser"
        "5A894077.McAfeeSecurity"
        "5CB722CC.CookingDiaryTastyHills"
        "60311BAFDEV.MyVideoDownloaderforYouTube"
        "62535WambaDev.FastYouTubeDownloaderFREE"
        "64885BlueEdge.OneCalendar*"
        "65284GameCabbage.OffRoadDriftSeries"
        "65327Damicolo.BartSimpsonSkateMania"
        "664D3057.MahjongDeluxeFree"
        "6E04A0BD.PhotoEditor"
        "6Wunderkinder.Wunderlist"
        "73F5BF5E.TwoDots"
        "7475BEDA.BitcoinMiner"
        "780F5C7B.FarmUp"
        "7906AAC0.TOSHIBACanadaPartners*"
        "7906AAC0.ToshibaCanadaWarrantyService*"
        "7906AAC0.TruRecorder"
        "7EE7776C.LinkedInforWindows"
        "7digitalLtd.7digitalMusicStore*"
        "81295E39.AnimalPuzzle"
        "828B5831.HiddenCityMysteryofShadows"
        "88449BC3.TodoistTo-DoListTaskManager"
        "89006A2E.AutodeskSketchBook*"
        "8bitSolutionsLLC.bitwardendesktop"
        "8tracksradio.8tracksradio"
        "9393SKYFamily.RollyVortex"
        "9426MICRO-STARINTERNATION.DragonCenter"
        "95FE1D22.VUDUMoviesandTV"
        "9E2F88E3.Twitter"
        "9FD20106.MediaPlayerQueen"
        "9FDF1AF1.HPImprezaPen"
        "A-Volute.Nahimic"
        "A025C540.Yandex.Music"
        "A278AB0D.DisneyMagicKingdoms"
        "A278AB0D.DragonManiaLegends*"
        "A278AB0D.GameloftGames"
        "A278AB0D.MarchofEmpires"
        "A278AB0D.PaddingtonRun"
        "A34E4AAB.YogaChef*"
        "A8C75DD4.Therefore"
        "A97ECD55.KYOCERAPrintCenter"
        "AD2F1837.BOAudioControl"
        "AD2F1837.BangOlufsenAudioControl"
        "AD2F1837.DiscoverHPTouchpointManager"
        "AD2F1837.GettingStartedwithWindows8"
        "AD2F1837.HPAudioCenter"
        "AD2F1837.HPBusinessSlimKeyboard"
        "AD2F1837.HPClassroomManager"
        "AD2F1837.HPConnectedMusic"
        "AD2F1837.HPConnectedPhotopoweredbySnapfish"
        "AD2F1837.HPCoolSense"
        "AD2F1837.HPFileViewer"
        "AD2F1837.HPGames"
        "AD2F1837.HPInc.EnergyStar"
        "AD2F1837.HPInteractiveLight"
        "AD2F1837.HPJumpStart"
        "AD2F1837.HPJumpStarts"
        "AD2F1837.HPPCHardwareDiagnosticsWindows"
        "AD2F1837.HPPhoneWise"
        "AD2F1837.HPPowerManager"
        "AD2F1837.HPPrimeFree"
        "AD2F1837.HPPrimeGraphingCalculator"
        "AD2F1837.HPPrivacySettings"
        "AD2F1837.HPProgrammableKey"
        "AD2F1837.HPRegistration"
        "AD2F1837.HPScanandCapture"
        "AD2F1837.HPSupportAssistant"
        "AD2F1837.HPSureShieldAI"
        "AD2F1837.HPSystemEventUtility"
        "AD2F1837.HPSystemInformation"
        "AD2F1837.HPThermalControl"
        "AD2F1837.HPWelcome"
        "AD2F1837.HPWorkWell"
        "AD2F1837.HPWorkWise"
        "AD2F1837.SavingsCenterFeaturedOffers"
        "AD2F1837.SmartfriendbyHPCare"
        "AD2F1837.bulbDigitalPortfolioforHPSchoolPack"
        "ASUSCloudCorporation.MobileFileExplorer"
        "AccuWeather.AccuWeatherforWindows8*"
        "AcerIncorporated*"
        "AcerIncorporated.AcerCareCenter"
        "AcerIncorporated.AcerCareCenterS"
        "AcerIncorporated.AcerCollection"
        "AcerIncorporated.AcerCollectionS"
        "AcerIncorporated.AcerExplorer"
        "AcerIncorporated.AcerRegistration"
        "AcerIncorporated.PredatorSenseV30"
        "AcerIncorporated.PredatorSenseV31"
        "AcerIncorporated.QuickAccess"
        "AcerIncorporated.UserExperienceImprovementProgram"
        "AcrobatNotificationClient"
        "ActiproSoftwareLLC*"
        "ActiproSoftwareLLC.562882FEEB491"
        "Adictiz.SpaceDogRun"
        "AdobeNotificationClient"
        "AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "AdobeSystemsIncorporated.AdobeRevel*"
        "AdvancedMicroDevicesInc-2.59462344778C5"
        "AdvancedMicroDevicesInc-2.AMDDisplayEnhance"
        "AeriaCanadaStudioInc.BlockWarsSurvivalGames"
        "AeriaCanadaStudioInc.CopsVsRobbersJailBreak"
        "Amazon.com.Amazon*"
        "Aol.AOLOn"
        "AppUp.IntelAppUpCatalogueAppWorldwideEdition*"
        "AppUp.IntelGraphicsExperience"
        "AppUp.IntelManagementandSecurityStatus"
        "AppUp.IntelOptaneMemoryandStorageManagement"
        "AppUp.ThunderboltControlCenter"
        "AppleInc.iCloud"
        "B9ECED6F.ASUSBatteryHealthCharging"
        "B9ECED6F.ASUSCalculator"
        "B9ECED6F.ASUSFiveinARow"
        "B9ECED6F.ASUSGIFTBOX*"
        "B9ECED6F.ASUSPCAssistant"
        "B9ECED6F.ASUSProductRegistrationProgram"
        "B9ECED6F.ASUSTutor"
        "B9ECED6F.ASUSTutorial"
        "B9ECED6F.ASUSWelcome"
        "B9ECED6F.ArmouryCrate"
        "B9ECED6F.AsusConverter"
        "B9ECED6F.GameVisual"
        "B9ECED6F.MyASUS"
        "B9ECED6F.TheWorldClock"
        "B9ECED6F.eManual"
        "BD9B8345.AlbumbySony*"
        "BD9B8345.MusicbySony*"
        "BD9B8345.Socialife*"
        "BD9B8345.VAIOCare*"
        "BD9B8345.VAIOMessageCenter*"
        "BooStudioLLC.8ZipLite"
        "BooStudioLLC.TorrexLite-TorrentDownloader"
        "BrowseTechLLC.AdRemover"
        "C27EB4BA.DROPBOX"
        "C27EB4BA.DropboxOEM"
        "COMPALELECTRONICSINC.AlienwareOSDKits"
        "COMPALELECTRONICSINC.AlienwareTypeCaccessory"
        "COMPALELECTRONICSINC.Alienwaredockingaccessory"
        "ChaChaSearch.ChaChaPushNotification*"
        "CirqueCorporation.DellPointStick"
        "ClearChannelRadioDigital.iHeartRadio*"
        "CrackleInc.Crackle*"
        "CreativeTechnologyLtd.SoundBlasterConnect"
        "CyberLink.PowerDirectorforMSI"
        "CyberLinkCorp.ac.AcerCrystalEye*"
        "CyberLinkCorp.ac.PhotoDirectorforacerDesktop"
        "CyberLinkCorp.ac.PowerDirectorforacerDesktop"
        "CyberLinkCorp.ac.SocialJogger*"
        "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC"
        "CyberLinkCorp.hs.YouCamforHP*"
        "CyberLinkCorp.id.PowerDVDforLenovoIdea*"
        "CyberLinkCorp.ss.SCamera"
        "CyberLinkCorp.ss.SGallery"
        "CyberLinkCorp.ss.SPlayer"
        "CyberLinkCorp.th.Power2GoforLenovo"
        "CyberLinkCorp.th.PowerDVDforLenovo"
        "D52A8D61.FarmVille2CountryEscape*"
        "D5BE6627.CompuCleverITHMBViewer"
        "D5BE6627.UltraBlu-rayPlayerSupportsDVD"
        "D5BE6627.UltraDVDPlayerPlatinum"
        "D5EA27B7.Duolingo-LearnLanguagesforFree*"
        "DB6EA5DB.CyberLinkMediaSuiteEssentials*"
        "DB6EA5DB.MediaSuiteEssentialsforDell"
        "DB6EA5DB.Power2GoforDell"
        "DB6EA5DB.PowerDirectorforDell"
        "DB6EA5DB.PowerMediaPlayerforDell"
        "DBA41F73.ColorNoteNotepadNotes"
        "DTSInc.51789B84BE3D7"
        "DTSInc.DTSCustomforAsus"
        "DTSInc.DTSHeadphoneXv1"
        "DailymotionSA.Dailymotion*"
        "DellInc.AlienwareCommandCenter"
        "DellInc.AlienwareCustomerConnect"
        "DellInc.AlienwareProductRegistration"
        "DellInc.DellCinemaGuide"
        "DellInc.DellCommandUpdate"
        "DellInc.DellCustomerConnect"
        "DellInc.DellDigitalDelivery"
        "DellInc.DellGettingStartedwithWindows8"
        "DellInc.DellHelpSupport"
        "DellInc.DellPowerManager"
        "DellInc.DellProductRegistration"
        "DellInc.DellShop"
        "DellInc.DellSupportAssistforPCs"
        "DellInc.DellUpdate"
        "DellInc.MyDell"
        "DellInc.PartnerPromo"
        "DellPrinter.DellDocumentHub"
        "DeviceDoctor.RAROpener"
        "DevolverDigital.MyFriendPedroWin10"
        "DolbyLaboratories.DolbyAccess*"
        "DolbyLaboratories.DolbyAtmosSoundSystem"
        "DolbyLaboratories.DolbyAtmosforGaming"
        "DolbyLaboratories.DolbyAudioPremium"
        "Drawboard.DrawboardPDF*"
        "DriverToaster*"
        "E046963F.LenovoCompanion*"
        "E046963F.LenovoSupport*"
        "E0469640.CameraMan*"
        "E0469640.DeviceCollaboration*"
        "E0469640.LenovoRecommends*"
        "E0469640.LenovoUtility"
        "E0469640.NerveCenter"
        "E0469640.YogaCameraMan*"
        "E0469640.YogaPhoneCompanion*"
        "E0469640.YogaPicks*"
        "E3D1C1C1.MEOGO"
        "E97CB0A1.LogitechCameraController"
        "ELANMicroelectronicsCorpo.ELANTouchpadSetting"
        "ELANMicroelectronicsCorpo.ELANTouchpadforThinkpad"
        "ESPNInc.WatchESPN*"
        "Ebates.EbatesCashBack"
        "EncyclopaediaBritannica.EncyclopaediaBritannica*"
        "EnnovaResearch.ToshibaPlaces"
        "Evernote.Evernote"
        "Evernote.Skitch*"
        "EvilGrogGamesGmbH.WorldPeaceGeneral2017"
        "F223684A.SkateboardParty2Lite"
        "F5080380.ASUSPowerDirector*"
        "FACEBOOK.317180B0BB486"
        "FINGERSOFT.HILLCLIMBRACING"
        "Facebook.317180B0BB486"
        "Facebook.Facebook"
        "Facebook.InstagramBeta*"
        "FilmOnLiveTVFree.FilmOnLiveTVFree*"
        "Fingersoft.HillClimbRacing"
        "Fingersoft.HillClimbRacing2"
        "FingertappsInstruments*"
        "FingertappsOrganizer*"
        "Flipboard.Flipboard*"
        "FreshPaint*"
        "GAMELOFTSA.Asphalt8Airborne*"
        "GAMELOFTSA.DespicableMeMinionRush"
        "GAMELOFTSA.GTRacing2TheRealCarExperience"
        "GAMELOFTSA.SharkDash*"
        "GIANTSSoftware.FarmingSimulator14"
        "GameCircusLLC.CoinDozer"
        "GameGeneticsApps.FreeOnlineGamesforLenovo*"
        "GettingStartedwithWindows8*"
        "GoogleInc.GoogleSearch"
        "HPConnectedMusic*"
        "HPConnectedPhotopoweredbySnapfish*"
        "HPRegistration*"
        "HuluLLC.HuluPlus*"
        "ICEpower.AudioWizard"
        "InsightAssessment.CriticalThinkingInsight"
        "JigsWar*"
        "K-NFBReadingTechnologiesI.BookPlace*"
        "KasperskyLab.KasperskyNow*"
        "KeeperSecurityInc.Keeper"
        "KindleforWindows8*"
        "Kortext.Kortext"
        "LGElectronics.LGControlCenter"
        "LGElectronics.LGEasyGuide2.0"
        "LGElectronics.LGOSD3"
        "LGElectronics.LGReaderMode"
        "LGElectronics.LGTroubleShooting2.0"
        "LenovoCorporation.LenovoID*"
        "LenovoCorporation.LenovoSettings*"
        "MAGIX.MusicMakerJam*"
        "MAXONComputerGmbH.Cinebench"
        "MSWP.DellTypeCStatus"
        "McAfeeInc.01.McAfeeSecurityAdvisorforDell"
        "McAfeeInc.05.McAfeeSecurityAdvisorforASUS"
        "McAfeeInc.06.McAfeeSecurityAdvisorforLenovo"
        "Mobigame.ZombieTsunami"
        "MobileFileExplorer*"
        "MobilesRepublic.NewsRepublic"
        "MobirateLtd.ParkingMania"
        "MusicMakerJam*"
        "NAMCOBANDAIGamesInc.PAC-MANChampionshipEditionDXfo*"
        "NAVER.LINEwin8*"
        "NBCUniversalMediaLLC.NBCSportsLiveExtra*"
        "NORDCURRENT.COOKINGFEVER"
        "NevosoftLLC.MushroomAge"
        "NextGenerationGames.WildDinosaurSniperHuntingHuntt"
        "NextIssue.NextIssueMagazine"
        "Nordcurrent.CookingFever"
        "OCS.OCS"
        "Ookla.SpeedtestbyOokla"
        "OrangeFrance.MaLivebox"
        "OrangeFrance.MailOrange"
        "OrangeFrance.TVdOrange"
        "PLRWorldwideSales.Gardenscapes-NewAcres"
        "PORTOEDITORA.EVe-Manuais"
        "PandoraMediaInc.29680B314EFC2"
        "PhotoAndVideoLabsLLC.MakeaPoster-ContinuumMediaSer"
        "PinballFx2*"
        "Pinterest.PinItButton"
        "Playtika.CaesarsSlotsFreeCasino*"
        "Pleemploi.Pleemploi"
        "PortraitDisplays.DellCinemaColor"
        "Priceline"
        "PricelinePartnerNetwork.Booking.comBigsavingsonhot"
        "PricelinePartnerNetwork.Booking.comEMEABigsavingso"
        "PricelinePartnerNetwork.Booking.comUSABigsavingson"
        "PricelinePartnerNetwork.Priceline.comTheBestDealso"
        "PublicationsInternational.iCookbookSE*"
        "ROBLOXCorporation.ROBLOX"
        "RandomSaladGamesLLC.GinRummyProforHP*"
        "RandomSaladGamesLLC.HeartsforHP"
        "ReaderNotificationClient"
        "RealtekSemiconductorCorp.HPAudioControl"
        "RealtekSemiconductorCorp.RealtekAudioControl"
        "Relay.com.KiosqueRelay"
        "RivetNetworks.KillerControlCenter"
        "RivetNetworks.SmartByte"
        "RollingDonutApps.JewelStar"
        "RoomAdjustment"
        "RubenGerlach.Solitaire-Palace"
        "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService"
        "SAMSUNGELECTRONICSCO.LTD.PCGallery"
        "SAMSUNGELECTRONICSCO.LTD.PCMessage"
        "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner"
        "SAMSUNGELECTRONICSCO.LTD.SamsungPrinterExperience"
        "SAMSUNGELECTRONICSCO.LTD.Wi-FiTransfer"
        "SAMSUNGELECTRONICSCoLtd.SamsungFlux"
        "STMicroelectronicsMEMS.DellFreeFallDataProtection"
        "ScreenovateTechnologies.DellMobileConnect"
        "SegaNetworksInc.56538047DFC80"
        "ShazamEntertainmentLtd.Shazam*"
        "SilverCreekEntertainment.HardwoodHearts"
        "SkisoSoft.FireEngineSimulator"
        "SkisoSoft.TrashTruckSimulator"
        "SocialQuantumIreland.WildWestNewFrontier"
        "SolidRhino.SteelTactics"
        "SonicWALL.MobileConnect"
        "SpotifyAB.SpotifyMusic"
        "SprakelsoftUG.CrocsWorld"
        "SprakelsoftUG.FlapFlapFlap"
        "SymantecCorporation.5478111E43ACF"
        "SymantecCorporation.NortonSafeWeb"
        "SymantecCorporation.NortonStudio*"
        "SynapticsIncorporated.SynHPCommercialDApp"
        "SynapticsIncorporated.SynHPCommercialStykDApp"
        "SynapticsIncorporated.SynHPConsumerDApp"
        "TOSHIBATEC.ToshibaPrintExperience"
        "TeenGamesLLC.HelicopterSimulator3DFree-ContinuumRe"
        "TelegraphMediaGroupLtd.TheTelegraphforLenovo*"
        "TelltaleGames.MinecraftStoryMode-ATelltaleGamesSer"
        "TheNewYorkTimes.NYTCrossword*"
        "ThumbmunkeysLtd.PhototasticCollage"
        "ThumbmunkeysLtd.PhototasticCollage*"
        "ToshibaAmericaInformation.ToshibaCentral*"
        "TreeCardGames.HeartsFree"
        "TriPlayInc.MyMusicCloud-Toshiba"
        "TripAdvisorLLC.TripAdvisorHotelsFlightsRestaurants*"
        "TuneIn.TuneInRadio*"
        "UniversalMusicMobile.HPLOUNGE"
        "UptoElevenDigitalSolution.mysms-Textanywhere*"
        "VectorUnit.BeachBuggyRacing"
        "Vimeo.Vimeo*"
        "WavesAudio.MaxxAudioProforDell2019"
        "WavesAudio.MaxxAudioProforDell2020"
        "WavesAudio.WavesMaxxAudioProforDell"
        "Weather.TheWeatherChannelforHP*"
        "Weather.TheWeatherChannelforLenovo*"
        "WeatherBug.a.WeatherBug"
        "WhatsNew"
        "WildTangentGames*"
        "WildTangentGames.-GamesApp-"
        "WildTangentGames.63435CFB65F55"
        "WinZipComputing.WinZipUniversal*"
        "XINGAG.XING"
        "XLabzTechnologies.22450B0065C6A"
        "XeroxCorp.PrintExperience"
        "YahooInc.54977BD360724"
        "YouSendIt.HighTailForLenovo*"
        "ZapposIPInc.Zappos.com"
        "ZeptoLabUKLimited.CutTheRope"
        "ZhuhaiKingsoftOfficeSoftw.WPSOffice"
        "ZhuhaiKingsoftOfficeSoftw.WPSOffice2019"
        "ZhuhaiKingsoftOfficeSoftw.WPSOfficeforFree"
        "ZinioLLC.Zinio*"
        "Zolmo.JamiesRecipes"
        "avonmobility.EnglishClub"
        "eBayInc.eBay*"
        "esobiIncorporated.newsXpressoMetro*"
        "fingertappsASUS.FingertappsInstrumentsrecommendedb*"
        "fingertappsASUS.JigsWarrecommendedbyASUS*"
        "fingertappsasus.FingertappsOrganizerrecommendedbyA*"
        "flaregamesGmbH.RoyalRevolt2*"
        "king.com*"
        "king.com.BubbleWitch3Saga"
        "king.com.CandyCrushFriends"
        "king.com.CandyCrushJellySaga"
        "king.com.CandyCrushSaga"
        "king.com.CandyCrushSodaSaga"
        "king.com.FarmHeroesSaga"
        "king.com.ParadiseBay"
        "n-tvNachrichtenfernsehenG.n-tvNachrichten"
        "rara.com.rara.com"
        "sMedioforHP.sMedio360*"
        "sMedioforToshiba.TOSHIBAMediaPlayerbysMedioTrueLin*"
        "www.cyberlink.com.AudioDirectorforLGE"
        "www.cyberlink.com.ColorDirectorforLGE"
        "www.cyberlink.com.PhotoDirectorforLGE"
        "www.cyberlink.com.PowerDirectorforLGE"
        "www.cyberlink.com.PowerMediaPlayerforLGE"
        "zuukaInc.iStoryTimeLibrary*"
    )
    foreach ($App in $Apps) {
        Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        Write-Host "Trying to remove $App."
    }
}

# Uninstall Windows Store for Current User
Function UninstallWindowsStore {
	Write-Output "Uninstalling Windows Store for current user..."
	Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Services.Store.Engagement" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.StorePurchaseApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
}

# Install Windows Store
Function InstallWindowsStore {
	Write-Output "Installing Windows Store..."
	Get-AppxPackage -AllUsers "Microsoft.DesktopAppInstaller" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Services.Store.Engagement" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.StorePurchaseApp" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsStore" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}

# Disable Xbox for current user - Not applicable to Server
Function DisableXboxFeatures {
	Write-Output "Disabling Xbox features for current user..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\System\" -Name "GameConfigStore" -Force
    Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name "GameDVR" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\" -Name "GameDVR" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
}

# Enable Xbox features - Not applicable to Server
Function EnableXboxFeatures {
	Write-Output "Enabling Xbox features..."
	Get-AppxPackage -AllUsers "Microsoft.XboxApp" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGamingOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name HistoricalCaptureEnabled -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name HistoricalCaptureEnabled -Type "DWORD" -Value 1 -Force
}

Function CleanupRegistry {
	$ErrorActionPreference = 'SilentlyContinue'
	Write-Host " "
	Write-Host "Cleaning up registry..."
    	$Keys = @(
		
		New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
               
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
        
    #This writes the output of each key it is removing and also removes the keys listed above.
    ForEach ($Key in $Keys) {
		Remove-Item $Key -Recurse
	}
	Write-Host "Done."
}

# Remove Meet Now icon
# Microsoft added the Meet Now icon to the Windows 10 taskbar. Microsoft added the button to make it easier for users of its operating system to create meetings or to join meetings.
# You can now easily set up a video call and reach friends and family in an instant by clicking on the Meet Now icon in the notification area (system tray) of the taskbar in Windows 10. No sign ups or downloads needed.
# Note: The new Meet Now icon is not added on Windows 10 Enterprise systems or Azure Active Directory accounts.
Function DisableMeetNow {
	Write-Output "Removing Meet Now icon for current user..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
	Write-Output "Removing Meet Now icon for all users..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
}

# Enable Meet Now icon
Function EnableMeetNow {
	Write-Output "Removing Meet Now icon for current user..."
	Remove-ItemProperty -Path "HKCU:\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Force -ErrorAction SilentlyContinue
	Write-Output "Removing Meet Now icon for all users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Force -ErrorAction SilentlyContinue
}

# Disable Fullscreen optimizations
Function DisableFullscreenOptims {
	Write-Output "Disabling Fullscreen optimizations..."
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1
}

# Enable Fullscreen optimizations
Function EnableFullscreenOptims {
	Write-Output "Enabling Fullscreen optimizations..."
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 0
	Remove-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 0
}

# Disable built-in Adobe Flash in IE and Edge
Function DisableAdobeFlash {
	Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
}

# Enable built-in Adobe Flash in IE and Edge
Function EnableAdobeFlash {
	Write-Output "Enabling built-in Adobe Flash in IE and Edge..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -ErrorAction SilentlyContinue
}

# Disable Edge preload after Windows startup - Applicable since Win10 1809
Function DisableEdgePreload {
	Write-Output "Disabling Edge preload..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type DWord -Value 0
}

# Enable Edge preload after Windows startup
Function EnableEdgePreload {
	Write-Output "Enabling Edge preload..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -ErrorAction SilentlyContinue
}

# Disable Edge desktop shortcut creation after certain Windows updates are applied
Function DisableEdgeShortcutCreation {
	Write-Output "Disabling Edge shortcut creation..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWord -Value 1
}

# Enable Edge desktop shortcut creation after certain Windows updates are applied
Function EnableEdgeShortcutCreation {
	Write-Output "Enabling Edge shortcut creation..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -ErrorAction SilentlyContinue
}

# Disable Internet Explorer first run wizard
Function DisableIEFirstRun {
	Write-Output "Disabling Internet Explorer first run wizard..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1
}

# Enable Internet Explorer first run wizard
Function EnableIEFirstRun {
	Write-Output "Disabling Internet Explorer first run wizard..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -ErrorAction SilentlyContinue
}

# Disable "Hi!" First Logon Animation (it will be replaced by "Preparing Windows" message)
Function DisableFirstLogonAnimation {
	Write-Output "Disabling First Logon Animation..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Type DWord -Value 0
}

# Enable "Hi!" First Logon Animation
Function EnableFirstLogonAnimation {
	Write-Output "Enabling First Logon Animation..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -ErrorAction SilentlyContinue
}

# Disable Windows Media Player's media sharing feature
Function DisableMediaSharing {
	Write-Output "Disabling Windows Media Player media sharing..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -Type DWord -Value 1
}

# Enable Windows Media Player's media sharing feature
Function EnableMediaSharing {
	Write-Output "Enabling Windows Media Player media sharing..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -ErrorAction SilentlyContinue
}

# Disable Windows Media Player online access - audio file metadata download, radio presets, DRM.
Function DisableMediaOnlineAccess {
	Write-Output "Disabling Windows Media Player online access..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 1
}

# Enable Windows Media Player online access
Function EnableMediaOnlineAccess {
	Write-Output "Enabling Windows Media Player online access..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -ErrorAction SilentlyContinue
}

# Uninstall Windows Media Player
Function UninstallMediaPlayer {
	Write-Output "Uninstalling Windows Media Player..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install Windows Media Player
Function InstallMediaPlayer {
	Write-Output "Installing Windows Media Player..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Add-WindowsCapability -Online | Out-Null
}

# Uninstall Internet Explorer
Function UninstallInternetExplorer {
	Write-Output "Uninstalling Internet Explorer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer-Optional*" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install Internet Explorer
Function InstallInternetExplorer {
	Write-Output "Installing Internet Explorer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer-Optional*" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Add-WindowsCapability -Online | Out-Null
}

# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
	Write-Output "Uninstalling Work Folders Client..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Work Folders Client - Not applicable to Server
Function InstallWorkFolders {
	Write-Output "Installing Work Folders Client..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall PowerShell 2.0 Environment
# PowerShell 2.0 is deprecated since September 2018. This doesn't affect PowerShell 5 or newer which is the default PowerShell environment.
# May affect Microsoft Diagnostic Tool and possibly other scripts. See https://blogs.msdn.microsoft.com/powershell/2017/08/24/windows-powershell-2-0-deprecation/
Function UninstallPowerShellV2 {
	Write-Output "Uninstalling PowerShell 2.0 Environment..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "MicrosoftWindowsPowerShellV2Root" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Uninstall-WindowsFeature -Name "PowerShell-V2" -WarningAction SilentlyContinue | Out-Null
	}
}

# Install PowerShell 2.0 Environment
Function InstallPowerShellV2 {
	Write-Output "Installing PowerShell 2.0 Environment..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "MicrosoftWindowsPowerShellV2Root" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Install-WindowsFeature -Name "PowerShell-V2" -WarningAction SilentlyContinue | Out-Null
	}
}

# Install Linux Subsystem - Applicable since Win10 1607 and Server 1709
# Note: 1607 requires also EnableDevelopmentMode for WSL to work
# For automated Linux distribution installation, see https://docs.microsoft.com/en-us/windows/wsl/install-on-server
Function InstallLinuxSubsystem {
	Write-Output "Installing Linux Subsystem..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Windows-Subsystem-Linux" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Linux Subsystem - Applicable since Win10 1607 and Server 1709
Function UninstallLinuxSubsystem {
	Write-Output "Uninstalling Linux Subsystem..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Windows-Subsystem-Linux" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install .NET Framework 2.0, 3.0 and 3.5 runtimes - Requires internet connection
Function InstallNET23 {
	Write-Output "Installing .NET Framework 2.0, 3.0 and 3.5 runtimes..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "NetFx3" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Install-WindowsFeature -Name "NET-Framework-Core" -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall .NET Framework 2.0, 3.0 and 3.5 runtimes
Function UninstallNET23 {
	Write-Output "Uninstalling .NET Framework 2.0, 3.0 and 3.5 runtimes..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "NetFx3" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Uninstall-WindowsFeature -Name "NET-Framework-Core" -WarningAction SilentlyContinue | Out-Null
	}
}

# Set Photo Viewer association for bmp, gif, jpg, png and tif
Function SetPhotoViewerAssociation {
	Write-Output "Setting Photo Viewer association for bmp, gif, jpg, png and tif..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
		New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
		New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
		Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
		Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	}
}

# Unset Photo Viewer association for bmp, gif, jpg, png and tif
Function UnsetPhotoViewerAssociation {
	Write-Output "Unsetting Photo Viewer association for bmp, gif, jpg, png and tif..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
	Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
	Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
	Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse -ErrorAction SilentlyContinue
}

# Add Photo Viewer to 'Open with...'
Function AddPhotoViewerOpenWith {
	Write-Output "Adding Photo Viewer to 'Open with...'"
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
}

# Remove Photo Viewer from 'Open with...'
Function RemovePhotoViewerOpenWith {
	Write-Output "Removing Photo Viewer from 'Open with...'"
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse -ErrorAction SilentlyContinue
}

# Uninstall Microsoft Print to PDF
Function UninstallPDFPrinter {
	Write-Output "Uninstalling Microsoft Print to PDF..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-PrintToPDFServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft Print to PDF
Function InstallPDFPrinter {
	Write-Output "Installing Microsoft Print to PDF..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-PrintToPDFServices-Features" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Microsoft XPS Document Writer
Function UninstallXPSPrinter {
	Write-Output "Uninstalling Microsoft XPS Document Writer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-XPSServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft XPS Document Writer
Function InstallXPSPrinter {
	Write-Output "Installing Microsoft XPS Document Writer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-XPSServices-Features" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Remove Default Fax Printer
Function RemoveFaxPrinter {
	Write-Output "Removing Default Fax Printer..."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}

# Add Default Fax Printer
Function AddFaxPrinter {
	Write-Output "Adding Default Fax Printer..."
	Add-Printer -Name "Fax" -DriverName "Microsoft Shared Fax Driver" -PortName "SHRFAX:" -ErrorAction SilentlyContinue
}

# Uninstall Windows Fax and Scan Services - Not applicable to Server
Function UninstallFaxAndScan {
	Write-Output "Uninstalling Windows Fax and Scan Services..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install Windows Fax and Scan Services - Not applicable to Server
Function InstallFaxAndScan {
	Write-Output "Installing Windows Fax and Scan Services..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Add-WindowsCapability -Online | Out-Null
}

##########
#endregion Application Tweaks
##########



##########
#region Maintenance Tasks
##########

Function ImageCleanup {
	Write-Host "Clean up unused files and Windows updates..."
	Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
	    Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore
	}

	$VolumeCaches = @(
	    # Active Setup Temp Folders
	    "Active Setup Temp Folders",

	    # BranchCache
	    "BranchCache",

	    # Content Indexer Cleaner
	    "Content Indexer Cleaner",

	    # D3D Shader Cache
	    "D3D Shader Cache",

	    # Delivery Optimization Files
	    "Delivery Optimization Files",

	    # Device Driver Packages
	    "Device Driver Packages",

	    # Diagnostic Data Viewer database files
	    "Diagnostic Data Viewer database files"

	    # Downloaded Program Files
	    "Downloaded Program Files"

	    # GameNewsFiles
	    "GameNewsFiles"

	    # GameStatisticsFiles
	    "GameStatisticsFiles"

	    # GameUpdateFiles
	    "GameUpdateFiles"

	    # Internet Cache Files
	    "Internet Cache Files"

	    # Language Pack
	    "Language Pack"

	    # Offline Pages Files
	    "Offline Pages Files"

	    # Diagnostic Data Viewer database files
	    "Diagnostic Data Viewer database files"

	    # Old ChkDsk Files
	    "Old ChkDsk Files"

	    # Previous Windows Installation(s)
	    "Previous Installations",

	    # Recycle Bin
	    "Recycle Bin"

	    # RetailDemo Offline Content
	    "RetailDemo Offline Content"

	    # Service Pack Cleanup
	    "Service Pack Cleanup"

	    # Setup log files
	    "Setup Log Files",

	    # System error memory dump files
	    "System error memory dump files"

	    # System error minidump files
	    "System error minidump files"

	    # Temporary Files
	    "Temporary Files"

	    # Temporary Setup Files
	    "Temporary Setup Files",

	    # Temporary Sync Files
	    "Temporary Sync Files"

	    # Thumbnail Cache
	    "Thumbnail Cache"

	    # Update Cleanup
	    "Update Cleanup"

	    # Upgrade Discarded Files
	    "Upgrade Discarded Files"

	    # User file versions
	    "User file versions"

	    # Microsoft Defender
	    "Windows Defender",

	    # Windows Error Reporting Files
	    "Windows Error Reporting Files"

	    # Windows ESD installation files
	    "Windows ESD installation files"

	    # Windows Upgrade Log Files
	    "Windows Upgrade Log Files"
	)

	foreach ($VolumeCache in $VolumeCaches)
	{
	    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$VolumeCache" -Name StateFlags65535 -PropertyType DWord -Value 2 -Force
	}
	#Delete "windows.old" folder
	#Cmd.exe /c Cleanmgr /sageset:65535
	Cmd.exe /c Cleanmgr /sagerun:65535
	# Create task to clean up unused files and Windows updates 
	Write-Host "Creating task to clean up unused files and Windows updates in task scheduler..."
	schtasks /Create /SC WEEKLY /D THU  /ST 11:00 /TN "Pegasus Script\Windows Cleanup" /TR "%windir%\system32\cleanmgr.exe /sagerun:65535"
	Write-Verbose "Removing .tmp, .etl, .evtx, thumbcache*.db, *.log files not in use"
	Get-ChildItem -Path c:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
	#Delete "RetailDemo" content (if it exits)
	Write-Verbose "Removing Retail Demo content (if it exists)"
	Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo\* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -ErrorAction SilentlyContinue
	#Delete not in-use anything in the C:\Windows\Temp folder
	Write-Verbose "Removing all files not in use in $env:windir\TEMP"
	Remove-Item -Path $env:windir\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
	#Clear out Windows Error Reporting (WER) report archive folders
	Write-Verbose "Cleaning up WER report archive"
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue
	#Delete not in-use anything in your $env:TEMP folder
	Write-Verbose "Removing files not in use in $env:TEMP directory"
	Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
	#Clear out ALL visible Recycle Bins
	Write-Verbose "Clearing out ALL Recycle Bins"
	Clear-RecycleBin -Force -ErrorAction SilentlyContinue
	#Clear out BranchCache cache
	Write-Verbose "Clearing BranchCache cache"
	Clear-BCCache -Force -ErrorAction SilentlyContinue
	#Clear volume backups (shadow copies)
	vssadmin delete shadows /all /quiet
	#Empty trash bin
	Powershell -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10);$bin.items() | ForEach { Write-Host "Deleting $($_.Name) from Recycle Bin"; Remove-Item $_.Path -Recurse -Force}"
	#Delete controversial default0 user
	net user defaultuser0 /delete 2>nul
	#Clear thumbnail cache
	Remove-Item /f /s /q /a $env:LocalAppData\Microsoft\Windows\Explorer\*.db
	#Clear Windows temp files
	Remove-Item /f /q $env:localappdata\Temp\*
	Remove-Item /s /q "$env:WINDIR\Temp"
	Remove-Item /s /q "$env:TEMP"
	#Clear main telemetry file
	takeown /f "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r -Value y
	icacls "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
	Write-Output"" > "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
	Write-Output Clear successful: "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
	#Clear Distributed Transaction Coordinator logs
	Remove-Item /f /q $env:SystemRoot\DtcInstall.log
	#Clear Optional Component Manager and COM+ components logs
	Remove-Item /f /q $env:SystemRoot\comsetup.log
	#Clear Pending File Rename Operations logs
	Remove-Item /f /q $env:SystemRoot\PFRO.log
	#Clear Windows Deployment Upgrade Process Logs
	Remove-Item /f /q $env:SystemRoot\setupact.log
	Remove-Item /f /q $env:SystemRoot\setuperr.log
	#Clear Windows Setup Logs
	Remove-Item /f /q $env:SystemRoot\setupapi.log
	Remove-Item /f /q $env:SystemRoot\Panther\*
	Remove-Item /f /q $env:SystemRoot\inf\setupapi.app.log
	Remove-Item /f /q $env:SystemRoot\inf\setupapi.dev.log
	Remove-Item /f /q $env:SystemRoot\inf\setupapi.offline.log
	#Clear Windows System Assessment Tool logs
	Remove-Item /f /q $env:SystemRoot\Performance\WinSAT\winsat.log
	#Clear Password change events
	Remove-Item /f /q $env:SystemRoot\debug\PASSWD.LOG
	#Clear user web cache database
	Remove-Item /f /q $env:LocalAppData\Microsoft\Windows\WebCache\*.*
	#Clear system temp folder when noone is logged in
	Remove-Item /f /q $env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Temp\*.*
	#Clear DISM (Deployment Image Servicing and Management) Logs
	Remove-Item /f /q  $env:SystemRoot\Logs\CBS\CBS.log
	Remove-Item /f /q  $env:SystemRoot\Logs\DISM\DISM.log
	#Clear Server-initiated Healing Events Logs
	Remove-Item /f /q "$env:SystemRoot\Logs\SIH\*"
	#Common Language Runtime Logs
	Remove-Item /f /q "$env:LocalAppData\Microsoft\CLR_v4.0\UsageTraces\*"
	Remove-Item /f /q "$env:LocalAppData\Microsoft\CLR_v4.0_32\UsageTraces\*"
	#Network Setup Service Events Logs
	Remove-Item /f /q "$env:SystemRoot\Logs\NetSetup\*"
	#Disk Cleanup tool (Cleanmgr.exe) Logs
	Remove-Item /f /q "$env:SystemRoot\System32\LogFiles\setupcln\*"
	#Clear Windows update and SFC scan logs
	Remove-Item /f /q $env:SystemRoot\Temp\CBS\*
	#Clear Windows Update Medic Service logs
	takeown /f $env:SystemRoot\Logs\waasmedic /r -Value y
	icacls $env:SystemRoot\Logs\waasmedic /grant administrators:F /t
	Remove-Item /s /q $env:SystemRoot\Logs\waasmedic
	#Clear Cryptographic Services Traces
	Remove-Item /f /q $env:SystemRoot\System32\catroot2\dberr.txt
	Remove-Item /f /q $env:SystemRoot\System32\catroot2.log
	Remove-Item /f /q $env:SystemRoot\System32\catroot2.jrs
	Remove-Item /f /q $env:SystemRoot\System32\catroot2.edb
	Remove-Item /f /q $env:SystemRoot\System32\catroot2.chk
	#Windows Update Events Logs
	Remove-Item /f /q "$env:SystemRoot\Logs\SIH\*"
	#Windows Update Logs
	Remove-Item /f /q "$env:SystemRoot\Traces\WindowsUpdate\*"
	#Clear Internet Explorer traces
	Remove-Item /f /q "$env:LocalAppData\Microsoft\Windows\INetCache\IE\*"
	reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" /va /f
	reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLsTime" /va /f
	Remove-Item /s /q "$env:LocalAppData\Microsoft\Internet Explorer"
	Remove-Item /s /q "$env:APPDATA\Microsoft\Windows\Cookies"
	Remove-Item /s /q "$env:USERPROFILE\Cookies"
	Remove-Item /s /q "$env:USERPROFILE\Local Settings\Traces"
	Remove-Item /s /q "$env:LocalAppData\Temporary Internet Files"
	Remove-Item /s /q "$env:LocalAppData\Microsoft\Windows\Temporary Internet Files"
	Remove-Item /s /q "$env:LocalAppData\Microsoft\Windows\INetCookies\PrivacIE"
	Remove-Item /s /q "$env:LocalAppData\Microsoft\Feeds Cache"
	Remove-Item /s /q "$env:LocalAppData\Microsoft\InternetExplorer\DOMStore"
	#Clear Google Chrome traces
	Remove-Item /f /q "$env:LocalAppData\Google\Software Reporter Tool\*.log"
	Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Google\Chrome\User Data"
	Remove-Item /s /q "$env:LocalAppData\Google\Chrome\User Data"
	Remove-Item /s /q "$env:LocalAppData\Google\CrashReports\""
	Remove-Item /s /q "$env:LocalAppData\Google\Chrome\User Data\Crashpad\reports\""
	#Clear Opera traces
	Remove-Item /s /q "$env:USERPROFILE\AppData\Local\Opera\Opera"
	Remove-Item /s /q "$env:APPDATA\Opera\Opera"
	Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Opera\Opera"
	#Clear Safari traces
	Remove-Item /s /q "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Traces"
	Remove-Item /s /q "$env:APPDATA\Apple Computer\Safari"
	Remove-Item /q /s /f "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Cache.db"
	Remove-Item /q /s /f "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\WebpageIcons.db"
	Remove-Item /s /q "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Traces"
	Remove-Item /q /s /f "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Cache.db"
	Remove-Item /q /s /f "$env:USERPROFILE\Local Settings\Application Data\Safari\WebpageIcons.db"
	#Clear Listary indexes
	Remove-Item /f /s /q $env:APPDATA\Listary\UserData > nul
	#Clear Java cache
	Remove-Item /s /q "$env:APPDATA\Sun\Java\Deployment\cache"
	#Clear Flash traces
	Remove-Item /s /q "$env:APPDATA\Macromedia\Flash Player"
	#Clear Steam dumps, logs and traces
	Remove-Item /f /q %ProgramFiles(x86)%\Steam\Dumps
	Remove-Item /f /q %ProgramFiles(x86)%\Steam\Traces
	Remove-Item /f /q %ProgramFiles(x86)%\Steam\appcache\*.log
	#Clear Visual Studio telemetry and feedback data
	Remove-Item /s /q "$env:APPDATA\vstelemetry" 2>nul
	Remove-Item /s /q "$env:LocalAppData\Microsoft\VSApplicationInsights" 2>nul
	Remove-Item /s /q "$env:ProgramData\Microsoft\VSApplicationInsights" 2>nul
	Remove-Item /s /q "$env:TEMP\Microsoft\VSApplicationInsights" 2>nul
	Remove-Item /s /q "$env:TEMP\VSFaultInfo" 2>nul
	Remove-Item /s /q "$env:TEMP\VSFeedbackPerfWatsonData" 2>nul
	Remove-Item /s /q "$env:TEMP\VSFeedbackVSRTCLogs" 2>nul
	Remove-Item /s /q "$env:TEMP\VSRemoteControl" 2>nul
	Remove-Item /s /q "$env:TEMP\VSTelem" 2>nul
	Remove-Item /s /q "$env:TEMP\VSTelem.Out" 2>nul
	#Clear Dotnet CLI telemetry
	Remove-Item /s /q "$env:USERPROFILE\.dotnet\TelemetryStorageService" 2>nul
	#Clear regedit last key
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
	#Clear regedit favorites
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
	#Clear list of recent programs opened
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
	#Clear Adobe Media Browser MRU
	reg delete "HKCU\Software\Adobe\MediaBrowser\MRU" /va /f
	#Clear MSPaint MRU
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
	#Clear Wordpad MRU
	reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List" /va /f
	#Clear Map Network Drive MRU MRU
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
	#Clear Windows Search Assistant history
	reg delete "HKCU\Software\Microsoft\Search Assistant\ACMru" /va /f
	#Clear list of Recent Files Opened, by Filetype
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
	reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" /va /f
	#Clear windows media player recent files and urls
	reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
	reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
	reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
	reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
	#Clear Most Recent Application's Use of DirectX
	reg delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
	reg delete "HKLM\SOFTWARE\Microsoft\Direct3D\MostRecentApplication" /va /f
	#Clear Windows Run MRU & typedpaths
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
	reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /va /f
	#Clear recently accessed files
	Remove-Item /f /q "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*"
	#Clear user pins
	Remove-Item /f /q "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"
	#Clear regedit last key
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
}

##########
#endregion Maintenance Tasks
##########



##########
#region Server specific Tweaks
##########

# Hide Server Manager after login
Function HideServerManagerOnLogin {
	Write-Output "Hiding Server Manager after login..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -Type DWord -Value 1
}

# Show Server Manager after login
Function ShowServerManagerOnLogin {
	Write-Output "Showing Server Manager after login..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -ErrorAction SilentlyContinue
}

# Disable Shutdown Event Tracker
Function DisableShutdownTracker {
	Write-Output "Disabling Shutdown Event Tracker..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0
}

# Enable Shutdown Event Tracker
Function EnableShutdownTracker {
	Write-Output "Enabling Shutdown Event Tracker..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -ErrorAction SilentlyContinue
}

# Disable password complexity and maximum age requirements
Function DisablePasswordPolicy {
	Write-Output "Disabling password complexity and maximum age requirements..."
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	(Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile
}

# Enable password complexity and maximum age requirements
Function EnablePasswordPolicy {
	Write-Output "Enabling password complexity and maximum age requirements..."
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	(Get-Content $tmpfile).Replace("PasswordComplexity = 0", "PasswordComplexity = 1").Replace("MaximumPasswordAge = -1", "MaximumPasswordAge = 42") | Out-File $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile
}

# Disable Ctrl+Alt+Del requirement before login
Function DisableCtrlAltDelLogin {
	Write-Output "Disabling Ctrl+Alt+Del requirement before login..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 1
}

# Enable Ctrl+Alt+Del requirement before login
Function EnableCtrlAltDelLogin {
	Write-Output "Enabling Ctrl+Alt+Del requirement before login..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 0
}

# Disable Internet Explorer Enhanced Security Configuration (IE ESC)
Function DisableIEEnhancedSecurity {
	Write-Output "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
}

# Enable Internet Explorer Enhanced Security Configuration (IE ESC)
Function EnableIEEnhancedSecurity {
	Write-Output "Enabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
}

# Enable Audio
Function EnableAudio {
	Write-Output "Enabling Audio..."
	Set-Service "Audiosrv" -StartupType Automatic
	Start-Service "Audiosrv" -WarningAction SilentlyContinue
}

# Disable Audio
Function DisableAudio {
	Write-Output "Disabling Audio..."
	Stop-Service "Audiosrv" -WarningAction SilentlyContinue
	Set-Service "Audiosrv" -StartupType Manual
}

##########
#endregion Server specific Tweaks
##########



##########
#region Unpinning
##########

# Unpin all Start Menu tiles
# Note: This function has no counterpart. You have to pin the tiles back manually.
Function UnpinStartMenuTiles {
	Write-Output "Unpinning all Start Menu tiles..."
	If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
			$data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
			$data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
			Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")
		}
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
		$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
}

# Unpin all Taskbar icons
# Note: This function has no counterpart. You have to pin the icons back manually.
Function UnpinTaskbarIcons {
	Write-Output "Unpinning all Taskbar icons..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}

##########
#endregion Unpinning
##########



##########
#region Auxiliary Functions
##########

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

Function CreateRestorePoint {
  Write-Output "Creating Restore Point incase something bad happens"
  Enable-ComputerRestore -Drive "C:\"
  Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"
}

##########
#endregion Auxiliary Functions
##########



##########
# Parse parameters and apply tweaks
##########

# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}

# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }
