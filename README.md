# Pegasus-Script
This is the Pegasus Script from a creation from multiple debloat scripts and gists from github. It's a powershell script for automation of routine tasks done after fresh installations of Windows 10 and Windows Server 2016 / 2019. Also is settings which I like to use and which in my opinion make the system lightest possible.

# Supported Windows 10 Versions

| Version |        Code name        |     Marketing name     | Build | Arch |      Editions     | Script version |
| :-----: | ----------------------- | ---------------------- | :---: |:----:|:-----------------:|:--------------:|
|  1507   | Threshold 1 (TH1 / RTM) | N/A                    | 10240 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1511   | Threshold 2 (TH2)       | November Update        | 10586 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1607   | Redstone 1 (RS1)        | Anniversary Update     | 14393 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1607   | Redstone 1 (RS1)        | Windows Server 2016    | 14393 |  x64 |Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1703   | Redstone 2 (RS2)        | Creators Update        | 15063 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1709   | Redstone 3 (RS3)        | Fall Creators Update   | 16299 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1803   | Redstone 4 (RS4)        | April 2018 Update      | 17134 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1809   | Redstone 5 (RS5)        | October 2018 Update    | 17763 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1809   | Redstone 5 (RS5)        | Windows Server 2019    | 17763 |  x64 |Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1903   | 19H1                    | May 2019 Update        | 18362 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  1909   | 19H2                    | November 2019 Update   | 18363 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  2004   | 20H1                    | May 2020 Update        | 19041 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|
|  2009   | 20H2                    | October 2020 Update    | 19042 |  x64 |Home/Pro/Enterprise|[0.1](https://github.com/dennyamarojr/Pegasus-Script/releases/latest)|

## FAQ

**Q:** Can I run the script safely?  
**A:** Definitely not. You have to understand what the functions do and what will be the implications for you if you run them. Some functions lower security, hide controls or uninstall applications. **If you're not sure what the script does, do not attempt to run it!**

**Q:** Can I run the script repeatedly?  
**A:** Yes! In fact the script has been written to support exactly that, as it's not uncommon that big Windows Updates reset some of the settings.

**Q:** Which versions and editions of Windows are supported?  
**A:** The script aims to be fully compatible with the most up-to-date 64bit version of Windows 10 receiving updates from semi-annual channel, however if you create your own preset and exclude the incompatible tweaks, it will work also on LTSB/LTSC and possibly also on 32bit systems. Vast majority of the tweaks will work on all Windows editions. Some of them rely on group policy settings, so there may be a few limitations for Home and Education editions.

**Q:** Can I run the script on Windows Server 2016 or 2019?  
**A:** Yes. Windows Server is supported. There are even few tweaks specific to Server environment. Keep in mind though, that the script is still primarily designed for Windows 10, so you have to create your own preset.

**Q:** Can I run the script on Windows 7, 8, 8.1 or other versions of Windows?  
**A:** No. Although some tweaks may work also on older versions of Windows, the script is developed only for Windows 10 and Windows Server 2016 / 2019. There are no plans to support older versions.

**Q:** Did you test the script?  
**A:** Yes. I'm testing new additions on up-to-date 64bit Home and Enterprise editions in VMs. I'm also regularly using it for all my home installations after all bigger updates.

**Q:** I've run the script and it did something I don't like, how can I undo it?  
**A:** For every tweak, there is also a corresponding function which restores the default settings. The default is considered freshly installed Windows 10 or Windows Server 2016 with no adjustments made during or after the installation. Use the tweaks to create and run new preset. Alternatively, since some functions are just automation for actions which can be done using GUI, find appropriate control and modify it manually.

**Q:** I've run the script and some controls are now greyed out and display message "*Some settings are hidden or managed by your organization*", why?  
**A:** To ensure that system-wide tweaks are applied smoothly and reliably, some of them make use of *Group Policy Objects* (*GPO*). The same mechanism is employed also in companies managing their computers in large scale, so the users without administrative privileges can't change the settings. If you wish to change a setting locked by GPO, apply the appropriate restore tweak and the control will become available again.
