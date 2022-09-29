# Registry Explorer


#### System Information

###### OS Version

We can determine the OS version from which this data was pulled through the registry by looking at the `SOFTWARE\Microsoft\Windows NT\CurrentVersion` key:

![[regripper_os_version.png]]

###### Current Control Set

As part of the system configuration, there are two keys `ControlSet1` and `ControlSet2` within the `SYSTEM` hive.  This plays a huge part in analysis as we need to know which control set was in use at the time of the incident.  We can determine this through the `SYSTEM\Select\` key with the `LastKnownGood` value:

![[lastknowngood_value.png]]

The above indicates that `ControlSet002` was last used on the system.

It is vital to establish this as many forensic artifacts will be collected from control sets.

###### Computer Name

It is crucial to establish the computer name when performing forensics to ensure thatw e are working on the correct machine. We can view the computer name from `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`:

![[registry_explorer_computer_name.png]]

###### Time Zone Information

Similarly, we also want to establish what timezone the computer is located in.  This will help us understand the chronology of events as they happened.  To find the timezone information, we can look within the `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` key:

![[registry_explorer_timezone.png]]

Establishing a timezone is essential as some data on the system will have thieir timestamps in UTC/GMT format and others in the local timezone.  As mentioned above, knowing the local timezone helps establish a tiemline when merging data from other sources.

###### Network Interfaces and Past Networks

We can also get a list of network interfaces on the machine by viewing the `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` key:

![[registry_explorer_network_interfaces.png]]

Each interface is represented through a unique identified (GUID) which contains values relating to the interface's TCP/IP configuration.  As such, this key provides the IP addresses, DHCP IP address, subnet mask, DNS servers, and much more, which can help us establish which machine we are performing forensics on.

The past networks which the machine was connected to can also be viewed through `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` or `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed`:

![[registry_explorer_past_networks.png]]

These keys contain past networks as well as the last time they were connected - last write time.

###### Autostart Programs (Autoruns)

The following registry keys include information about programs or commands that run when a user logs on:

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

![[registry_explorer_autoruns.png]]

Similarly, the `SYSTEM\CurrentControlSet\Services` key stores information about the services on the system:

![[registry_explorer_services.png]]

Note, from the above, if the `start` key is set to `0x02`, then the service will start **at boot**.

###### SAM Hive and User Information

The SAM hive contains user account information, login information, and group information and is mainly located in the `SAM\Domains\Accounts\Users` key:

![[registry_explorer_sam_hive.png]]

The information here includes the **r**elative **id**entifier (**RID**) of the user, the number of times the user logged in, last login time, last failed login, last password change, password expiry, password policy and password hint, and any groups that the user is part of.

#### Files and Folders

###### Recent Files

Windows maintains a list of recently opened files for each user.  This information is stored in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`:

![[registry_explorer_recent_files.png]]

Registry Explorer allows you to sort the data contained within the registry keys based on given properties.  For example, in `RecentDocs`, the Most Recently Used (MRU) file is at the top of the list.

We can also look for specific file types.  For example, if we want to look for last used PDF files, we would go to `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs.pdf`

###### Office Recent Files

Similarly, Microsoft Office also maintains a list of recently opened documents.  This list is located within `NTUSER.DAT\Software\Microsoft\Office\<VERSION>`.

The version number for each product release is different.  For example: `NTUSER.DAT\Software\Microsoft\Office\15.0\Word` refers to Office 2013 - refer to [this list](https://docs.microsoft.com/en-us/deployoffice/install-different-office-visio-and-project-versions-on-the-same-computer#office-releases-and-their-version-number) for other version numers. 

With Office 365, Microsoft also ties the location to the user's [live ID](https://www.microsoft.com/security/blog/2008/05/07/what-is-a-windows-live-id/).  In this case, recent files can be found at `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\LiveID_<ID>\FileMRU`

###### ShellBags

When a user opens a folder, it opens in a specific layout which can be changed according to the user's preference.  This information about the Windows "*shell*" is stored and can help identify most recently used files and folders.  Since this setting is unique for each user, it is located within the user hives:

- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`
- `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`

Registry Explorer doesn't provide much information regarding ShellBags, but the [ShellBag Explorer](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FTools%2FShellBag%20Explorer) from EzTools can provide this information.  There is also a module within [RegRipper](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FTools%2FRegRipper) which can be used to analyse ShellBags.

###### Open/Save and LastVisited Dialog MRUs:

When a file is opened/saved, a dialog box appears asking us where to save/open that file from.  Once we open/save a file at a specific location, Windows makes a record of this.  This implies that we can find recently used files.  This information is stored in the following keys:

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`

![[registry_epxlorer_lastvisitedpidlmru.png]]

###### Windows Explorer Address/Search Bars

We can also identify a user's activity by looking at the paths typed into the Windows Explorer address bar or searches performed using the following registry keys:

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`

For example, `TypedPaths` is shown as follows:

![[registry_explorer_typedpaths.png]]

#### Evidence of Execution

###### UserAssist

Windows keeps track of applications which are launched through the Windows explorer in the `UserAssist` registry keys - mainly for statistical purposes.  These keys contain informatiom about the programs launched, at the time of their launch, and the number of times they were executed.

However, programs run through the command-line cannot be found in the `UserAssist` key.  The `UserAssist` key is mapped to each user's GUID and can be found at `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count`:

![[registry_explorer_userassist.png]]

###### ShimCache

ShimCache, or Application Compatibility Cache (AppCompatCache), keeps track of application compatibility with the OS and tracks all applications launched on the machine.  Its main purpose is to ensure backwards compatibility and is located in `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`.

ShimCache stores the file name, size, and last modified time of executables.  Unfortunately, Registry Explorer doesn't parse ShimCache data so [AppCompatCache Parser](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FTools%2FEzTools%2FAppCompatCache%20Parser) from EzTools must be used.

###### AmCache

The AmCache hive is an artifact related to ShimCache in that it stores additional data related to program executions.  This data includes execution path, installation, execution and deletion times, and SHA1 hashes of the executed programs.  This hive is located in the `C:\Windows\appcompat\Programs\Amcache.hve`.  Information about the last executed programs can be found at `Amcache.hve\Root\File\<VOLUME GUID>\`.

The AmCache hive can be parsed through Registry Explorer:

![[registry_explorer_amcache_hive.png]]

###### BAM/DAM

**B**ackground **A**ctivity **M**onitor (**BAM**) keeps track of the background applications and their activity.  Similarly, **D**esktop **A**ctivity **M**oderator (**DAM**) optimises the power consumption of the device.  Each are part of the modern standby system within Microsoft Windows.

In the Windows Registry, the following locations contain information related to BAM and DAM, including the last run programs, their full paths, and last execution time:

- `SYSTEM\CurrentControlSet\Services\bam\UserSettings\<SID>`
- `SYSTEM\CurrentControlSet\Services\bam\UserSettings\<SID>`

Again, this data can be parsed with Registry Explorer:

![[registry_explorer_bam_dam.png]]

#### External Devices/USB Device Forensics

When performing forensics, foten the need arises to identify if any USB or removable devices were attached to the machine.  If so, any information related to those devices is important for an investigation.

###### Device Identification

The following locations keep track of USB keys plugged into the system:

- `SYSTEM\CurrentControlSet\Enum\USBSTOR`
- `SYSTEM\CurrentControlSet\Enum\USB`

These locations store the vendor ID, product ID, and version of the USB device plugged in and can be used to identify unique devices, as well as the time that the devices were plugged into the system.

![[registry_explorer_usb_device_identification.png]]

###### First/Last Times

Similarly, the following registry key tracks the first time the device was connected, the last time it was connected, and the last time the device was removed from the system:

```
SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\<VALUE>
```

In this key, the `<VALUE>` sign can be replaced with the following to get the required information:

| Value | Information |
| - | - |
| `0064` | First connection time |
| `0066` | Last connection time |
| `0067` | Last removal time |

###### USB Device Volume Name

The device name of the connected device can be found at `SOFTWARE\Microsoft\Windows Portable Devices\Devices`:

![[registry_explorer_usb_device_name.png]]

We can then compare the GUID to the DIsk ID on the keys within Device Identification to correlate the names with unique devices.  As such, we can create a fair picture of any USB devices that were connected to the machine we are investigating.

