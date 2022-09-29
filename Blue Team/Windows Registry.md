# Windows Registry

A **collection of databases** (key-value pairs) that contain the system's configuration.  Can be viewed through the **Registry Editor** (`regedit.exe`)

## Structure

The registry has the following root keys:

1. `HKEY_CLASSES_ROOT`
2. `HKEY_CURRENT_USER`
3. `HKEY_LOCAL_MACHINE`
4. `HKEY_USERS`
5. `HKEY_CURRENT_CONFIG`

#### `HKEY_CLASSES_ROOT`

Subkey of `HKEY_LOCAL_MACHINE\Software` - sometimes abbreviated `HKCR`.  Ensures the correct program is executed when open through the Windows Explorer.  

From Windows 2000, the information in `HKEY_CLASSES_ROOT` is also stored under `HKEY_LOCAL_MACHINE\Software\Classes` and `HKEY_CURRENT_USER\Software\Classes`.  These respective locations contain the default settings for all users on the local machine and the settings that override these default settings (only apply to the interactive user).

#### `HKEY_CURRENT_USER`

Contains the root of the configuration data for the user that is currently logged in to the system, including the user's folders, screen colors, and control panel - sometimes abbreviated `HKCU`.  This is a symbolic link to the `HKEY_USERS` key which stores the users on the system.

#### `HKEY_LOCAL_MACHINE`

Contains the Windows-specific settings for the computer - sometimes abbreviated `HKLM`.

#### `HKEY_USERS`

Contains all the actively loaded user profiles on the system.

#### `HKEY_CURRENT_CONFIG`

Contains information about the hardware profile that is used by the local computer at startup.

## Registry Hives

If you have access to a disk image, you can access the registry hives on the disk.

The registry hives which describe the system configuration are located in the `C:\Windows\System32\config` directory:

1. `DEFAULT`: mounted on `HKEY_USERS\DEFAULT`
2. `SAM`: mounted on `HKEY_LOCAL_MACHINE\SAM`
3. `SECURITY`: mounted on `HKEY_LOCAL_MACHINE\Security`
4. `SOFTWARE`: mounted on `HKEY_LOCAL_MACHINE\Software`
5. `SYSTEM`: mounted on `HKEY_LOCAL_MACHINE\System`

The registry hives which contain user information are located within the `C:\Users\<USERNAME>` and `C:\Users\<USERNAME>\AppData\Local\Mircrosoft\Windows` directories:

1. `NTUSER.DAT`: mounted on `HKEY_CURRENT_USER` when a user logs in
2. `USRCLASS.DAT`: mounted on `HKEY_CURRENT_USER\Software\CLASSES`

Finally, Windows creates an `Amcache.hve` file within `C:\Windows\AppCompat\Programs\Amcache.hve` which saves informationr egarding programs that were recently run on the system.

#### Transaction Logs

Windows also creates transaction logs which monitor the changes to each hive.  These can be viewed using `dir /a` on the `C:\Windows\System32\Config` directory:

![[transaction_logs.png]]

In addition, there may also be `.sav` files associated with such logs which hold the backups for each hive - these are more commonly found on older Windows systems.

## Exploring the Windows Registry

Once the registry hives have been extracted using one of the [Data Acquisition](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FData%20Acquisition) methods, you can then analyse them.

Since the registry editor (`regedit.exe`) only works for live systems and cannot export hives, we can use the following tools:

#### [Registry Viewer](https://accessdata.com/product-download/registry-viewer-2-0-0)

AccessData's [Registry Viewer](https://accessdata.com/product-download/registry-viewer-2-0-0) has a similar interaface to the Windows Registry Editor, but with some limitations, namely it can only load one hive at a time and cannot take transaction logs into account.

![[accessdata_registry_viewer_main_view.png]]

#### [Registry Explorer (EzTools)]([EzTools](https://ericzimmerman.github.io/#!index.md))

Within Eric Zimmerman's [EzTools]([EzTools](https://ericzimmerman.github.io/#!index.md)), the Registry Explorer can be used to parse through registry hives.  Unlike the Registry Viewer, this tool can load multiple hives simultaneously and add data from transaction logs to ensure each hive is up-to-date.

![[registry_explorer_imported_registry_hives.png]]

#### [RegRipper](https://github.com/keydet89/RegRipper3.0)

[RegRipper](https://github.com/keydet89/RegRipper3.0) is a utility which takes a registry hive as input and outputs a report (in the form of a text file) containing extracted data that may be of forensic importance.

This tool is available in both a CLI and GUI form.  However, RegRipper does not account for transaction logs, so we must use this in conjunction with Registry Explorer to merge transaction logs with the registry hives before sending them to RegRipper.

![[rr_exe_main_view.png]]

RegRipper operates from perl-based (`.pl`) plugins which contain code to parse through parts of a registry hive.  