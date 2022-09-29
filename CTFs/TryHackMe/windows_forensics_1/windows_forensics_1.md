# Windows Forensics 1

*Introduction to Windows Registry Forensics*

-----

###### Task 1 - Introduction to Windows Forensics

1. What is the most used Desktop Operating System right now?

```
Microsoft Windows
```

###### Task 2 - Windows Registry and Forensics

1. What is the short form for `HKEY_LOCAL_MACHINE`?

```
HKLM
```

###### Task 3 - Accessing registry hives offline

1. What is the path for the five main registry hives, `DEFAULT`, `SAM`, `SECURITY`, `SOFTWARE`, and `SYSTEM`?

```
C:\Windows\System32\Config
```

2. What is the path for the AmCache hive?

```
C:\Windows\AppCompat\Programs\Amcache.hve
```

###### Task 4 - Data Acquisition

1. Try collecting data on your own system or the atatched VM using one of the above mentioned tools

```
No answer needed
```

###### Task 5 - Exploring Windows Registry

1. Study the above material to understand the difference between the different tools

```
No answer needed
```

###### Task 6 - System Information and System Accounts

1. What is the Current Build Number of the machine whose data is being investigated?

```
19044
```

2. Which ControlSet contains the last known good configuration?

```
1
```

3. What is the Computer Name of the computer?

```
THM-4N6
```

4. What is the value of the `TimeZoneKeyName`?

```
Pakistan Standard Time
```

5. What is the DHCP IP address?

```
192.168.100.58
```

6. What is the RID of the Guest User account?

```
501
```

###### Task 7 - Usage or knowledge of files/folders

1. When was EZtools opened?

```
2021-12-01 13:00:34
```

2. At what time was My Computer last interacted with?

```
2021-12-01 13:06:47
```

3. What is the absolute path of the file opened using `notepad.exe`?

```
C:\Program Files\Amazon\Ec2ConfigService\Settings
```

4. When was this file opened?

```
2021-11-30 10:56:19
```

###### Task 8 - Evidence of Execution

1. How many times was the file explorer launched?

```
26
```

2. What is another name for ShimCache?

```
AppCompatCache
```

3. Which of the artifacts also saves SHA1 hashes of the executed programs?

```
AmCache
```

4. Which of the artifacts saves the full path of the executed programs?

```
BAM/DAM
```

###### Task 9 - External Devices/USB device forensics

1. What is the serial number of the device from the manufacturer "Kingston"?

```
1C6f654E59A3B0C179D366AE&0
```

2. What is the name of this device?

```
Kingston Data Traveler 2.0 USB Device
```

3. What is the friendly name of the device form the manufacturer "Kingston"?

```
USB
```

###### Task 10 - Hands-on Challenge

###### Task 11 - Conclusion