# Disk Analysis

## Overview

To conduct disk analysis, the following artifacts may be utilised:

- **System and User Information**
	- Windows Registry
- **File Analysis**
	- NTFS
- **Evidence of Execution**
	- BAM
	- ShimCache
	- Amcache
	- Prefetch
- **Persistence Mechanisms**
	- Run keys
	- Startup folder
	- Scheduled tasks
	- Services
- **Event Log Analysis**

Windows utilises the **N**ew **T**echnology **F**ile **S**ystem (**NTFS**) to manage the filesystem.  From analysing the file system, we can determine which files were executed and when, what files were deleted, and if the data is still recoverable.

## NTFS Disk Structure

![[hard_disk_structure 1.png]]

The above figure illustrates a typical structure for a hard disk which is broken up into **two partitions**.

Partition 1:
- 1: **M**aster **B**oot **R**ecord (**MBR**) helps the system find the pointers in order to load the OS
	- Specifically, this points to the actual partition
- 2: **Boot Sector** is a sector of persistent data storage which contains code that is loaded into RAM and then executed by the system's firmware
- 3: **Reserved Filesystem Area** holds the NTFS-related files and other metafiles
- 4: **Data Area** contains the actual data (files and folders) on the filesystem as well as manages unallocated space
	- A file may be broken up into several pieces and spread across the partition
	- When a user deletes the file, the OS does not necessarily delete it from the disk itself; it simply allows the data to be overwritten by other data when needed
		- As such, deleted files can be carved and potentially recovered

However, some files are not visible within Windows Explorer.  To view these files, load the partition with [FTK Imager](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FTools%2FFTK%20Imager):

![[ftkimager_ntfs_files.png]]

## Master File Table (MFT) Analysis

#### Overview of MFT Methods

Any file that has been created, written, stored, modified, or deleted on the filesystem will be contained within the `$MFT` file as an entry.

![[mft_file_record_structure.png]]

The above illustrates the structure of an MFT file record.  A record is typically 1024 bytes, consisting of four main attributes.  

The `Record Header` contains header information, including an entry number which is used by the system as a reference to a file, followed by flags which identify if the file is in use or not (deleted).  If a file is deleted, it would flag the entry as not in use and overwrite it at a later point.  

Files on Windows systems typically all have the `$STD_INFO` attribute which stores data on timestamps.  

The `$FILE_NAME` contains the name of the file with four additional timestamps.  

Finally, the `$DATA` attribute stores the data of the file.  If the file is bigger than the allocated space for the record, the `$DATA` attribute may just contain pointers to the allocated disk space so that the filesystem knows how to find the file.

It is also worthy to note that there may be additional meta data for the file after the `$DATA` attribute, which may contain data from a previous record - **slack space**.  This means that we can potentially find information about a file which previously existed.

#### MAC(b) Format for File Timestamps

As part of timestamp analysis regarding files, we want to turn the timestamps into a format widely recognised within digital forensics - vital for establishing timelines.  We do this using the [MAC(b) timestamp format](https://andreafortuna.org/2017/10/06/macb-times-in-windows-forensic-analysis/).

- **M**odified: `Modified On` timestamp
- **A**ccessed: `Last Accessed On` timestamp
- **C**hanged (`$MFT` modified): `Record Modified On` timestamp
- **B**irth (file creation time): `Created On` timestamp

We can then use the following table to determine how these timestamps are changed based on certain actions:

![[windows_time_rules_stdinfo.png]]

For example, if a file was renamed, it would only change the metadata and not any of the attributes.

#### File Timestomping

Timestomping refers to the attempt to manually change the `$STD_INFO` attributes in order to move the dates and out of scope from the investigation.  `$STD_INFO` can only be accessed through the Windows API, and when changed, can affect the `$FILE_NAME` timestamps - if moved before these dates, then the file could appear as timestomped.

We can analyse these suspected files with [MFTECmd](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FTools%2FEzTools%2FMFTECmd).

#### Deleted Files

We also must be able to find evidence of deleted files in order to fully understand the actions of the attacker.  We can use the [MFTECmd](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FTools%2FEzTools%2FMFTECmd) and Timeline Explorer within EzTools by searching for the name of the file.

Journalling is an NTFS specific feature which ensures filesystem integrity when a crash occurs.  These journal entries store operations which occur on particular files or on the `$MFT` specific entries.  If the system crashes, the NTFS uses these files for system recovery.

Journal files:
- `C:\$LogFile`: tracks data relating to `$MFT` and other updated metadata
- `C:\$Extend\$UsnJrnl`: **U**pdate **Sequence** **J**ournal (**USN**) contains a log of operations that have been carried out against files on the system
	- consists of two alternate data streams: `$Max` and `$J`

We can then use `MFTECmd.exe` to produce a separate output file:

```console
> MFTECmd.exe -f "C:\Cases\E\$Extend\$J" -m "C:\Cases\E\$MFT" --csv "C:\Analysis\NTFS"
```

Here we run `MFTECmd.exe` against the `$J` file.  We also have to point the application to the `$MFT` file (`-m`).  Finally, we output the file into and save it to `C:\Analysis\NTFS`.

Once processed, we can then open this file within Timeline Explorer for analysis.  The most important field to be concerned with is `Update Reasons` which details the particular operation which was applied to the file:

![[timeline_explorer_j_usnjrnl.png]]

As before, we can then search for files which may have been deleted to find out more information:

![[j_usnjrnl_deleted_file.png]]

![[j_usnjrnl_deleted_file_timestamps.png]]

As shown, there are three given entries.  Firstly, the file was created (`2022-04-13 22:11:50`), then it was closed (`2022-04-13 22:11:50`), and then it was deleted (`2022-04-13 22:11:56`).

We can then verify if there is an `$MFT` entry or not:

![[mft_record_deleted_file.png]]

As shown, we have a record for the supposedly deleted file within the `$MFT`.  However, looking at the `$FILE_NAME` attributes, it appears that another file has overwritten this file as it is now named something else:

![[deleted_file_overwritten.png]]

## Evidence of Execution

- Evidence of Execution
	- BAM
	- ShimCache
	- Amcache
	- Prefetch

These can help form a timeline of events and help investigators determine which files may have been used for malicious purposes.

#### Background Activity Moderator (BAM)

Introduced in Windows 10 (2018 build) and records information about executable run on the system.

Can be found at `HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings`.

More information can be found [here](https://dfir.ru/2020/04/08/bam-internals)

Can use the [Registry Explorer](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FTools%2FEzTools%2FRegistry%20Explorer) within EzTools and [RegRipper](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FTools%2FRegRipper).

