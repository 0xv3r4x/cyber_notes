# MFTCmd.exe

## Analysis of MFT Records

You can use the `MFTECmd.exe` application to parse through an NFTS file, but it is mostly used for the `$MFT` file.  As such, we can output the file's contents to another file where every row is an entry/record in the `MFT`.

We can also use this file to look into a particular record, meaning that we don't need to parse through all of the data.  Each record has a unique number associated with it.  Information on such meta data can be found at [NFTS.com](https://www.ntfs.com/ntfs-system-files.htm).  For example. we can view the entry details for the `MFT` record - the first record in every `$MFT` file:

```console
> MFTECmd.exe -f "C:\$MFT" --de 0
```

The above runs the `MFTECmd.exe` application against the `C:\$MFT` file and details the entry (`--de`) with index `0`, which points to the `MFT` record.  From the output, there are many interesting attributes.  Firstly, it indicates if the record/file is in user, as well as showing its log sequence number which is also recorded within the transaction logs:

![[mft_flag_in_use.png]]

Secondly, the `STANDARD INFO` section shows a number of key attributes in flags.  For example, `Resident: True` means that the associated attributes (i.e., `Created On`, `Modified On`, etc.) exist within this specific record - if this was set to `False`, then this information would be stored elsewhere

![[mft_standard_info.png]]

The `FILE NAME` section details information relating to the file itself.

![[mft_file_name_section.png]]

The `DATA` section indicates that the data is stored on a different area on the disk.  The `0x7D40` indicates where this data can be found.

![[mft_data_section.png]]

## MFT Parsing

We can use `MFTECmd.exe` to analyse the contents of the filesystem to give us an idea of when the system was compromised and the actions of the attacker.

To parse through the `$MFT` file, we can run the following:

```console
> MFTECmd.exe -f "path\to\$MFT" --csv "path\to\save" --csvf <output_file_name>
```

For example:

```console
> MFTECmd.exe -f "C:\Cases\E\$MFT" --csv "C:\Cases\Analysis\NFTS" --csvf MFT.csv
```

This will parse through the `$MFT` file, saving the output to `MFT.csv` within `C:\Cases\Analysis\NTFS`.  Subsequently, we can then use Excel to look through the data or **TimelineExplorer** within EzTools.

To do this, firstly open `TimelineExplorer.exe` and drag the parsed `.csv` file into the application:

![[load_csv_timeline_explorer.png]]

For the purposes of our attack, we are interested in the contents of the `PWF` folder:

![[pwf_folder_contents.png]]

We can also look for specific information relating to the identified `ART-attack.ps1` script.  From the above, the entry number for this file within the MFT is `32940`.  We can use this with MFTECmd to find out more details:

![[art_attack_ps1_mftecmd.png]]

As shown, the file is `InUse`, meaning it still exists on the filesystem.  From the above, we see that the file was created on the system on `31/07/2022` and was recorded on the MFT at `21:10:48` on the same day.

## Time Stomping

**Timestomping** is a technique used by attackers to hide certain files.  The attacker may manipulate the timestamp and move it back by a few years, meaning it likely will not show up in an analyst's timeline,

![[timestomping_evidence.png]]

For example, the above could have been timestamped if the `$STD_INFO` blocks are less than the `$FILE_NAME` timestamps, the file may have been timestompped.

Timeline Explorer within EzTools also has a field to indicate timestomping:

![[timeline_explorer_timestomping.png]]

## Deleted Files

Recall that if a file is marked not `InUse` within `$MFT`, then the file has been marked for deletion and will be overwritten when required.  We can look at the details of such records with `MFTECmd.exe`:

![[example_deleted_file_mftecmd.png]]

In this example file shown above, the `Flags: IsFree` indicates that the file can be overwritten with subsequent data writes and file creations.  Similarly, the `DATA` attribute points to the 10 clusters (`0x10`) within the `0x17D366` cluster area.  This area will contain the data of the file but can be overwritten by subsequent filesystem operations - unallocated space but not empty.

#### Analysing the USN Journal

Journalling is an NTFS specific feature which ensures filesystem integrity when a crash occurs.  These journal entries store operations which occur on particular files or on the `$MFT` specific entries.  If the system crashes, the NTFS uses these files for system recovery.

Journal files:
- `C:\$LogFile`: tracks data relating to `$MFT` and other updated metadata
- `C:\$Extend\$UsnJrnl`: **U**pdate **Sequence** **J**ournal (**USN**) contains a log of operations that have been carried out against files on the system
	- consists of two alternate data streams: `$Max` and `$J`