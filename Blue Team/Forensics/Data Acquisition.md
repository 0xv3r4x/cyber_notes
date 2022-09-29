# Data Acquisition

When performing forensics, we either encounter a live system or an image taken from the system.  It is recommended to use an image or make a copy of the required data and then carry out the forensics process.

Firstly, we need to understand the artifacts which are available in order to create a **triage collection** - an exported subset of files within the disk image.  This collection can then be used for further analysis and is particularly effective when an entire image cannot be moved because of size restrictions or time limitations.

## [Autopsy](https://www.autopsy.com/): Disk Acquisition

[Autopsy](https://www.autopsy.com/) allows you to acquire data from live systems and from disk images.  After adding your data source, you can navigate to the location of the files you want to extract, then right-click and select "**Extract File(s)**":

![[autopsy_extract_files.png]]

## [FTK Imager](https://www.exterro.com/ftk-imager): Disk Acquisition

Similar to Autopsy, [FTK Imager](https://www.exterro.com/ftk-imager) allows you to extract files from a disk image or live system.  You can also use this to extract specific files for further analysis:

![[ftk_imager_extract_files.png]]

FTK Imager can also be used to extract Windows Registry files through **Obtain Protected Files**.  This is only available for live systems and it allows you to extract all the registry hives to a specified location, excluding `Amcache.hve`:

![[ftk_imager_obtain_protected_files.png]]

## [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape): Triage Data Collection

[KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) is a live data acquisition and analysis tool which can be used to acquire registry data. Using KAPE, we can create a triage collection of a mounted image.

![[kape_main_view.png]]

First check the **Use Target options** box and then set the **Target source** to the mounted image and the **Target destination** to the directory where you want to store the data.

![[kape_target_configuration.png]]

Targets can then be manually selected within the **Targets** section.  In addition, **Compound** targets allow you to gather groups of associated artifacts automatically.  These are defined within the `\KAPE\Targets\Compound` directory.

![[kape_kapetriage_targets.png]]

On the right-side of KAPE, you can select specific tools and run them against the target, providing an instant result if we know the type of data we are looking for.

Once all of the targets have been configured, run KAPE by clicking "**Execute!**".  This will create a command-line instance, executing the command assembled within the GUI.