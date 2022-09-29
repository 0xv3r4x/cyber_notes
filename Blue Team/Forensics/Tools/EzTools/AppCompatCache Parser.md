# AppCompatCache Parser

ShimCache, or Application Compatibility Cache (AppCompatCache), keeps track of application compatibility with the OS and tracks all applications launched on the machine.  Its main purpose is to ensure backwards compatibility and is located in `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`.

ShimCache stores the file name, size, and last modified time of executables.

The AppCompatCache Parser takes the `SYSTEM` hive as input, parses the data, and outputs a `.csv` file which looks similar to the one shown below:

![[appcompatcache_parser.png]]

We can use the following command to run the utility:

```console
> AppCompatCacheParser.exe --csv <path to save output> -f <path to SYSTEM hive for parsing> -c <control set to parse>
```

The output can then be viewed using [EzViewer](obsidian://open?vault=cyber_notes&file=Blue%20Team%2FForensics%2FTools%2FEzTools%2FEzViewer) within EzTools.