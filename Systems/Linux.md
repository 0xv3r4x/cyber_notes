# Linux

Notes:
- `sort` and `uniq`
- Keyboard controls and process suspension
- Access rights (permissions, setuid, umask, etc.)
- Shell variables
- Jobs

## What is the Shell?

The **shell** is running a *process* (an instance of a program being executed by one or many threads).  It is an interactive interpreter which enables the user to enter commands in order to perform specified actions.

When a user runs a command, it is executed with respect to the shell's current directory - i.e., it learns the current directory from the parent process, being the shell.

## Shell Wildcards

```
*        Any number of characters
?        Any single character
[ab]     Characters 'a' or 'b'
[a-z]    Characters from a-z
```

Example usage:

```console
# Matches all filenames which begin with 'f', followed
# by any number of characters (including 0)
$ ls f*
f f1 ff file1 file2

# Matches all filenames which begin with 'f', followed
# by one character
$ ls f?
f1 ff

# Matches all files which begin with 'f', followed
# by a number within the range 0-9
$ ls f[0-9]
```

## I/O and Output Redirection

By default, the input is read from the keyboard (**stdin**) and outputted to the display via **stdout**.  In the case where an error occurs, **stderror** is used to communicate this with the user

```
stdin     0
stdout    1
stderr    2
```

The output of a command can be redirected:

```
>    Redirect stdout
>>   Append stdout
<    Redirect stdin
<<   Append stdin
|    Pipe stdout to stdin

2>     Redirect stderr
2>&1   Redirect stderr to stdout
```

For example:

```console
# stdout of first command is piped to the stdin of the second command
$ cat new_file | grep "hello world"

# Truncate (set write pointer to top of file) the string and direct
# the output to greeting.txt
$ echo "Hello world" > greeting.txt

# Append the string to the end of greeting.txt
$ echo "Hello again" >> greeting.txt
```

However, some operations won't work:

```console
# The shell handles the redirection first, opening the file for output, setting # its size to 0 for it to be overwritten. The shell then invokes the sort
# against the now empty file, outputting nothing
$ sort datafile > datafile

# Alternatively:
$ sort -o datafile datafile

# Or:
$ sort datafile > temp
$ mv temp datafile
```

## Composing Commands

```
# Sequential composition
# Upon completion of com1, com2 is executed, and so on
$ com1 ; com2 ; com3 ; com4

# Parallel composition
# All commands are executed at the same time - com1-com3 are executed in the
# background and com4 is executed in the foreground
$ com1 & com2 & com3 & com4

# Conjunctive composition (AND)
# Commands are executed sequentially, if and only if, the previous command
# returns 0 (success), otherwise the commands won't run
$ com1 && com2 && com3 && com4

# Disjunctive composition (OR)
# Continues execution only if the previous command returns 1 (fail)
$ com1 || com2 || com3 || com4
```

## Control Characters

```
CTRL+C    Interrupt command
CTRL+Z    Suspend command
CTRL+D    End-of-file
CTRL+H    Delete last character
CTRL+W    Delete last word
CTRL+U    Delete line
CTRL+S    Suspend output (rarely used)
CTRL+Q    Continue output (rarely used)
```

## Regular Expressions

**Regular expressions** are templates for strings:

```
.        Match any character
*        Match zero or more occurrences of previous character
^        Match beginning of line
$        Match end of line
[abc]    Match any one of a, b, or c
[a-z]    Match any character in range
```

## Linking Files

All directories have at least two names (the name in their parent directory and `.` in their own directory).

The two names refer to exactly the same area on the disk.  When a given file has multiple hard-links, it has multiple names that refer to its i-node number via a directory lookup.  When a file has no links, the contents are removed - the `rm` command uses `unlink()`

```
$ ln <source_file> <target_file>

# Creates a hard link from 'hard_link' that points to the i-node
# of 'greeting.txt'
$ ln greeting.txt hard_link

# Cannot create hard links to directories as it creates loops
# in the file system, causing commands like 'find' to behave
# unexpectedly
```

Symbolic (soft) links simply contains the pathname of the file it refers to, i.e., a new file whose content refers to the file.  As such has a different i-node number.

```
# Creates a soft link from 'soft_link' which refers to the
# 'greeting.txt' file
$ ln -s greeting.txt soft_link
```

Unlinking is done through the `rm` command and can be verified via `ls`:

```
# Second column indicates number of links to the file
$ ls -l
total 4
-rw-rw---- 2 halpinl cc6F67    14 Aug 15 19:45 greeting.txt
-rw-rw---- 2 halpinl cc6F67    14 Aug 15 19:45 hard_link

# Remove hard link to 'greeting.txt'
$ rm hard_link

# Verify link has been removed (2 -> 1)
$ ls -l
total 4
-rw-rw---- 1 halpinl cc6F67    14 Aug 15 19:45 greeting.txt
```

## Permissions

Can be represented in *octal form* or *symbolically*.

| Binary | Octal | Symbolic (UGO) |
| - | - | - |
| 000 | 0 | `---` |
| 001 | 1 | `--x` |
| 010 | 2 | `-w-` |
| 011 | 3 | `-wx` |
| 100 | 4 | `r--` |
| 101 | 5 | `r-x `|
| 110 | 6 | `rw-` |
| 111 | 7 | `rwx` |

Changed using `chmod`:

```
$ chmod file.txt
```

## Environment Variables

These variables can exist both locally and in the environment 

```
HOME       The path of the user's /home directory
LOGNAME    The user's login name
PATH       The command search path for the shell
PS1        The shell's primary prompt
PS2        The shell's secondary prompt
SHELL      The path of the shell
TERM       The type of terminal
IFS        Input file separator
MAILCHECK  The frequency email is checked
DISPLAY    X server for GUI applciations
```

## Inodes

There are reserved inodes - so they don't start from 0, 1 is for bad blocks, 2 is for the root of the filesystem.

Inodes also have a mode property which defines the permissions of the file/directory.

Information about owner - uid, guid.

Size and timestamp information (creation, last updated, etc.)

Does not contain the filename - it is stored as data on another part of the OS.


## Dynamic Link Libraries

When the app starts up, it doesn't ask for the library functionality until it needs to use it - loaded at runtime.

The compiler needs to know where the entry points are for each of the functions so they can be called.  This is the responsibility of the runtime linker

If two apps use the same DLL, it doesn't have to be loaded into memory twice.  When the library is defined, we can note which parts are shared and if there are any data that should be shared (made copies).