# Bash Cheatsheet

## Shebang

```bash
#!/bin/bash

# "shebang" -> the first line of the script
# tells the OS which interpreter to use for the script
```

## Executing Scripts

```bash
# octol permissions
chmod 775 script.sh

# ugo (user, group, other) permissions
chmod +x script.sh

# executing scripts
./script.sh
```

## Input and Output

```bash
# output
echo "Hello"  # => Hello
echo "Current directory $(pwd)"  # Prints output of pwd (same as `pwd`)

# basic input
echo "What is your name? "
read name
echo $name

# input (one character)
echo -n 1 "Proceed [y/n]: "
read choice
echo $choice
```

###### Arguments

```bash
$#  # Number of arguments

$*  # All positional arguments (as a single word)

$@  # All positional arguments (as separate strings)

$1  # First argument

$_  # Last argument of previous command
```

## Variables

```bash
name = "John"
echo $name  # => John
```

## Conditionals

```bash
string = "I am not empty"

if [[ -z $string ]]; then
	echo "String is empty"
elif [[ -n $string ]]; then
	echo "String is not empty"
else
	echo "This will never execute"
fi

# => String is not empty
```

###### Useful Conditionals

Common conditionals:

```bash
[[ -z STRING ]]  # Empty string

[[ -n STRING ]]  # Not empty string

[[ STRING == STRING ]]  # Equal

[[ STRING != STRING ]]  # Not equal

[[ NUM -eq NUM ]]  # Equal

[[ NUM -lt NUM ]]  # Less than

[[ NUM -le NUM ]]  # Less than or equal

[[ NUM -gt NUM ]]  #Greater than

[[ NUM -ge NUM ]]  # Greater than or equal

[[ STRING =~ STRING ]]  # Regexp

(( NUM < NUM ))  #Numeric conditions
```

File Conditionals:

```bash
[[ -e FILE ]]  # Exists

[[ -r FILE ]]  # Readable

[[ -h FILE ]]  # Symlink

[[ -d FILE ]]  # Directory

[[ -w FILE ]]  # Writable

[[ -s FILE ]]  # Size is > 0 bytes

[[ -f FILE ]]  # File

[[ -x FILE ]]  # Executable

[[ FILE1 -nt FILE2 ]]  # 1 is more recent than 2

[[ FILE1 -ot FILE2 ]]  # 2 is more recent than 1

[[ FILE1 -ef FILE2 ]]  #Same files
```

Operators:

```bash
[[ ! EXPRESSION ]]  # Not

[[ X && Y ]]  # And

[[ X || Y ]]  # Or
```

## Loops

###### For Loop

```bash
# basic for loop
for i in /etc/passwd; do
	echo $i
done

# c/java-style loop
for ((i=0; i<100; i++)); do
	echo $i  # => 0 1 2 3 4 ... 99
done
```

###### While Loop

```bash
# basic while
while true; do
	echo "hello"  # => hello hello hello...
done

# conditional while
cat file.txt | while read line; do
	echo $line
done
```

###### Ranges

```bash
# basic range loop
for i in {1..5}; do
	echo $i  # => 1 2 3 4 5
done

# loop with step
for i in {1..50..5}; do
	echo $i  # => 1 6 11 16 ...
done
```

## Functions

###### Defining functions

```bash
my_func() {
	echo "This is my function"
}

# OR

function my_func_alt() {
	echo "Hello $1"
}

my_func()  # => This is my function
my_func_alt
```

###### Raising Errors

```bash
my_func() {
	return 1
}

if [[ my_func ]]; then
	echo "Success: $(my_func)"
else
	echo "Failure: $(my_func)"
```

## Other Cheatsheets

- [DevHints.io](https://devhints.io/bash)