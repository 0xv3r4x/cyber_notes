# AV Evasion

Typically involves payload obfuscation (e.g., changing variable names, encoding aspects of script, or encrypting the payload and writing a wrapper to execute section-by-section).  Overall, the aim is to switch things enough so that the AV solution is unable to detect a malicious payload.

Two main types:
- **on-disk evasion**: when you try to get a file saved on a target and then executed
	- e.g., common when working with `.exe` files
- **in-memory evasion**: when you try to import a script directly into memory for execution
	- e.g., downloading a remote PowerShell module and directly importing it without ever saving it to disk 

## In-Memory Evasion

Historically, this was enough to bypass most AV solutions as they were unable to scan scripts stored within the memory of a running process.  However, Microsoft introduces **A**nti-**M**alware **S**can **I**nterface (**AMSI**) which scans scripts as they enter memory - provides hooks for AV software to copy script, execute it, and decide if it is safe to continue execution.

## Fingerprinting

We first start by fingerprinting the AV on the target to determine what solution we are up against.  If we have a shell on the target, we can use [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker) and [Seatbelt](https://github.com/GhostPack/Seatbelt) to identify the AV solution.

Once we know the OS version and AV solution, we can then replicate the environment in a virtual machine to test out payloads.  Once we have a working payload, we can attack the target.

## Detection Methods

Modern AV solutions rely on two main detection methods:
- **Static Detection**
- **Dynamic/Heuristic/Behavioural Detection**

AV vendors also work in unison to share signatures and behaviours of malware samples - this also includes websites like [VirusTotal](https://www.virustotal.com/)

#### Static Detection

Normally involves signature detection, whereby a hashsum is created from a suspicious file and compared against a database of known malware hashsums.  Can be effective, but as soon as the payload is changed the hashsum is also changed.

Static detection also involves Byte (or string) matching which searches through the program to match sequences of bytes against a known database of bad byte sequences.  This is much more effective method, but can take longer in cases where the AV is looking for a small sequence of bytes in a large program.  In contrast, a hashsum can be generated almost instantly and compared with a database.  However, the AV solution can hash small sections of the file to check against the database, rather than the entire file, reducing effectiveness of technique, but increasing speed of detection.

#### Dynamic Detection

Dynamic methods surveys how the file acts and can do so through two main ways.

Firstly, the AV software can check the executable line-by-line checking the flow of execution.  Based on a set of **pre-defined rules, the AV can see how the program **intends to act** (e.g., is it reaching out to a website? or messing with registry values?) and make decisions accordingly.

Secondly, the suspicious software can be executed within a sandbox environment under close supervision from AV software - it can then be quarantined and flagged as malware.

Dynamic methods are also harder to evade than static methods.  However, sandboxes can be distinctive and sophisticated malware will check for certain system features, such as is there a fan installed, is there a GUI, and if there are any virtualisation tools running which may indicate that it is within a sandbox.  If the malware detects any of these features, it should exit so that the AV software flags it as safe.

With logic-flow analysis, the AV software works with a set of rules to check for malicious behaviour.  If the malware acts in a way that is unexpected, such as some random code that does nothing within the exploit, it will likely pass this detection method.

With certain delivery methods, password protecting can also get around the behavioural analysis checks since the AV software is unable to open and execute the file.

Overall, dynamic detection methods are significantly more effective than sttaic methods, but can take more time and resources as VMs are required to analyse the file.

-----

Password: Password1!!
Recovery phrase:
couple frame atom tooth rebuild entry quiz circle cattle female expect rubber

804-608-744
- [ ] 352334700815100