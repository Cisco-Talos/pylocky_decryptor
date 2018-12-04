# PyLocky Decryptor

This decryptor is intended to decrypt the files for those victims affected by the ransomware PyLocky.
-----------------------------------------------------------------------------------------------------

This decryptor is built to be executed on Windows systems only and it does require a PCAP of the outbound connection attempt to the C&C servers. This connection is seen seconds after the infection occurs and it will contain, among other info, the Initialization Vector (IV) and a password (both generated randomly at runtime) used to encrypt the files. Without this PCAP containing these values, the decryption won't be possible.

The structure of the outbound connection contains an string like:

	PCNAME=NAME&IV=KXyiJnifKQQ%3D%0A&GC=VGA+3D&PASSWORD=CVxAfel9ojCYJ9So&CPU=Intel%28R%29+Xeon%28R%29+CPU+E5-1660+v4+%40+3.20GHz&LANG=en_US&INSERT=1&UID=XXXXXXXXXXXXXXXX&RAM=4&OSV=10.0.16299+16299&MAC=00%3A00%3A00%3A00%3A45%3A6B&OS=Microsoft+Windows+10+Pro

The above string is contained in a POST request and is required to be inside an HTTP session saved in the PCAP passed as an argument to this decryptor.

# Requirements to execute it
* Windows OS (infected machine)
* WinPcap (Download it here: https://www.winpcap.org/install/default.htm)
* PCAP file with IV and password generated at ransomware's runtime

# Usage

```
usage: pylocky_decryptor.exe [-h] [-p pylocky.pcap] [-r] [-d]

PyLocky decryptor

optional arguments:
  -h, --help            show this help message and exit
  -p pylocky.pcap, --pcap pylocky.pcap		Provide PyLocky C&C pcap
  -r, --remove          Remove encrypted files
  -d, --debug           Debug this program
```

# Instructions
1. Clone or download this repository to your computer (remember should be a PyLocky infected windows machine)
2. Open a terminal: Start-> Run-> Type `cmd` and hit Enter
3. In the command prompt, navigate to the folder location where the decryptor was downloaded (as in step 1), e.g:
`cd C:\Users\User\Desktop\pylocky_decryptor`
4. Specify the PCAP file with the `-p` (or `--pcap`) switch: `pylocky_decryptor.exe -p pylocky.pcap`
5. Wait for the decryptor to complete the decryption process and verify the usability of your files and system

# Output

If the program is enabled with debug output you will be able to see with detail how the PCAP file is being read, extracted both the IV and password and then what file is the decryptor reading, decrypting and restoring:

```
C:\Users\User\Desktop>pylocky_decryptor.exe -p pylock-fix.pcap -d -r
reading from file pylock-fix.pcap, link-type EN10MB (Ethernet)
Password to decrypt with: CVxAfel9ojCYJ9So
IV (base64 decoded) to decrypt with: )|ó&xƒ)
Opening fname: C:\Users\User\AppData\Local\Microsoft\Windows\Explorer\iconcache_48.db.lockedfile
Closed fname: C:\Users\User\AppData\Local\Microsoft\Windows\Explorer\iconcache_48.db.lockedfile
Before getting decryptor
...
Before decrypting data
Opening fname_w_e: C:\Users\User\MicrosoftEdgeBackups\backups\MicrosoftEdgeBackup20180914\MicrosoftEdgeFavoritesBackup.html
Closed fname_w_e: C:\Users\User\MicrosoftEdgeBackups\backups\MicrosoftEdgeBackup20180914\MicrosoftEdgeFavoritesBackup.html
File processed correctly: C:\Users\User\MicrosoftEdgeBackups\backups\MicrosoftEdgeBackup20180914\MicrosoftEdgeFavoritesBackup.html.lockedfile
File removed correctly: C:\Users\User\MicrosoftEdgeBackups\backups\MicrosoftEdgeBackup20180914\MicrosoftEdgeFavoritesBackup.html.lockedfile
Decryption complete! Please verify the content of your files and system
```

Also, if the remove flag was used along with the debugging flag, you will see a message like:

```
File removed correctly: C:\Users\User\Desktop\Tor Browser\Browser\browser\VisualElements\VisualElements_150.png.lockedfile
```

If there are no files with the `.lockedfile` extension OR all the files have been decrypted correctly and removed in a previous run, you'll simply get the following message:

```
No files with the ".lockedfile" extension were found. Please check again
```

# Compiling the source code

If you need to modify the source code of the decryptor, you can do it using Python 2.7 and then use `PyInstaller` on Windows OS which can be installed using the [auto-py-to-exe](https://pypi.org/project/auto-py-to-exe/) module. This module is a GUI that converts the Python script into a fully working exe file in a very easy way.

You can also use the command prompt, once you have `auto-py-to-exe` installed, with the following syntax:

```
C:\Users\User\Desktop>pyinstaller -y -F pylocky_decryptor.py
```

Note: if by any chance you get an import error stating: "No module named Queue" then just simply add `--hidden-import=Queue` to the pyinstaller arguments and the exe file should be generated correctly. You can find the exe file in a `dist` folder in the location you are currently working and with the same of the python script but with the `exe` extension.

# Warning

During the development and testing of this decryptor it has been tested the succesfull recovery of 3 infected systems (with their corresponding PCAP file) and the only small issue found has been with very large files (more than 4 Gb) not able to be decrypted.

This tool is intended to be used in a live infected system, since it will loop over all the hard drives installed in the system and search for all the files containing the PyLocky encryption extension.

The debugging switch `-d` or `--debug` might provide a very verbose output but can be useful to understand what the decryptor is doing and any potential issues found. Is recommended to use it the first time the decryptor is executed.

Last but not least, using the switch `-r` or `--remove` will remove the copy of the encrypted files. Doing so will help to clean a bit the infection leftovers in the system however, if something goes wrong during the process and a file wasn't decrypted properly AND this option is enabled, the encrypted file will be deleted and then there will be no way to recover the content. Please be careful and use this option after an initial first recovery of the files, then in a second time running the decryptor there will be less the likelihood of losing the content. Cisco won't be responsible for a misuse of this tool.
