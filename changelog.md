# Changelog

## 1.02 - 2021-05-17

 - Code cleanup
 - Update internal scan rules to include 32 & 64 bit rules.
 - BUGFIX: Issues with emulating 32bit code and reading from RIP when emulating x86 code
 - BUGFIX: FIX issue when the start of function is used as the blob start. First check if there are any calls or other data that was exected to be initialized.
 - BUGFIX: FIX issue where patch bytes are null.
 - KNOWN ISSUE: 32bit patching is disabled. Patching is being refactored and improved. 

## 1.0 - 2021-05-05
 - Initial Release 
