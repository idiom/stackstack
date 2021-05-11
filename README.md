# StackStack

Simple Unicorn emulation plugin. I originally developed the plugin as a quick way to emulate decoding strings obfuscated with
[ADVObfuscator](https://github.com/andrivet/ADVobfuscator) or similar methods. 

## Installation

- Copy src/stackstack.py and src/stackstack/ to your Ida Plugins directory.
- Restart Ida

## Requirements 
 - Unicorn Emulator
 - Yara
 - Keystone engine 
 - Capstone engine 

## Configuration

- `loglevel`: Log level to use (DEBUG, ERROR, INFO...). Default: `DEBUG`
- `patch`: Automated binary patching. Default: `True`
- `patch_type`: Type of patching to use. Default: `1`
- `patch_section_name`: Name of section used for deobfuscated strings. Default: `.stackstack`,
- `patch_section_size`: Size of section. Default: `0x1000`,
- `ext_yara_file`: External yara file to use for automated scanning. Defaults to `stackem.yara`
- `bookmarks`: Create bookmarks at decoded offsets. Default: `True`
- `rename_func`: Rename function which contains a single AdvObfuscated string. This is useful where a function 
                 encapsulates a call to a native API. Default: `False`
- `check_update`: Check if there is an update available.   

Example config file
```
{
    'loglevel': 'DEBUG',
    'debug': True,
    'patch': True,
    'patch_type': 1,
    'patch_section_name': '.stackstack',
    'patch_section_size': 0x1000,
    'ext_yara_file': 'stackstack.yara',
    'show_banner': True,
    'check_update': True    
}
```


## Modes 

### Decode 

Emulates the current block or selected bytes and attempts to extract the decoded bytes.

 - Decode Selected - Emulate the selected bytes
 - Decode Current - Based on the current cursor position, detect the blocks to emulate. 
 - Decode All - Scan for and attempt to decode each identified block. 
 - Decode Function - Scan the current function and attempt to decode the found blocks.

### Trace 

For now add register values as a comment and at the end of the block emit the last val
for each register. 

### Emulate 

Emulate the current block and return the end state of all registers.

### Scan

Scan for ADVObfuscated Strings or matches based on the passed yara rules.  
