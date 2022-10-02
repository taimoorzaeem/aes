# AES-128-in-x86-Assembly
Implemented AES in Intel x86 assembly.

For building on windows:

### Requirements
You must have Microsoft Macro Assembler `ml` installed on your machine.
You will also need Microsoft Incremental Linker `link` for linking with libraries.
Disable windows defender in case it interferes with building.

**To build with cmd:**
```
> ml -c /I include -coff aes.asm
> link aes.obj lib\irvine32.lib lib\kernel32.lib /SUBSYSTEM:CONSOLE
```
