# Cyclops
Disassembler project utilizing Capstone.<br />
### [WARNING]<br />
<pre>
Your eyes are at serious risk of illness, there are a ton of horrible code practices...<br />
I will fix them as I improve the disassembler
</pre>

### [REQUIREMENTS]<br />
<pre>
 sudo apt-get update; sudo apt-get install libcapstone-dev
</pre>

### [COMPILING]<br />
<pre>
 Run make
</pre>
 

### [SUPPORTED FILE FORMATS]<br />
<pre>
  - ELF (Working)<br />
  - PE (In Development)
</pre>

### [SUPPORTED ARCHITECTURES]<br />
<pre>
  - x86 (Working)<br />
  - IA-64 (Working)<br />
  - AMD x86-64 (Working)<br />
  - ARMv7 (In Development)<br />
  - ARMv8 (In Development)<br />
  - SPARC (In Development)<br />
  - PowerPC (In Development)<br />
  - Berkley Packet Filter (In Development)<br />
  - TMS320C6000 Digital Signal Processor family (In Development)
</pre>

### [EXAMPLE DISASSEMBLY]<br />
<pre>
$ ./cyclops -d Example.elf<br />

[Cyclops Disassembler Version (0.1.0)]<br />

[Cyclops_Analyzer]: Starting General Analysis of Example.elf<br />
[Cyclops_Analyzer]: Analysis of Example.elf finished!<br />

[Example.elf]<br />
 > FILE_FORMAT: ELF<br />
 > FILE_SIZE: 16720<br />
 > BIT: 64-bit<br />
 > ENDIANESS: Little Endian<br />
 > OSABI: System-V<br />
 > E_TYPE: Shared Object File<br />
 > E_MACHINE: AMD x86-64<br />
 > E_ENTRY: 0xc010000000000000<br />

[Cyclops_Disassembler]: Starting disassembly of Example.elf<br />
[Cyclops_Disassembler]: Disassembling main() @ (0x11a9)<br />

MAIN:<br />
 > 0x11a9: endbr64 <br />
 > 0x11ad: push rbp<br />
 > 0x11ae: mov rbp, rsp<br />
 > 0x11b1: lea rsi, [rip + 0xe4d]<br />
 > 0x11b8: lea rdi, [rip + 0x2e81]<br />
 > 0x11bf: call 0x1090<br />
 > 0x11c4: mov rdx, rax<br />
 > 0x11c7: mov rax, qword ptr [rip + 0x2e02]<br />
 > 0x11ce: mov rsi, rax<br />
 > 0x11d1: mov rdi, rdx<br />
 > 0x11d4: call 0x10a0<br />
 > 0x11d9: mov eax, 0<br />
 > 0x11de: pop rbp<br />
 > 0x11df: ret
</pre>

### [VERSION TRACKER]<br />
<pre>
 (1.1.0):<br />
   - Support for Disassembling x86, IA-64 and AMD x86-64 ELF binaries
</pre>

### [BUG TRACKER]<br />
<pre>
 (1.1.0):<br />
   - (Not really a bug, just logic error) In analyze(std::string fileName) on eEntry set we get our bytes from [FILE] but it is displayed as Big Endian
</pre>
