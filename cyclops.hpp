/* 
 * Cyclops Disassembler
 * Author: https://twitter.com/Plut0n1um1
 */

// Standard Headers
#include <map>
#include <elf.h>
#include <capstone/capstone.h>

// CYCLOPS BASE CLASS
class cyclops{
	// Public Function Declarations
	public:
		void help(); // Display Help information for Cyclops
		void error(uint8_t errorCode); // Display error provided errorCode
		void banner(uint8_t maj, uint8_t bug, uint8_t min); // Display Banner
		void bugTrackerReport(uint8_t bugVer); // Display bug tracker report
};

// TODO: This might not need to be derived, we will see..
class cycDisasm : public cyclops{

	// Public Function Declarations
  	public:
  
    		// Analysis and verification functions
    		bool checkFile(std::string fileName); // Check [FILE] Exists
    		uint8_t analyze(std::string fileName); // Analyze [FILE]


	// Public Variable Declarations
	private:
  
		// ELF related variables
    		uint8_t eiData; // Location 0x05 [EI_DATA] (1: Little Endian, 2: Big Endian)
		uint8_t eiClass; // Location 0x04 [EI_CLASS] (1: 32-bit, 2: 64-bit)
    		uint64_t eEntry; // We designate this as a 64 bit value, but if eClass is 0x01, only use lower 32
    		uint16_t mainAddr; // Used to store the address of main ((eEntry+0x28)+0xC1)
		std::string format; // File Format (Only support ELF Currently)
    		uint16_t eEntrySet; // used to set eEntry for further calculations
		uint16_t eMachineSet; // Store confirmed architecture
		std::streampos fileSize; // File Size
		
    		/*
			Location 0x07 [EI_OSABI]
			(APPLICATION BINARY INTERFACE)
			This value can range from 0x00 -> 0x12 so we will create a map to match 
			these values to their respective ABI
		*/
		std::map<uint8_t, std::string> eiOsbi{
			{0x00, "System-V"},
			{0x01, "HP-UX"},
			{0x02, "NetBSD"},
			{0x03, "Linux"},
			{0x04, "GNU Hurd"},
			{0x06, "Solaris"},
			{0x07, "AIX"},
			{0x08, "IRIX"},
			{0x09, "FreeBSD"},
			{0x0A, "True64"},
			{0x0B, "Novell Modesto"},
			{0x0C, "OpenBSD"},
			{0x0D, "OpenVMS"},
			{0x0E, "NonStop Kernel"},
			{0x0F, "AROS"},
			{0x10, "Fenix OS"},
			{0x11, "CloudABI"},  
			{0x12, "Status Technologies OpenVOS"},
		};
		/*
			Location 0x10 [e_type]
			Specifies Object File Type
			This value is 2-byte so we will compare with ET_* in our map
		*/
		std::map<uint16_t, std::string> eType{
			{ET_NONE, "ET_NONE"},
			{ET_REL, "Relocatable File"}, // Relocatable File
			{ET_EXEC, "Executable File"}, // Executable File
			{ET_DYN, "Shared Object File"}, // Shared object File
			{ET_CORE, "Core File"}, // Core File
			{ET_LOOS, "OS-Specific Range Start"}, // OS-Specifc range start
			{ET_HIOS, "OS-Specific Range End"}, // OS-Specific range end
			{ET_LOPROC, "Processor-Specific Range Start"}, // Processor-Specific range start
			{ET_HIPROC, "Processor-Specific Rnage End"}, // Processor-Specific range end
		};

		/*
			Location 0x12 [e_machine]
			Specifies the Target File Architecture
			This value is 2-bytes
		*/
		std::map<uint16_t, std::string> eMachine{
			{0x0000, "No Specific Instruction Set"},
			{0x0001, "AT&T WE 32100"},
			{0x0002, "SPARC"},
			{0x0003, "x86"},
			{0x0004, "Motorola 68000 (M68k)"},
			{0x0005, "Motorola 88000 (M88k)"},
			{0x0006, "Intel MCU"},
			{0x0007, "Intel 80860"},
			{0x0008, "MIPS"},
			{0x0009, "IBM System/370"},
			{0x000A, "MIPS RS3000 Little-Endian"},
			{0x000E, "Hewlett-Packard PA-RISC"},
			{0x0013, "Intel 80960"},
			{0x0014, "PowerPC"},
			{0x0015, "PowerPC (64-bit)"},
			{0x0016, "S390, including S390x"},
			{0x0017, "IBM SPU/SPC"},
			{0x0024, "NEC V800"},
			{0x0025, "Fujitsu FR20"},
			{0x0026, "TRW RH-32"},
			{0x0027, "Motorola RCE"},
			{0x0028, "ARM (up to ARMv7/Aarch32)"},
			{0x0029, "Digital Alpha"},
			{0x002A, "SuperH"},
			{0x002B, "SPARC Version 9"},
			{0x002C, "Siemens TriCore Embedded Processor"},
			{0x002D, "Argonaut RISC Core"},
			{0x002E, "Hitachi H8/300"},
			{0x002F, "Hitachi H8/300H"},
			{0x0030, "Hitachi H8S"},
			{0x0031, "Hitachi H8/500"},	
			{0x0032, "IA-64"},
			{0x0033, "Stanford MIPS-X"},
			{0x0034, "Motorola ColdFire"},
			{0x0035, "Motorola M68HC12"},
			{0x0036, "Fujitsu MMA Multimedia Accelerator"},
			{0x0037, "Siemens PCP"},
			{0x0038, "Sony nCPU Embedded RISC Processor"},
			{0x0039, "Denso NDR1 Microprocessor"},
			{0x003A, "Motorola Star*Core Processor"},
			{0x003B, "Toyota ME16 Processor"},
			{0x003C, "STMicroelectronics"},
			{0x003D, "Advanced Logic Corp. Tinyj Embedded Processor Family"},
			{0x003E, "AMD x86-64"},
			{0x008C, "TMS320C6000 Family"},
			{0x00AF, "MCST Elbrus e2k"},
			{0x00B7, "ARM 64-bits (ARMv8/Aarch64)"},
			{0x00F7, "Berkeley Packet Filter"},
			{0x0101, "WDC 65C816"},
		};

		// TODO: Add more file Signatures (PE, etc.)
		std::map<std::string, std::string> fileSig{
			{"7f454c46", "ELF"},
		};
  
    		// Helper variables
    		uint16_t tempBytes; // Used for a plethora of things	
		uint16_t tempBytesTwo; // Used for a plethora of things
		uint32_t tempBytesFour; // Used for a plethora of things
		uint32_t tempBytesFour_2; // Used for a plethora of things
  
    		// Capstone variables
    		cs_insn* insn; // Memory pointer for disassembled instructions
    		size_t instrCnt; // Total number of instructions disassembled
    		cs_arch arch_type; // Architecture type
    		csh capstoneHandle; // Define our Capstone Engine Handle
    		cs_mode hardwareMode; // Hardware mode of our arch
	
	// Private Function Declarations
	private:
    
    		// Disassembly Functions
		bool disassembleELF(std::string fileName, uint16_t arch, char* &data, std::streampos fSize); // Disassemble our elf file
};
