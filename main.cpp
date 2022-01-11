/* 
 * Cyclops Disassembler
 * Author: https://twitter.com/Plut0n1um1
 */

// Standard C++ Headers
#include <string>
#include <iostream>

// Cyclops Headers
#include "cyclops.hpp"

int main(int argc, const char* argv[]){

	cyclops cyc; // Create our cyclops object for access to coreutils
	cycDisasm cyc_dis; // Create our Cyclops Disassembler for access to disassembler utils

	cyc.banner(1, 1, 0); // Display our banner

	// Check how many arguments were passed
	switch(argc){

		// Invalid argc
		case 1:
			cyc.error(0);
			cyc.help();
			break;		

		// Help information (Possible error in [INIT_ARG])
		case 2:
			// User wants to hack the NSA
			if(static_cast<std::string>(argv[1]) == "-hackthensa"){
				cyc.hackthensa();
				return 0;
			}
			// User specified help argument
			if(static_cast<std::string>(argv[1]) == "-h"){
				cyc.help();
				return 0;
			}
			// User specified disassemble, but no [FILE] Provided
			if(static_cast<std::string>(argv[1]) == "-d"){
				cyc.error(0x01);
				cyc.help();
				return -1;
			}
			// User specified they want a bugTrackerReport
			if(static_cast<std::string>(argv[1]) == "-b"){
				cyc.bugTrackerReport(1); // TODO Update as more bugs come in
				return 0;
			}
			// Invalid [INIT_ARG] Display error and call cyclops::error(uint8_t)
			else{
				cyc.error(0x02);
				cyc.help();
				return -1;
			}
			break;
	
		// Disassemble [FILE]
		case 3:
			// File doesn't exist on filesystem
			if(cyc_dis.checkFile(static_cast<std::string>(argv[2])) == false){
				cyc.error(0x03);
				return -1;
			}
			
			// Step 1: Start Analyzing [FILE] 
			if(cyc_dis.analyze(static_cast<std::string>(argv[2])) != 0){
				return -1;
			}
			break;
	}
	
	return 0;
}
