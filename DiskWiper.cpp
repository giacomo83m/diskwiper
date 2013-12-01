/*
 * DiskWiper,IRT Forensic Tool, 2013
 * Author: Giacomo Milani <giacomo83m@gmail.com>
 *
 * DiskWiper is posix (developed on osx) disk cleaning/erasing tool.
 *
 * The main objective of the software is to develop an opensource tool that
 * is compliant to wiping baseline of different countries.
 * It supports verbose logging so it can be used to produce a full evidence
 * of secure erasing process.
 *
 * OSX Installation ( you require Xcode ):
 *  $ g++ DiskWiper.cpp -o DiskWiper
 *  $ sudo cp DiskWiper /usr/sbin/
 *
 * Linux Installation ( you require devtools ):
 *  TODO
 *
 * Usage:
 *  $ sudo ./DiskWiper -d <DEVICE> -p <POLICY> -r <REPORT.LOG>
 *
 * Wiping scheme supported/planned:
 * - Fast (1 pass)
 *    The fastest wiping scheme. Your data is overwritten with zeroes.
 * - British HMG IS5 (Baseline) (1 pass)
 *    Your data is overwritten with zeroes with verification.
 * - Russian GOST P50739-95 (2 passes)
 *    GOST P50739-95 wiping scheme calls for a single pass of zeroes followed
 *    by a single pass of random byte.
 * - British HMG IS5 (Enhanced) (3 passes)
 *    British HMG IS5 (Enhanced) is a three pass overwriting algorithm:
 *    first pass - with zeroes, second pass - with ones and the last pass
 *    with random bytes (last pass is verified).
 * - US Army AR380-19 (3 passes)
 *    AR380-19 is data wiping scheme specified and published by the U.S. Army.
 *    AR380-19 is three pass overwriting algorithm: first pass - with random
 *    bytes, second and third passes with certain bytes and with its
 *    compliment (with last pass verification) .
 * - US Department of Defense DoD 5220.22-M (3 passes)
 *    DoD 5220.22-M is three pass overwriting algorithm: first pass
 *    with zeroes, second pass with ones and the last pass with random bytes.
 *    With all passes verification.
 * - the US Department of Defense DoD 5220.22-M (E) (3 passes)
 *    DoD 5220.22-M (E) is three pass overwriting algorithm: first pass -
 *    with certain bytes, second pass - with its complement and the last pass -  
 *    with random bytes.
 * - the US Department of Defense DoD 5220.22-M(ECE) (7 passes)
 *    DoD 5220.22-M(ECE) is seven pass overwriting algorithm: first and second
 *    passes - with certain bytes and with its compliment, then two passes with  
 *    random character, then two passes with character and its complement
 *    and the last pass - with random character.
 * - German VSITR (7 passes)
 *    The German standard calls for each sector to be overwritten with three
 *    alternating patterns of zeroes and ones and in the last pass with chars.
 * - Bruce Schneier (7 passes)
 *    The Bruce Schneier wiping algorithm has seven passes: first pass -
 *    with ones, the second pass - with zeroes and then five times with
 *    random characters.
 * - Peter Gutmann (35 passes)
 *    Peter Gutmann wiping algorithm has 35 passes.
 *
 * OpenSource License: BSD
 * 
 * Copyright 2013 Milani Giacomo. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted 
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions an
 * the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
 * and the following disclaimer in the documentation and/or other materials provided with the 
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE FREEBSD PROJECT "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE FREEBSD PROJECT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN 
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define VERSION "0.2"
#define CREDITS "Giacomo Milani"

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <ctime>
#include <cstdarg>

#define E_SUCCESS 0
#define E_FAILURE 1
#define E_CONTINUE 2

// Rules for space overwriting
typedef struct OverWriteRule_s {
	const char *data;
	unsigned int datalen;
	unsigned int random;
	unsigned int _reserved;
} OverWriteRule;

/*********************************************************************
* Peter Gutmann Method
* Secure Deletion of Data from Magnetic 
* http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
*********************************************************************/
OverWriteRule r_Gutmann[] = {
	{0,0,1,0},
	{0,0,1,0},
	{0,0,1,0},
	{0,0,1,0},
	{"\x55",1,0,0}, 	// 	01010101
	{"\xAA",1,0,0}, 	//	10101010
	{"\x92\x49\x24",3,0,0}, //	10010010 01001001 00100100
	{"\x49\x24\x92",3,0,0}, //	01001001 00100100 10010010
	{"\x24\x92\x49",3,0,0}, //	00100100 10010010 01001001
	{"\x00",1,0,0},
	{"\x11",1,0,0},
	{"\x22",1,0,0},
	{"\x33",1,0,0},
	{"\x44",1,0,0},
	{"\x55",1,0,0},
	{"\x66",1,0,0},
	{"\x77",1,0,0},
	{"\x88",1,0,0},
	{"\x99",1,0,0},
	{"\xAA",1,0,0},
	{"\xBB",1,0,0},
	{"\xCC",1,0,0},
	{"\xDD",1,0,0},
	{"\xEE",1,0,0},
	{"\xFF",1,0,0},
	{"\x92\x49\x24",3,0,0}, // 	10010010 01001001 00100100
	{"\x49\x24\x92",3,0,0}, //	01001001 00100100 10010010
	{"\x24\x92\x49",3,0,0}, //	00100100 10010010 01001001
	{"\x6D\xB6\xDB",3,0,0}, //	01101101 10110110 11011011
	{"\xB6\xDB\x6D",3,0,0}, //	10110110 11011011 01101101
	{"\xDB\x92\x49",3,0,0}, //	11011011 01101101 10110110
	{0,0,1,0},
	{0,0,1,0},
	{0,0,1,0},
	{0,0,1,0},
};

/*********************************************************************
* Fast Method
* Data is overwritten with zeroes
*********************************************************************/
OverWriteRule r_Fast[] = {
	{"\x00",1,0,0},
};

/*********************************************************************
* Russian GOST P50739-95 (2 passes)
* GOST P50739-95 wiping scheme calls for a single pass of zeroes 
* followed by a single pass of random byte.
*********************************************************************/
OverWriteRule r_Gost[] = {
	{"\x00",1,0,0},
	{0,0,1,0},
};

/*********************************************************************
* US Department of Defense DoD 5220.22-M (3 passes)
* DoD 5220.22-M is three pass overwriting algorithm: first pass
* with zeroes, second pass with ones and the last pass with random bytes.
* With all passes verification.
*********************************************************************/
OverWriteRule r_UsDod5220_22_M[] = {
	{"\x00",1,0,0},
	{"\xFF",1,0,0},
	{0,0,1,0},
};

/*********************************************************************
* German VSITR (7 passes)
* The German standard calls for each sector to be overwritten with three
* alternating patterns of zeroes and ones and in the last pass with 10101010.
*********************************************************************/
OverWriteRule r_VSITR[] = {
	{"\x00",1,0,0},
	{"\xFF",1,0,0},
	{"\x00",1,0,0},
	{"\xFF",1,0,0},
	{"\x00",1,0,0},
	{"\xFF",1,0,0},
	{"\xAA",1,0,0}, 	//       10101010
};

typedef struct WipePolicy_s {
	const char *name;
	int passes;
	OverWriteRule *rules;
} WipePolicy;

#define COUNT_PASSES(x) sizeof(x)/sizeof(OverWriteRule)

WipePolicy FastPolicy = { "Fast",COUNT_PASSES(r_Fast),r_Fast };
WipePolicy GostPolicy = { "Russian GOST P50739-95",COUNT_PASSES(r_Gost),r_Gost};
WipePolicy PeterGutmannPolicy = { "Peter Gutmann",COUNT_PASSES(r_Gutmann),r_Gutmann };
WipePolicy DOD522022MPolicy = { "US DOD 5220.22-M",COUNT_PASSES(r_UsDod5220_22_M),r_UsDod5220_22_M};
WipePolicy VsitrPolicy = { "German VSITR",COUNT_PASSES(r_VSITR),r_VSITR};

WipePolicy wPolicies[] = {
	FastPolicy,
	GostPolicy,
    DOD522022MPolicy,
	VsitrPolicy,
	PeterGutmannPolicy
};
#define N_POLICIES sizeof(wPolicies)/sizeof(WipePolicy)

class ReportLog {
	std::ofstream fd;
	bool _enabled;
	bool _silent;
public:
	ReportLog() {
		_silent = false;
		_enabled = false;
	}

	bool SetQuite(bool flag) 
	{
		_silent = flag;
		return _silent;
	}

	void Open(const char *name) {
		fd.open(name,std::fstream::app);
		_enabled = true;
	}
	void Close() {
		fd.close();
	}

	void Log(const char *fmt,...) {
		std::time_t rawtime;
		std::tm* timeinfo;
		char tbuffer[80] = { 0x00 };
		char mbuffer[1024] = { 0x00 };

		if ( _silent == true && _enabled == false )
			return;	

		std::time(&rawtime);
		// Zulu Time
		timeinfo = std::gmtime(&rawtime);

		// ISO8601 Format
		std::strftime(tbuffer,80,"%Y-%m-%d-%H-%M-%SZ",timeinfo);

		// Format Message
		va_list args;
		va_start (args, fmt);
		vsnprintf (mbuffer,1024,fmt,args);

		if ( _silent == false)
			std::cout << tbuffer << " " << mbuffer << std::endl;

		// join Date,Msg and write the result to logfile
		if ( _enabled )
			fd << tbuffer << " " << mbuffer << std::endl;		

		va_end (args);
	}
};

/**********************************************************************************
* Wrap OS Dependent functions to easly port the code to different platforms
**********************************************************************************/
#ifdef __APPLE__ || define(linux)
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <errno.h>
#else
#error "Platform not supported"
#endif

namespace OS {
	int AccessFile(const char *path, int mode) {
		int ret;
		ret = access(path,mode);		
		if ( ret < 0 && errno == ENOENT )
		{
			std::ofstream testfd(path,std::fstream::out);
			if ( testfd.is_open() == true )
				ret = 0;
			testfd.close();
		}
		return ret;
	}
	void GetRandomData(char *buffer,unsigned int sz) 
	{
		std::ifstream rfd("/dev/random",std::fstream::in);
		rfd.read(buffer,sz);
		rfd.close();
	}

	unsigned int GetDeviceSize(const char *device)
	{
		int fd;
		unsigned int size = 0;
		unsigned int block_size = 0;
		unsigned int block_count = 0;

		fd = open(device,O_RDONLY);
		if ( fd > 0 ) {
			struct stat st;
			fstat(fd,&st);
			if ( st.st_mode & S_IFBLK ) 
			{
#ifdef __APPLE__
				ioctl(fd, DKIOCGETPHYSICALBLOCKSIZE, &block_size);
				ioctl(fd, DKIOCGETBLOCKCOUNT, &block_count);
				size = block_count * block_size;
#elif define(linux)
				ioctl(fd, BLKPBSZGET, &block_size);
				size = block_size * 512;
#else
				size = 0; // ERR
#endif
			}
			else {
				size = st.st_size;
			}
		}

		return size;
	}

	int AccessOK = 0;
	namespace Perm {
		int R = R_OK;
		int W = W_OK;
		int X = X_OK;
		int F = F_OK;
	};
};

/**********************************************************************************
* DiskWiper
* Main Class
**********************************************************************************/
class DiskWiper
{
	std::string _PolicySelection;
	std::string _DeviceName;
	std::string _ReportFile;
	std::string _ShowDetails;
	bool _Quite;
	bool _Help;
	bool _Show;
	bool _Policy;
	bool _Device;
	bool _Reporting;
	int _ValidPolicySel;

	int Usage() {
		std::cerr << "DiskWiper, " << CREDITS << ", " << VERSION;
		std::cerr << std::endl << std::endl;
		std::cerr << "./diskwiper [-r <report.log>] -p <policy number> -d </dev/hdX>" << std::endl;
		std::cerr << "-h\t\tthis help page" << std::endl;
		std::cerr << "-s <dgt>\tshow details about a <dgt> wipe policy number" << std::endl;
		std::cerr << "-p <dgt>\tselect <dgt> policy number for the wipe process" << std::endl;
		std::cerr << "-r <file>\twrite a report log to file" << std::endl;
		std::cerr << "-d <dev>\tdisk divice to wipe" << std::endl;

		std::cerr << std::endl << "Wipe Policies: " << std::endl;
		for ( int i = 0; i < N_POLICIES ; i++ ) {
			WipePolicy *Pol = &wPolicies[i];
			std::cerr << i+1 << ") " << Pol->name << " ( " << Pol->passes << " passes ) " << std::endl;
		}
		std::cerr << std::endl;

		return E_FAILURE;
	}

	int ShowPolicyDetail (WipePolicy *policy ) {
		std::cerr << "Policy: " << policy->name << std::endl;
		std::cerr << "Passes: " << policy->passes << std::endl;
		for ( int i = 0; i <  policy->passes; i++ ) {
			OverWriteRule *rule = &policy->rules[i];
			if ( rule->random ) 
				std::cerr << "Step " << i+1 << ": random bytes" << std::endl;
			else 
			{
				std::stringstream tmp;

				for ( int k = 0; k< rule->datalen; k++ )
					tmp << std::hex << std::uppercase << (rule->data[k] & 0xFF) << " ";

				tmp << ": ";
				for ( int k = 0; k< rule->datalen; k++ )
				{
					unsigned char raw = (rule->data[k] & 0xFF);
					for ( int z = 0; z < 8; z++ ) tmp << ((raw >> z) & 0x1);
					tmp << " ";
				}

				std::cerr << "Step " << i+1 << ": " << tmp.str() << std::endl;
			}
		}
		std::cerr << std::endl;
	}

	int ParseOption (int ac,char **av) {
		int cmd;

		while ( ( cmd = getopt(ac,av,"hs:p:d:r:q") ) != EOF ) {
			switch ( cmd ) {
				case 'h':
					_Help = true;
					break;
				case 'q':
					_Quite = true;
					break;
				case 's':
					_Show = true;
					_ShowDetails.assign ( optarg );
					break;
				case 'p':
					_Policy = true;
					_PolicySelection.assign ( optarg );
					break;
				case 'd':
					_Device = true;
					_DeviceName.assign ( optarg );
					break;
				case 'r':
					_Reporting = true;
					_ReportFile.assign ( optarg );
					break;
				default:
					break;
			}
		} 
	
		if ( _Help ) 
			return Usage();
		
		if ( _Show )
		{
			int sel = atoi(_ShowDetails.c_str());
			if ( sel < 1 || sel > N_POLICIES )
			{
				std::cerr << "Bad Option (-s): Invalid Policy Number" << std::endl;
				return E_FAILURE;
			} 
			return ShowPolicyDetail (&wPolicies[sel-1]); 
		}

		if ( _Policy ) 
		{
			int sel = atoi(_PolicySelection.c_str());
			if ( sel < 1 || sel > N_POLICIES )
			{
				std::cerr << "Bad Option (-p): Invalid Policy Number" << std::endl;
				return E_FAILURE;
			}
			if ( !_Device )
			{
				std::cerr << "Bad Parameters: you have select valid policy (-p) but a valid device (-d) is missing" << std::endl;
				return E_FAILURE;
			}
			_ValidPolicySel = sel-1;
		}
		if ( _Device )
		{
			if ( OS::AccessFile(_DeviceName.c_str(),OS::Perm::W) != OS::AccessOK ) 
			{
				std::cerr << "Bad Device File Access: Check file path and permissions: " << _DeviceName << std::endl;
				return E_FAILURE;
			}
			if ( !_Policy ) 
			{
				std::cerr << "Bad Parameters: you have select a valid device name (-d) but a valid policy (-p) is missing" << std::endl;
				return E_FAILURE;
			}
		}
		if ( _Reporting ) 
		{
			if ( OS::AccessFile(_ReportFile.c_str(),OS::Perm::W) != OS::AccessOK )
			{
				std::cerr << "Bad Report File Access: Check path and permissions: " << _ReportFile << std::endl;
				return E_FAILURE;
			}
		}

		if ( !_Device || !_Policy )
		{
			std::cerr << "Please read diskwiper inline help: ./diskwiper -h" << std::endl;
			return E_FAILURE;
		}

		return E_CONTINUE;
	}

	void FillBlock(char *owBlock, OverWriteRule *rules) {
		if ( !rules->random ) {
			// Data from Policy
			for ( int b = 0; b < blockSize; b+= rules->datalen ) {
				for ( int dl = 0; dl < rules->datalen; dl++ ) {
					owBlock[b+dl] = rules->data[dl];
				}
			}	
		}
		else {
			// Data from Random pool
			OS::GetRandomData(owBlock,blockSize);
		}
	}

public:
	DiskWiper() {
                _Help = false;
                _Show = false;
                _Policy = false;
                _Device = false;
                _Reporting = false;
		_Quite = false;

                _PolicySelection.erase();
                _DeviceName.erase();
                _ReportFile.erase();
                _ShowDetails.erase();
        }

	// 3*1024*32. DiskWiper use a size mutiple of three to be aligned even using Gutmann Method
	static const int blockSize = 98304; 

	int main (int argc,char **argv) 
	{
		int ret;
		unsigned int size;

		ret = ParseOption (argc,argv);
		if ( ret != E_CONTINUE )
			return ret;

		ReportLog Log;
		if ( _Reporting )
			Log.Open(_ReportFile.c_str());
		if ( _Quite )
			Log.SetQuite(true);

		Log.Log("DiskWiper session start");
		Log.Log("WipePolicy Selected: %s",wPolicies[_ValidPolicySel].name);
		Log.Log("Passes: %d",wPolicies[_ValidPolicySel].passes);
		Log.Log("Target device: %s",_DeviceName.c_str());
		Log.Log("device: %s",_DeviceName.c_str());

		size = OS::GetDeviceSize(_DeviceName.c_str());
		Log.Log("Device/File Size: %lu",size);
		if ( size == 0 )
		{
			Log.Log("Invalid Disk/File Size");
			Log.Log("DiskWiper session aborted");
			return E_FAILURE;
		}

		std::ofstream devfd(_DeviceName.c_str());
		char owBlock[blockSize];

		for ( int step = 0; step < wPolicies[_ValidPolicySel].passes; step++ )
		{
			OverWriteRule *rules = &wPolicies[_ValidPolicySel].rules[step];
			devfd.seekp(0);

			if ( !rules->random )
				Log.Log("Building overwrite block for step %d",step);
			else
				Log.Log("Scheduling random overwrite block for step %d",step);

			Log.Log("Step %d: start",step);

			// always initialize overwrite block
			FillBlock(owBlock,rules);

			for ( unsigned int cs = 1; cs <(size/blockSize); cs++ )
			{
				// if it's a random pass, diskwiper will recompute random bytes per cycle 
				if ( rules->random ) FillBlock(owBlock,rules);
				devfd.write((const char*)owBlock, blockSize );
			}
            
			for ( unsigned int cb = 0; cb < (size%blockSize); cb++ )
			{
				if ( rules->random ) FillBlock(owBlock,rules);
				devfd.write((const char*)owBlock,1);;
			}

			Log.Log("Step %d: done",step);
		}

		devfd.close();

		Log.Log("DiskWiper session done");
		Log.Log("----------------------");

		return E_SUCCESS;
	}
};

int main(int argc,char **argv) {
	try {
		DiskWiper dw;
		return dw.main( argc, argv );
	} 
	catch ( ... ) {
		std::cerr << "Unhandled Error occured" << std::endl;
	}	

	return E_FAILURE;
}
