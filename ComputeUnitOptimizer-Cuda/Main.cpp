#include "Timer.h"
#include "ComputeUnitOptimizer.h"
#include "Base58.h"
#include "CmdParse.h"
#include <fstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <cassert>
#include <algorithm>
#ifndef WIN64
#include <signal.h>
#include <unistd.h>
#endif

#define RELEASE "1.08"

// Global flag to signal threads to exit gracefully.
volatile bool should_exit = false;

void printUsage()
{
	printf("ComputeUnitOptimizer-Cuda v%s\n", RELEASE);
	printf("Usage: ComputeUnitOptimizer [OPTIONS...] [TARGET]\n\n");
	printf("TARGET is a required argument, which is either a single address/xpoint or a file.\n\n");
	printf("Options:\n");
	printf(" -h, --help                               Show this help message.\n");
	printf(" -v, --version                            Show version information.\n");
	printf(" -c, --check                              Run internal self-tests for math libraries.\n");
	printf(" -l, --list                               List available CUDA devices.\n");
	printf("\nSearch Mode:\n");
	printf(" -m, --mode MODE                          Search mode (required). MODE can be:\n");
	printf("                                            ADDRESS:   Find a single Bitcoin/Ethereum address.\n");
	printf("                                            ADDRESSES: Find any address from a binary file.\n");
	printf("                                            XPOINT:    Find a single Bitcoin public key X-coordinate.\n");
	printf("                                            XPOINTS:   Find any X-point from a binary file.\n");
	printf(" --coin TYPE                              Coin type (BTC or ETH). Default is BTC.\n");
	printf(" -i, --in FILE                            Input file for ADDRESSES or XPOINTS mode.\n");
	printf("                                            The file must be a sorted binary list of hashes.\n");
	printf("\nPerformance:\n");
	printf(" -t, --thread N                           Number of CPU threads. Default is all available cores.\n");
	printf(" -g, --gpu                                Enable GPU acceleration. Disables CPU threads by default.\n");
	printf(" --gpui IDS                               Comma-separated list of GPU device IDs to use (e.g., 0,1).\n");
	printf(" --gpux GRID                              Comma-separated grid/block dimensions (e.g., 1024,512).\n");
	printf("\nKeyspace:\n");
	printf(" --range START:END                        Specify a hexadecimal keyspace range to search.\n");
	printf(" -r, --rkey MKEYS                         Randomize search starting point every MKEYS million keys.\n");
	printf("\nOutput:\n");
	printf(" -o, --out FILE                           Output file for found keys. Default is 'Found.txt'.\n");
}

// Safely parses a string of comma-separated integers.
void parseInts(const std::string& name, std::vector<int>& tokens, const std::string& text, char sep)
{
	tokens.clear();
	size_t start = 0;
	size_t end = 0;
	while ((end = text.find(sep, start)) != std::string::npos) {
		try {
			tokens.push_back(std::stoi(text.substr(start, end - start)));
		} catch (const std::exception&) {
			fprintf(stderr, "Error: Invalid number in %s argument: %s\n", name.c_str(), text.c_str());
			exit(1);
		}
		start = end + 1;
	}
	try {
		tokens.push_back(std::stoi(text.substr(start)));
	} catch (const std::exception&) {
		fprintf(stderr, "Error: Invalid number in %s argument: %s\n", name.c_str(), text.c_str());
		exit(1);
	}
}

int parseSearchMode(const std::string& s)
{
	std::string stype = s;
	std::transform(stype.begin(), stype.end(), stype.begin(), ::tolower);
	if (stype == "address")   return SEARCH_MODE_SA;
	if (stype == "addresses") return SEARCH_MODE_MA;
	if (stype == "xpoint")    return SEARCH_MODE_SX;
	if (stype == "xpoints")   return SEARCH_MODE_MX;
	
	fprintf(stderr, "Error: Invalid search mode '%s'\n", s.c_str());
	exit(1);
}

int parseCoinType(const std::string& s)
{
	std::string stype = s;
	std::transform(stype.begin(), stype.end(), stype.begin(), ::tolower);
	if (stype == "btc") return COIN_BTC;
	if (stype == "eth") return COIN_ETH;

	fprintf(stderr, "Error: Invalid coin type '%s'\n", s.c_str());
	exit(1);
}

void parseRange(const std::string& s, Int& start, Int& end)
{
	size_t pos = s.find(':');
	if (pos == std::string::npos) { // No colon, treat as START
		start.SetBase16(s.c_str());
		end.Set(&start);
		end.Add(0xFFFFFFFFFFFFULL); // Default to a large, but finite range
	} else {
		std::string left = s.substr(0, pos);
		start.SetBase16(left.empty() ? "1" : left.c_str());
		
		std::string right = s.substr(pos + 1);
		if (right[0] == '+') { // Relative count
			Int count;
			count.SetBase16(right.substr(1).c_str());
			end.Set(&start);
			end.Add(&count);
		} else { // Absolute end
			end.SetBase16(right.c_str());
		}
	}
}

#ifdef WIN64
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	if (fdwCtrlType == CTRL_C_EVENT) {
		should_exit = true;
		// Give threads a moment to shut down gracefully
		Sleep(2000);
		return TRUE;
	}
	return FALSE;
}
#else
void CtrlHandler(int signum) {
	(void)signum; // Unused parameter
	should_exit = true;
	// Give threads a moment to shut down gracefully
	sleep(2);
	// Re-raise signal to ensure clean exit
	signal(SIGINT, SIG_DFL);
	raise(SIGINT);
}
#endif

void runSelfCheck() {
	printf("ComputeUnitOptimizer-Cuda v%s\n\n", RELEASE);
	printf("Checking Secp256K1 implementation...\n");
	Secp256K1 secp;
	secp.Init();
	secp.Check();
	printf("\nChecking large integer math library...\n");
	Int K;
	K.SetBase16("3EF7CEF65557B61DC4FF2313D0049C584017659A32B002C105D04A19DA52CB47");
	K.Check();
	printf("\nChecks passed successfully.\n");
}


int main(int argc, char** argv)
{
	Timer::Init();
	rseed(Timer::getSeed32());

	// --- Default Configuration ---
	int compMode = SEARCH_COMPRESSED;
	int searchMode = -1;
	int coinType = COIN_BTC;
	bool gpuEnable = false;
	int nbCPUThread = Timer::getCoreNumber();
	std::vector<int> gpuId = {0};
	std::vector<int> gridSize;
	std::string outputFile = "Found.txt";
	std::string inputFile = "";
	Int rangeStart, rangeEnd;
	rangeStart.SetInt32(0);
	rangeEnd.SetInt32(0);
	uint64_t rKey = 0;
	bool useSSE = true;

	// --- Command Line Parsing ---
	if (argc == 1) {
		printUsage();
		return 0;
	}
	
	CmdParse parser;
	parser.add("-h", "--help", false);
	parser.add("-v", "--version", false);
	parser.add("-c", "--check", false);
	parser.add("-l", "--list", false);
	parser.add("-u", "--uncomp", false);
	parser.add("-b", "--both", false);
	parser.add("-g", "--gpu", false);
	parser.add("", "--gpui", true);
	parser.add("", "--gpux", true);
	parser.add("-t", "--thread", true);
	parser.add("-i", "--in", true);
	parser.add("-o", "--out", true);
	parser.add("-m", "--mode", true);
	parser.add("", "--coin", true);
	parser.add("", "--range", true);
	parser.add("-r", "--rkey", true);

	try {
		parser.parse(argc, argv);
	} catch (const std::string& err) {
		fprintf(stderr, "Error: %s\n", err.c_str());
		return 1;
	}

	for (const auto& optArg : parser.getArgs()) {
		if (optArg.equals("-h", "--help")) { printUsage(); return 0; }
		if (optArg.equals("-v", "--version")) { printf("ComputeUnitOptimizer-Cuda v%s\n", RELEASE); return 0; }
		if (optArg.equals("-c", "--check")) { runSelfCheck(); return 0; }
		if (optArg.equals("-l", "--list")) {
			#ifdef WITHGPU
				GPUEngine::PrintCudaInfo();
			#else
				printf("GPU support not compiled. Use 'make gpu=1' to enable.\n");
			#endif
			return 0;
		}
		if (optArg.equals("-u", "--uncomp")) compMode = SEARCH_UNCOMPRESSED;
		if (optArg.equals("-b", "--both")) compMode = SEARCH_BOTH;
		if (optArg.equals("-g", "--gpu")) { gpuEnable = true; nbCPUThread = 0; }
		if (optArg.equals("-t", "--thread")) nbCPUThread = std::stoi(optArg.arg);
		if (optArg.equals("", "--gpui")) parseInts("--gpui", gpuId, optArg.arg, ',');
		if (optArg.equals("", "--gpux")) parseInts("--gpux", gridSize, optArg.arg, ',');
		if (optArg.equals("-i", "--in")) inputFile = optArg.arg;
		if (optArg.equals("-o", "--out")) outputFile = optArg.arg;
		if (optArg.equals("-m", "--mode")) searchMode = parseSearchMode(optArg.arg);
		if (optArg.equals("", "--coin")) coinType = parseCoinType(optArg.arg);
		if (optArg.equals("", "--range")) parseRange(optArg.arg, rangeStart, rangeEnd);
		if (optArg.equals("-r", "--rkey")) rKey = std::stoull(optArg.arg);
	}

	// --- Validate Configuration ---
	if (searchMode == -1) {
		fprintf(stderr, "Error: Search mode (-m) is a required argument.\n");
		return 1;
	}
	
	if (coinType == COIN_ETH) {
		if (searchMode == SEARCH_MODE_SX || searchMode == SEARCH_MODE_MX) {
			fprintf(stderr, "Error: XPOINT search modes are not applicable to Ethereum.\n");
			return 1;
		}
		compMode = SEARCH_UNCOMPRESSED; // ETH addresses only use uncompressed keys
		useSSE = false;
	}

	if (searchMode == SEARCH_MODE_MX || searchMode == SEARCH_MODE_SX) {
		useSSE = false; // SSE is for hashing, not X-point comparison
	}

	std::vector<std::string> operands = parser.getOperands();
	std::vector<unsigned char> hashORxpoint;

	if (searchMode == SEARCH_MODE_SA || searchMode == SEARCH_MODE_SX) {
		if (operands.size() != 1) {
			fprintf(stderr, "Error: Single address/xpoint search requires exactly one target argument.\n");
			return 1;
		}
		if (searchMode == SEARCH_MODE_SA) { // Single Address
			std::string address = operands[0];
			if (coinType == COIN_BTC) {
				if (!DecodeBase58(address, hashORxpoint) || hashORxpoint.size() != 25) {
					fprintf(stderr, "Error: Invalid Bitcoin address format.\n"); return 1;
				}
				hashORxpoint.erase(hashORxpoint.begin()); // Remove version byte
				hashORxpoint.erase(hashORxpoint.begin() + 20, hashORxpoint.end()); // Remove checksum
			} else { // Ethereum
				if (address.length() != 42 || address.substr(0, 2) != "0x") {
					fprintf(stderr, "Error: Invalid Ethereum address format.\n"); return 1;
				}
				for (size_t i = 2; i < address.length(); i += 2) {
					hashORxpoint.push_back(std::stoi(address.substr(i, 2), nullptr, 16));
				}
			}
			assert(hashORxpoint.size() == 20);
		} else { // Single X-Point
			Int xpoint;
			xpoint.SetBase16(operands[0].c_str());
			hashORxpoint.resize(32);
			xpoint.Get32Bytes(hashORxpoint.data());
		}
	} else { // Multi-address/xpoint from file
		if (!inputFile.empty()) {
			// File is handled inside the ComputeUnitOptimizer constructor
		} else if (operands.size() == 1) {
			inputFile = operands[0];
		} else {
			fprintf(stderr, "Error: File-based search requires an input file specified with -i or as the final argument.\n");
			return 1;
		}
	}
	
	if (rangeStart.IsZero()) {
		fprintf(stderr, "Error: A search range must be specified with --range.\n");
		return 1;
	}

	if (gridSize.size() > 0 && gridSize.size() != gpuId.size() * 2) {
		fprintf(stderr, "Error: GPU grid size list must contain two values (X,Y) for each GPU ID.\n");
		return 1;
	}
	if (gpuEnable && nbCPUThread > 0) {
		printf("Warning: Both CPU and GPU threads were specified. Disabling CPU threads to prioritize GPU.\n");
		nbCPUThread = 0;
	}


	// --- Print Configuration Summary ---
	printf("\nComputeUnitOptimizer-Cuda v%s\n\n", RELEASE);
	printf("COIN TYPE    : %s\n", coinType == COIN_BTC ? "Bitcoin" : "Ethereum");
	printf("SEARCH MODE  : %s\n", searchMode == SEARCH_MODE_MA ? "Multi Address" : searchMode == SEARCH_MODE_SA ? "Single Address" : searchMode == SEARCH_MODE_MX ? "Multi X-Point" : "Single X-Point");
	if (coinType == COIN_BTC) printf("COMPRESSION  : %s\n", compMode == SEARCH_COMPRESSED ? "Compressed" : (compMode == SEARCH_UNCOMPRESSED ? "Uncompressed" : "Both"));
	printf("DEVICE(S)    : %s\n", gpuEnable ? "GPU" : "CPU");
	if (gpuEnable) {
		printf("GPU IDs      : "); for(size_t i=0; i<gpuId.size(); ++i) printf("%d%s", gpuId[i], i+1<gpuId.size()?", ":""); printf("\n");
	} else {
		printf("CPU THREADS  : %d\n", nbCPUThread);
	}
	printf("SSE          : %s\n", useSSE ? "Enabled" : "Disabled");

	// --- Initialize and Run Search ---
	#ifdef WIN64
		SetConsoleCtrlHandler(CtrlHandler, TRUE);
	#else
		signal(SIGINT, CtrlHandler);
	#endif

	ComputeUnitOptimizer* finder = nullptr;

	try {
		if (searchMode == SEARCH_MODE_MA || searchMode == SEARCH_MODE_MX) {
			finder = new ComputeUnitOptimizer(inputFile, compMode, searchMode, coinType, gpuEnable, outputFile, useSSE,
				0, rKey, rangeStart.GetBase16(), rangeEnd.GetBase16(), should_exit);
		} else {
			finder = new ComputeUnitOptimizer(hashORxpoint, compMode, searchMode, coinType, gpuEnable, outputFile, useSSE,
				0, rKey, rangeStart.GetBase16(), rangeEnd.GetBase16(), should_exit);
		}
		
		finder->Search(nbCPUThread, gpuId, gridSize, should_exit);

	} catch (const std::runtime_error& e) {
		fprintf(stderr, "\nA runtime error occurred: %s\n", e.what());
		delete finder;
		return 1;
	}

	delete finder;
	printf("\n\nSearch complete. Bye!\n");
	return 0;
}
