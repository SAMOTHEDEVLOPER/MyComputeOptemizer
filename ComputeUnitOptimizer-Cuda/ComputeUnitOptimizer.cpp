#include "ComputeUnitOptimizer.h"
#include "GmpUtil.h"
#include "Base58.h"
#include "hash/sha256.h"
#include "hash/keccak160.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <vector> // Added for std::vector in constructor
#include <string> // Added for std::string

#ifndef WIN64
#include <pthread.h>
#endif

//using namespace std;

Point Gn[CPU_GRP_SIZE / 2];
Point _2Gn;

// ----------------------------------------------------------------------------
// Static helper function to convert bytes to a hex prefix string
std::string ComputeUnitOptimizer::BytesToHexPrefix(const unsigned char* bytes, size_t num_bytes_for_prefix) {
    std::string hex_str;
    hex_str.reserve(num_bytes_for_prefix * 2);
    char tmp[3]; // For "%02X"
    for (size_t i = 0; i < num_bytes_for_prefix; ++i) {
        sprintf(tmp, "%02X", bytes[i]);
        hex_str.append(tmp);
    }
    return hex_str;
}
// ----------------------------------------------------------------------------

ComputeUnitOptimizer::ComputeUnitOptimizer(const std::string& inputFile, int compMode, int searchMode, int coinType, bool useGpu,
	const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->inputFile = inputFile;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->lastrKey = 0;

    // Initialize prefix search related members (default to off for file mode)
    this->performPrefixSearch = false;
    this->targetHexPrefix = "";
    // this->nbPrefixFound = 0; // Optional: if you add a counter for prefix matches

	secp = new Secp256K1();
	secp->Init();

	// load file
	FILE* wfd;
	uint64_t N = 0;

	wfd = fopen(this->inputFile.c_str(), "rb");
	if (!wfd) {
		printf("%s can not open\n", this->inputFile.c_str());
		exit(1);
	}

#ifdef WIN64
	_fseeki64(wfd, 0, SEEK_END);
	N = _ftelli64(wfd);
#else
	fseek(wfd, 0, SEEK_END);
	N = ftell(wfd);
#endif

	int K_LENGTH = 20;
	if (this->searchMode == (int)SEARCH_MODE_MX)
		K_LENGTH = 32;

	N = N / K_LENGTH;
	rewind(wfd);

	DATA = (uint8_t*)malloc(N * K_LENGTH);
	memset(DATA, 0, N * K_LENGTH);

	uint8_t* buf = (uint8_t*)malloc(K_LENGTH);;

	bloom = new Bloom(2 * N, 0.000001);

	uint64_t percent = (N - 1) / 100;
	uint64_t i = 0;
	printf("\n");
	while (i < N && !should_exit) {
		memset(buf, 0, K_LENGTH);
		memset(DATA + (i * K_LENGTH), 0, K_LENGTH);
		if (fread(buf, 1, K_LENGTH, wfd) == K_LENGTH) {
			bloom->add(buf, K_LENGTH);
			memcpy(DATA + (i * K_LENGTH), buf, K_LENGTH);
			if ((percent != 0) && i % percent == 0) {
				printf("\rLoading      : %llu %%", (i / percent));
				fflush(stdout);
			}
		}
		i++;
	}
	fclose(wfd);
	free(buf);

	if (should_exit) {
		delete secp;
		delete bloom;
		if (DATA)
			free(DATA);
		exit(0);
	}

	BLOOM_N = bloom->get_bytes();
	TOTAL_COUNT = N;
	targetCounter = i; // This should be maxFound passed from main, or N if searching whole file.
                      // For prefix, targetCounter might behave differently or be ignored.
	if (coinType == COIN_BTC) {
		if (searchMode == (int)SEARCH_MODE_MA)
			printf("Loaded       : %s Bitcoin addresses\n", formatThousands(i).c_str());
		else if (searchMode == (int)SEARCH_MODE_MX)
			printf("Loaded       : %s Bitcoin xpoints\n", formatThousands(i).c_str());
	}
	else {
		printf("Loaded       : %s Ethereum addresses\n", formatThousands(i).c_str());
	}

	printf("\n");

	bloom->print();
	printf("\n");

	InitGenratorTable();

}

// ----------------------------------------------------------------------------

ComputeUnitOptimizer::ComputeUnitOptimizer(const std::vector<unsigned char>& hashORxpoint, int compMode, int searchMode, int coinType,
	bool useGpu, const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->targetCounter = 1; // For single address/xpoint, we expect 1 full match.
	this->lastrKey = 0;

	secp = new Secp256K1();
	secp->Init();

    // Initialize prefix search related members
    this->performPrefixSearch = false;
    this->targetHexPrefix = "";
    // this->nbPrefixFound = 0; // Optional: if you add a counter

	if (this->searchMode == (int)SEARCH_MODE_SA) { // Single Address
		assert(hashORxpoint.size() == 20);
		for (size_t i = 0; i < hashORxpoint.size(); i++) {
			((uint8_t*)hash160Keccak)[i] = hashORxpoint.at(i);
		}
        // Generate targetHexPrefix from hash160Keccak (first 3 bytes = 6 hex chars)
        if (hashORxpoint.size() >= 3) { // 3 bytes for 6 hex characters
            this->targetHexPrefix = BytesToHexPrefix((const unsigned char*)hash160Keccak, 3);
            this->performPrefixSearch = true;
            printf("Target Address Prefix (first 6 hex): %s\n", this->targetHexPrefix.c_str());
        }
	}
	else if (this->searchMode == (int)SEARCH_MODE_SX) { // Single XPoint
		assert(hashORxpoint.size() == 32);
		for (size_t i = 0; i < hashORxpoint.size(); i++) {
			((uint8_t*)xpoint)[i] = hashORxpoint.at(i);
		}
        // Generate targetHexPrefix from xpoint (first 3 bytes = 6 hex chars)
         if (hashORxpoint.size() >= 3) { // 3 bytes for 6 hex characters
            this->targetHexPrefix = BytesToHexPrefix((const unsigned char*)xpoint, 3);
            this->performPrefixSearch = true;
            printf("Target XPoint Prefix (first 6 hex): %s\n", this->targetHexPrefix.c_str());
        }
	}
	printf("\n");

	InitGenratorTable();
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::InitGenratorTable()
{
	// Compute Generator table G[n] = (n+1)*G
	Point g = secp->G;
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g, secp->G);
		Gn[i] = g;
	}
	// _2Gn = CPU_GRP_SIZE*G
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

	char* ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	printf("Start Time   : %s", ctimeBuff);

	if (rKey > 0) {
		printf("Base Key     : Randomly changes on every %llu Mkeys\n", rKey);
	}
	printf("Global start : %s (%d bit)\n", this->rangeStart.GetBase16().c_str(), this->rangeStart.GetBitLength());
	printf("Global end   : %s (%d bit)\n", this->rangeEnd.GetBase16().c_str(), this->rangeEnd.GetBitLength());
	printf("Global range : %s (%d bit)\n", this->rangeDiff2.GetBase16().c_str(), this->rangeDiff2.GetBitLength());

}

// ----------------------------------------------------------------------------

ComputeUnitOptimizer::~ComputeUnitOptimizer()
{
	delete secp;
	if (searchMode == (int)SEARCH_MODE_MA || searchMode == (int)SEARCH_MODE_MX)
		delete bloom;
	if (DATA) // DATA is only allocated in the file-based constructor
		free(DATA);
}

// ----------------------------------------------------------------------------

double log1(double x) // This function seems unused in the provided code.
{
	// Use taylor series to approximate log(1-x)
	return -x - (x * x) / 2.0 - (x * x * x) / 3.0 - (x * x * x * x) / 4.0;
}

void ComputeUnitOptimizer::output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey)
{

#ifdef WIN64
	WaitForSingleObject(ghMutex, INFINITE);
#else
	pthread_mutex_lock(&ghMutex);
#endif

	FILE* f = stdout;
	bool needToClose = false;

	if (outputFile.length() > 0) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("Cannot open %s for writing\n", outputFile.c_str());
			f = stdout;
		}
		else {
			needToClose = true;
		}
	}

	if (!needToClose) // If writing to stdout only, add a newline for separation
		printf("\n");

    fprintf(f, "\n--- Full Match Found ---\n"); // Clarify this is a full match
	fprintf(f, "PubAddress: %s\n", addr.c_str());
	fprintf(stdout, "\n=================================================================================\n");
    fprintf(stdout, "--- Full Match Found ---\n");
	fprintf(stdout, "PubAddress: %s\n", addr.c_str());

	if (coinType == COIN_BTC) {
		fprintf(f, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
		fprintf(stdout, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
	}

	fprintf(f, "Priv (HEX): %s\n", pAddrHex.c_str());
	fprintf(stdout, "Priv (HEX): %s\n", pAddrHex.c_str());

	fprintf(f, "PubK (HEX): %s\n", pubKey.c_str());
	fprintf(stdout, "PubK (HEX): %s\n", pubKey.c_str());

	fprintf(f, "=================================================================================\n");
	fprintf(stdout, "=================================================================================\n");

	if (needToClose)
		fclose(f);

#ifdef WIN64
	ReleaseMutex(ghMutex);
#else
	pthread_mutex_unlock(&ghMutex);
#endif

}

// ----------------------------------------------------------------------------
void ComputeUnitOptimizer::checkAndReportPrefixMatch(bool compressed_param_for_output, Int& baseKey, int key_incr, Point& p1, const unsigned char* current_hash_bytes, int hash_byte_length)
{
    if (!performPrefixSearch || targetHexPrefix.empty()) {
        return;
    }

    // Ensure we have enough bytes in the current hash to form a prefix
    // targetHexPrefix is 6 chars, meaning 3 bytes.
    if (hash_byte_length < 3) {
        return;
    }

    std::string current_gen_hex_prefix = BytesToHexPrefix(current_hash_bytes, 3);

    if (current_gen_hex_prefix == targetHexPrefix) {
        // Prefix Matched!
        std::string addr_str;
        std::string pubKeyHexStr;
        std::string privKeyHexStr;
        std::string wifStrOrEmpty; // WIF for BTC, typically empty for ETH display here

        Int actualKey(baseKey); // Create a copy of the base key for modification
        actualKey.Add((uint64_t)key_incr); // Add the increment for this specific key

        privKeyHexStr = actualKey.GetBase16();

        // Regenerate the point for the actual key if p1 was for baseKey (common in group processing)
        // Or, if p1 is already the point for baseKey + key_incr, this can be skipped.
        // For simplicity, we assume p1 IS the point for baseKey + key_incr.
        // If p1 was a base point for a group, you'd recompute:
        // Point actual_p = secp->ComputePublicKey(&actualKey);

        if (coinType == COIN_BTC) {
            addr_str = secp->GetAddress(compressed_param_for_output, current_hash_bytes); // Use the hash directly
            pubKeyHexStr = secp->GetPublicKeyHex(compressed_param_for_output, p1); // p1 is the public key point
            wifStrOrEmpty = secp->GetPrivAddress(compressed_param_for_output, actualKey);
        } else { // COIN_ETH
            addr_str = secp->GetAddressETH(current_hash_bytes); // Use the hash directly
            pubKeyHexStr = secp->GetPublicKeyHexETH(p1); // p1 is the public key point
            // No WIF typically shown for ETH in this context, private key hex is primary.
        }

        // Outputting the find
        #ifdef WIN64
        WaitForSingleObject(ghMutex, INFINITE);
        #else
        pthread_mutex_lock(&ghMutex);
        #endif

        FILE* f_out_stream = stdout;
        bool close_file_handle = false;
        if (!outputFile.empty()) {
            f_out_stream = fopen(outputFile.c_str(), "a");
            if (f_out_stream == NULL) {
                fprintf(stderr, "Cannot open %s for writing prefix match\n", outputFile.c_str());
                f_out_stream = stdout; // Fallback to stdout
            } else {
                close_file_handle = true;
            }
        }
        
        // Prepare output strings
        const char* title_format_file = "\n--- Prefix Match Found (Target: %s, Matched: %s) ---\n";
        const char* title_format_stdout = "\n========================= PREFIX MATCH FOUND =========================\nTarget Prefix: %s, Matched Address Prefix: %s\n";
        const char* addr_format = "PubAddress: %s\n";
        const char* wif_format = "Priv (WIF): p2pkh:%s\n"; // For BTC
        const char* priv_hex_format = "Priv (HEX): %s\n";
        const char* pubk_hex_format = "PubK (HEX): %s\n";
        const char* separator_stdout = "==================================================================\n";
        const char* separator_file = "------------------------------------------------------------------\n";


        // Print to stdout for immediate visibility
        fprintf(stdout, title_format_stdout, targetHexPrefix.c_str(), current_gen_hex_prefix.c_str());
        fprintf(stdout, addr_format, addr_str.c_str());
        if (coinType == COIN_BTC && !wifStrOrEmpty.empty()) {
            fprintf(stdout, wif_format, wifStrOrEmpty.c_str());
        }
        fprintf(stdout, priv_hex_format, privKeyHexStr.c_str());
        fprintf(stdout, pubk_hex_format, pubKeyHexStr.c_str());
        fprintf(stdout, separator_stdout);
        
        // Print to file (if open and different from stdout)
        if (close_file_handle) { 
            fprintf(f_out_stream, title_format_file, targetHexPrefix.c_str(), current_gen_hex_prefix.c_str());
            fprintf(f_out_stream, addr_format, addr_str.c_str());
            if (coinType == COIN_BTC && !wifStrOrEmpty.empty()) {
                fprintf(f_out_stream, wif_format, wifStrOrEmpty.c_str());
            }
            fprintf(f_out_stream, priv_hex_format, privKeyHexStr.c_str());
            fprintf(f_out_stream, pubk_hex_format, pubKeyHexStr.c_str());
            fprintf(f_out_stream, separator_file);
            fclose(f_out_stream);
        }


        #ifdef WIN64
        ReleaseMutex(ghMutex);
        #else
        pthread_mutex_unlock(&ghMutex);
        #endif
        
        // if (nbPrefixFound) nbPrefixFound++; // If using a counter
    }
}
// ----------------------------------------------------------------------------

bool ComputeUnitOptimizer::checkPrivKey(std::string addr, Int& key, int32_t incr, bool mode)
{
	Int k_base(&key); // Use a copy of the original key passed
    k_base.Add((uint64_t)incr); // Add increment to get the specific key for this address
    Int k_to_check(&k_base);


	// Check addresses
	Point p = secp->ComputePublicKey(&k_to_check);
	// std::string px = p.x.GetBase16(); // Not directly used here, but good for debugging
	std::string chkAddr = secp->GetAddress(mode, p);

	if (chkAddr != addr) {
		//Key may be the opposite one (for BTC, due to y parity in uncompressed or specific compressed form)
        // This usually applies if the original key calculation could result in -k mod N.
        // The current structure computes points from k, k+1, k+2... so direct negation isn't typical here unless `key` itself was negative.
        // However, if the address generation implies a choice (e.g. for uncompressed, either y or -y leads to same x but different point)
        // this check is for cases where the discovered hash matches, but our derived private key needs negation.
		k_to_check.Neg(); // Try -k_final
		k_to_check.Add(&secp->order); // Ensure it's positive: -k_final + N
		p = secp->ComputePublicKey(&k_to_check);
		chkAddr = secp->GetAddress(mode, p); // Recalculate address with negated key

		if (chkAddr != addr) {
			#ifdef WIN64
			WaitForSingleObject(ghMutex, INFINITE);
			#else
			pthread_mutex_lock(&ghMutex);
			#endif
			printf("\n========================= WARNING: Private Key Mismatch =========================\n");
			printf("A hash match was found, but the derived private key does not regenerate the address.\n");
			printf("  Original Key (before incr): %s\n", key.GetBase16().c_str());
            printf("  Increment: %d\n", incr);
			printf("  Derived Key (k+incr): %s\n", k_base.GetBase16().c_str());
			printf("  Target Address: %s\n", addr.c_str());
			printf("  Address from Derived Key: %s\n", secp->GetAddress(mode, secp->ComputePublicKey(&k_base)).c_str());
            printf("  Address from Negated Derived Key: %s\n", chkAddr.c_str());
			printf("  Public Key X from Derived Key: %s\n", secp->ComputePublicKey(&k_base).x.GetBase16().c_str());
			printf("=================================================================================\n");
			#ifdef WIN64
			ReleaseMutex(ghMutex);
			#else
			pthread_mutex_unlock(&ghMutex);
			#endif
			return false;
		}
	}
    // If we are here, k_to_check is the correct private key (either k_base or its negation)
	output(addr, secp->GetPrivAddress(mode, k_to_check), k_to_check.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

bool ComputeUnitOptimizer::checkPrivKeyETH(std::string addr, Int& key, int32_t incr)
{
	Int k_base(&key);
    k_base.Add((uint64_t)incr);
	Int k_to_check(&k_base);

	Point p = secp->ComputePublicKey(&k_to_check);
	std::string chkAddr = secp->GetAddressETH(p);

	if (chkAddr != addr) {
        // For ETH, private key negation producing the same address is not standard like BTC's y-parity.
        // A mismatch here usually indicates a more fundamental issue or that the input 'addr'
        // was not actually derived from 'key + incr'.
        // However, to be safe, we can try the negation as it's a common pattern in ECC.
		k_to_check.Neg();
		k_to_check.Add(&secp->order);
		p = secp->ComputePublicKey(&k_to_check);
		chkAddr = secp->GetAddressETH(p);
		if (chkAddr != addr) {
            #ifdef WIN64
			WaitForSingleObject(ghMutex, INFINITE);
			#else
			pthread_mutex_lock(&ghMutex);
			#endif
			printf("\n========================= WARNING: ETH Private Key Mismatch =========================\n");
            printf("A hash match was found, but the derived private key does not regenerate the address.\n");
			printf("  Original Key (before incr): %s\n", key.GetBase16().c_str());
            printf("  Increment: %d\n", incr);
			printf("  Derived Key (k+incr): %s\n", k_base.GetBase16().c_str());
			printf("  Target Address: %s\n", addr.c_str());
            printf("  Address from Derived Key: %s\n", secp->GetAddressETH(secp->ComputePublicKey(&k_base)).c_str());
            printf("  Address from Negated Derived Key: %s\n", chkAddr.c_str());
			printf("  Public Key (uncomp) from Derived Key: %s\n", secp->GetPublicKeyHexETH(secp->ComputePublicKey(&k_base)).c_str());
			printf("=====================================================================================\n");
            #ifdef WIN64
			ReleaseMutex(ghMutex);
			#else
			pthread_mutex_unlock(&ghMutex);
			#endif
			return false;
		}
	}
    // k_to_check is the correct private key
	output(addr, k_to_check.GetBase16()/* ETH usually shows hex private key, WIF is BTC specific */, k_to_check.GetBase16(), secp->GetPublicKeyHexETH(p));
	return true;
}

// For XPoint, the "address" is the XPoint itself. We just need to output the key.
bool ComputeUnitOptimizer::checkPrivKeyX(Int& key, int32_t incr, bool mode, const unsigned char* xpoint_bytes)
{
	Int k_final(&key);
	k_final.Add((uint64_t)incr);
	Point p = secp->ComputePublicKey(&k_final);

    // Verify the XPoint matches if provided (it should, as this function is called after a match)
    unsigned char current_xpoint[32];
    secp->GetXBytes(mode, p, current_xpoint);
    if(memcmp(xpoint_bytes, current_xpoint, 32) != 0) {
        // This case should ideally not happen if called after MatchXPoint
        // Try negative key just in case, though X-coordinate is the same for P and -P
        Int k_neg(&k_final);
        k_neg.Neg();
        k_neg.Add(&secp->order);
        Point p_neg = secp->ComputePublicKey(&k_neg);
        secp->GetXBytes(mode, p_neg, current_xpoint);
        if(memcmp(xpoint_bytes, current_xpoint, 32) != 0) {
            #ifdef WIN64
            WaitForSingleObject(ghMutex, INFINITE);
            #else
            pthread_mutex_lock(&ghMutex);
            #endif
            printf("\n========================= WARNING: XPoint Private Key Mismatch =========================\n");
            printf("An XPoint match was found, but the derived private key does not regenerate the XPoint.\n");
            printf("  Original Key (before incr): %s\n", key.GetBase16().c_str());
            printf("  Increment: %d\n", incr);
            printf("  Derived Key (k+incr): %s\n", k_final.GetBase16().c_str());
            printf("  Target XPoint (hex): ");
            for(int i=0; i<32; ++i) printf("%02X", xpoint_bytes[i]);
            printf("\n");
            printf("  XPoint from Derived Key (hex): ");
            for(int i=0; i<32; ++i) printf("%02X", current_xpoint[i]); // This will be the one from p_neg if we reached here
            printf("\n");
            printf("========================================================================================\n");
            #ifdef WIN64
            ReleaseMutex(ghMutex);
            #else
            pthread_mutex_unlock(&ghMutex);
            #endif
            return false;
        }
        // If negative key worked
        k_final.Set(&k_neg);
        p.Set(&p_neg);
    }

    // Convert XPoint bytes to string for output function
    std::string xpoint_str;
    char tmp[3];
    for(int i=0; i<32; ++i) {
        sprintf(tmp, "%02X", xpoint_bytes[i]);
        xpoint_str.append(tmp);
    }
    // The 'output' function expects an address-like string. For XPoints, this is the XPoint hex itself.
	output(xpoint_str, secp->GetPrivAddress(mode, k_final), k_final.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

// ----------------------------------------------------------------------------

#ifdef WIN64
DWORD WINAPI _FindKeyCPU(LPVOID lpParam)
{
#else
void* _FindKeyCPU(void* lpParam)
{
#endif
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyCPU(p);
	return 0;
}

#ifdef WIN64
DWORD WINAPI _FindKeyGPU(LPVOID lpParam)
{
#else
void* _FindKeyGPU(void* lpParam)
{
#endif
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyGPU(p);
	return 0;
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::checkMultiAddresses(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHash160(compressed, p1, h0);
	if (CheckBloomBinary(h0, 20) > 0) { // Bloom filter positive
        // Binary search to confirm
        if (CheckBloomBinary(h0, 20) == 1) { // Confirmed in DATA
		    std::string addr = secp->GetAddress(compressed, h0);
		    if (checkPrivKey(addr, key, i, compressed)) {
			    nbFoundKey++;
		    }
        }
	}
    // Prefix check is not typically done in multi-address mode against a large file,
    // as it would require a specific target prefix to be defined.
    // If you want prefix checking here, a target prefix must be set globally.
    // checkAndReportPrefixMatch(compressed, key, i, p1, h0, 20);
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::checkMultiAddressesETH(Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHashETH(p1, h0);
	if (CheckBloomBinary(h0, 20) > 0) {
        if (CheckBloomBinary(h0, 20) == 1) { // Confirmed in DATA
		    std::string addr = secp->GetAddressETH(h0);
		    if (checkPrivKeyETH(addr, key, i)) {
			    nbFoundKey++;
		    }
        }
	}
    // checkAndReportPrefixMatch(false, key, i, p1, h0, 20); // See comment in checkMultiAddresses
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::checkSingleAddress(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHash160(compressed, p1, h0);
	if (MatchHash((uint32_t*)h0)) { // Full match
		std::string addr = secp->GetAddress(compressed, h0);
		if (checkPrivKey(addr, key, i, compressed)) {
			nbFoundKey++;
		}
	}
    // Always check for prefix if enabled, regardless of full match
    if (performPrefixSearch) {
        checkAndReportPrefixMatch(compressed, key, i, p1, h0, 20);
    }
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::checkSingleAddressETH(Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHashETH(p1, h0);
	if (MatchHash((uint32_t*)h0)) { // Full match (hash160Keccak is target)
		std::string addr = secp->GetAddressETH(h0);
		if (checkPrivKeyETH(addr, key, i)) {
			nbFoundKey++;
		}
	}
    // Always check for prefix if enabled
    if (performPrefixSearch) {
        // For ETH, the 'compressed' parameter in checkAndReportPrefixMatch primarily affects
        // BTC WIF generation if used, but for ETH pubkey/address, it's less critical.
        // Standard ETH uses uncompressed points for addresses.
        checkAndReportPrefixMatch(false, key, i, p1, h0, 20);
    }
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::checkMultiXPoints(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[32]; // XPoints are 32 bytes

	// Point
	secp->GetXBytes(compressed, p1, h0);
	if (CheckBloomBinary(h0, 32) > 0) {
        if (CheckBloomBinary(h0, 32) == 1) { // Confirmed in DATA
		    if (checkPrivKeyX(key, i, compressed, h0)) { // Pass h0 as the matched XPoint
			    nbFoundKey++;
		    }
        }
	}
    // checkAndReportPrefixMatch(compressed, key, i, p1, h0, 32); // See comment in checkMultiAddresses
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::checkSingleXPoint(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[32]; // XPoints are 32 bytes

	// Point
	secp->GetXBytes(compressed, p1, h0);
	if (MatchXPoint((uint32_t*)h0)) { // Full match
		if (checkPrivKeyX(key, i, compressed, h0)) { // Pass h0 as the matched XPoint
			nbFoundKey++;
		}
	}
    // Always check for prefix if enabled
    if (performPrefixSearch) {
        checkAndReportPrefixMatch(compressed, key, i, p1, h0, 32);
    }
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::checkMultiAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4)
{
	unsigned char h0[20], h1[20], h2[20], h3[20];
    Point points[] = {p1, p2, p3, p4};
    unsigned char* hashes[] = {h0, h1, h2, h3};

	secp->GetHash160(compressed, p1, p2, p3, p4, h0, h1, h2, h3);

    for (int j = 0; j < 4; ++j) {
        if (CheckBloomBinary(hashes[j], 20) > 0) {
            if (CheckBloomBinary(hashes[j], 20) == 1) { // Confirmed
                std::string addr = secp->GetAddress(compressed, hashes[j]);
                if (checkPrivKey(addr, key, i + j, compressed)) {
                    nbFoundKey++;
                }
            }
        }
        // if (performPrefixSearch) { // See comment in checkMultiAddresses
        //    checkAndReportPrefixMatch(compressed, key, i + j, points[j], hashes[j], 20);
        // }
    }
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::checkSingleAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4)
{
	unsigned char h0[20], h1[20], h2[20], h3[20];
    Point points[] = {p1, p2, p3, p4};
    unsigned char* hashes[] = {h0, h1, h2, h3};

	secp->GetHash160(compressed, p1, p2, p3, p4, h0, h1, h2, h3);

    for (int j = 0; j < 4; ++j) {
        if (MatchHash((uint32_t*)hashes[j])) { // Full match
            std::string addr = secp->GetAddress(compressed, hashes[j]);
            if (checkPrivKey(addr, key, i + j, compressed)) {
                nbFoundKey++;
            }
        }
        // Always check for prefix if enabled
        if (performPrefixSearch) {
            checkAndReportPrefixMatch(compressed, key, i + j, points[j], hashes[j], 20);
        }
    }
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::getCPUStartingKey(Int & tRangeStart, Int & tRangeEnd, Int & key, Point & startP)
{
	if (rKey <= 0) {
		key.Set(&tRangeStart);
	}
	else {
        // Ensure tRangeStart is less than tRangeEnd for Rand to work correctly
        if (tRangeStart.IsGreaterOrEqual(&tRangeEnd)) {
             key.Set(&tRangeStart); // Fallback or handle error
        } else {
		    key.Rand(&tRangeStart, &tRangeEnd); // Corrected Rand to take a range
        }
	}
	Int km(&key);
	km.Add((uint64_t)CPU_GRP_SIZE / 2); // Start from the middle of the first "group" to be generated
	startP = secp->ComputePublicKey(&km);

}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::FindKeyCPU(TH_PARAM * ph)
{

	// Global init
	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;
	counters[thId] = 0;

	// CPU Thread
	IntGroup* grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);

	// Group Init
	Int baseKey;// The key corresponding to pts[0] in each iteration
	Point startP;// The point from which the next group is derived, P + (GRP_SIZE/2)*G
	getCPUStartingKey(tRangeStart, tRangeEnd, baseKey, startP);
    // baseKey is now the key for the *center* of the first calculated batch (startP).
    // Adjust baseKey to be the key for the *first point* in the batch.
    baseKey.Sub((uint64_t)CPU_GRP_SIZE / 2);


	Int* dx = new Int[CPU_GRP_SIZE / 2 + 1];
	Point* pts = new Point[CPU_GRP_SIZE]; // Stores P, P+G, P-G, P+2G, P-2G ...

	Int* dy = new Int();
	Int* dyn = new Int();
	Int* _s = new Int();
	Int* _p = new Int();
	Point* pp = new Point(); // Temp for P+iG
	Point* pn = new Point(); // Temp for P-iG
	grp->Set(dx);

	ph->hasStarted = true;
	ph->rKeyRequest = false;

	while (!endOfSearch) {

        if (baseKey.IsGreaterOrEqual(&tRangeEnd) && rKey <= 0) { // Check if current key exceeds thread's range
            break; 
        }

		if (ph->rKeyRequest) {
			getCPUStartingKey(tRangeStart, tRangeEnd, baseKey, startP);
            baseKey.Sub((uint64_t)CPU_GRP_SIZE / 2); // Adjust again
			ph->rKeyRequest = false;
		}

		// Fill group for Lucas sequence based point addition/subtraction
		// dx[i] = Gn[i].x - startP.x
		// dx[i+1] = _2Gn.x - startP.x (for next startP calculation)
		int hLength = (CPU_GRP_SIZE / 2 - 1); // Number of G multiples to add/subtract from startP

		for (i = 0; i < hLength; i++) { // For P +/- G, P +/- 2G ... P +/- (hLength)G
			dx[i].ModSub(&Gn[i].x, &startP.x); // (i+1)G.x - startP.x
		}
		// Last dx for P +/- (CPU_GRP_SIZE/2)G
		dx[i].ModSub(&Gn[CPU_GRP_SIZE/2 -1].x, &startP.x); // (CPU_GRP_SIZE/2)G.x - startP.x

        // dx for calculating the next startP: startP + (CPU_GRP_SIZE)G
        // This involves startP and (CPU_GRP_SIZE)G which is _2Gn
		dx[i + 1].ModSub(&_2Gn.x, &startP.x);

		// Grouped ModInv
		grp->ModInv(); // Computes 1/dx[j] for all j

		// Center point of the current calculation batch
		pts[CPU_GRP_SIZE / 2] = startP; // Key for this point is baseKey + CPU_GRP_SIZE/2

		// Calculate points: startP + k*G and startP - k*G
		for (i = 0; i < hLength && !endOfSearch; i++) { // i from 0 to (CPU_GRP_SIZE/2 - 2)
                                                        // Corresponds to (i+1)*G, so G, 2G, ..., (CPU_GRP_SIZE/2 - 1)G
			*pp = startP; // Point for positive addition: startP + (i+1)G
			*pn = startP; // Point for negative addition: startP - (i+1)G

			// P_new = startP + Gn[i]  (Gn[i] is (i+1)*G)
			dy->ModSub(&Gn[i].y, &pp->y);    // Gn[i].y - startP.y
			_s->ModMulK1(dy, &dx[i]);       // s = (Gn[i].y - startP.y) / (Gn[i].x - startP.x)
			_p->ModSquareK1(_s);            // _p = s^2

			pp->x.ModNeg();                 // -startP.x
			pp->x.ModAdd(_p);               // s^2 - startP.x
			pp->x.ModSub(&Gn[i].x);         // rx = s^2 - startP.x - Gn[i].x

			pp->y.ModSub(&Gn[i].x, &pp->x); // Gn[i].x - rx
			pp->y.ModMulK1(_s);             // s * (Gn[i].x - rx)
			pp->y.ModSub(&Gn[i].y);         // ry = s * (Gn[i].x - rx) - Gn[i].y

			// P_new = startP - Gn[i] (i.e., startP + (-Gn[i]))
            // -Gn[i] has point (Gn[i].x, -Gn[i].y mod p)
			dyn->Set(&Gn[i].y);
			dyn->ModNeg();                  // -Gn[i].y
			dyn->ModSub(&pn->y);            // -Gn[i].y - startP.y

			_s->ModMulK1(dyn, &dx[i]);      // s_neg = (-Gn[i].y - startP.y) / (Gn[i].x - startP.x)
			_p->ModSquareK1(_s);            // _p_neg = s_neg^2

			pn->x.ModNeg();                 // -startP.x
			pn->x.ModAdd(_p);               // s_neg^2 - startP.x
			pn->x.ModSub(&Gn[i].x);         // rx_neg = s_neg^2 - startP.x - Gn[i].x

			pn->y.ModSub(&Gn[i].x, &pn->x); // Gn[i].x - rx_neg
			pn->y.ModMulK1(_s);             // s_neg * (Gn[i].x - rx_neg)
            // Original formula for addition P1+P2 is ry = s(P1.x - R.x) - P1.y
            // Here P1 is -Gn[i] (point (Gn[i].x, -Gn[i].y)) and P2 is startP.
            // So, ry = s_neg * (Gn[i].x - pn.x) - (-Gn[i].y)
			pn->y.ModAdd(&Gn[i].y);         // ry_neg = s_neg * (Gn[i].x - pn.x) + Gn[i].y

            // Store points symmetrically around the center
            // pts[GRP/2 + k] corresponds to startP + kG
            // pts[GRP/2 - k] corresponds to startP - kG
			pts[CPU_GRP_SIZE / 2 + (i + 1)] = *pp; // startP + (i+1)G
			pts[CPU_GRP_SIZE / 2 - (i + 1)] = *pn; // startP - (i+1)G
		}

		// First point in array: startP - (CPU_GRP_SIZE/2)*G
        // This corresponds to Gn[CPU_GRP_SIZE/2 - 1] which is (CPU_GRP_SIZE/2)*G
        // Index i for dx was hLength = CPU_GRP_SIZE/2 -1
		*pn = startP;
		dyn->Set(&Gn[CPU_GRP_SIZE/2 -1].y); // (CPU_GRP_SIZE/2)*G .y
		dyn->ModNeg();
		dyn->ModSub(&pn->y);

		_s->ModMulK1(dyn, &dx[CPU_GRP_SIZE/2 -1]); // Use the correct dx index
		_p->ModSquareK1(_s);

		pn->x.ModNeg();
		pn->x.ModAdd(_p);
		pn->x.ModSub(&Gn[CPU_GRP_SIZE/2 -1].x);

		pn->y.ModSub(&Gn[CPU_GRP_SIZE/2 -1].x, &pn->x);
		pn->y.ModMulK1(_s);
		pn->y.ModAdd(&Gn[CPU_GRP_SIZE/2 -1].y);
		pts[0] = *pn; // Key for pts[0] is baseKey (which was startP_key - GRP_SIZE/2)


		// Calculate the next startP for the next iteration: current_startP + CPU_GRP_SIZE*G
        // Uses current startP and _2Gn (which is CPU_GRP_SIZE * G)
        // dx index for this was CPU_GRP_SIZE/2
		*pp = startP; // Current startP
		dy->ModSub(&_2Gn.y, &pp->y);    // _2Gn.y - startP.y

		_s->ModMulK1(dy, &dx[CPU_GRP_SIZE/2]); // Use dx for _2Gn
		_p->ModSquareK1(_s);

		pp->x.ModNeg();                 // -startP.x
		pp->x.ModAdd(_p);               // s^2 - startP.x
		pp->x.ModSub(&_2Gn.x);          // rx = s^2 - startP.x - _2Gn.x

		pp->y.ModSub(&_2Gn.x, &pp->x);  // _2Gn.x - rx
		pp->y.ModMulK1(_s);             // s*(_2Gn.x - rx)
		pp->y.ModSub(&_2Gn.y);          // ry = s*(_2Gn.x - rx) - _2Gn.y
		startP = *pp; // This is the new center point for the next batch of GRP_SIZE calculations

		// At this point, pts array is filled with GRP_SIZE points.
        // pts[0] corresponds to baseKey
        // pts[1] corresponds to baseKey + 1
        // ...
        // pts[GRP_SIZE/2] corresponds to baseKey + GRP_SIZE/2 (the original startP key)
        // ...
        // pts[GRP_SIZE-1] corresponds to baseKey + GRP_SIZE - 1

		// Check addresses
		if (useSSE) { // SSE processes 4 points at a time
			for (int j = 0; j < CPU_GRP_SIZE && !endOfSearch; j += 4) {
                // The 'key' argument to check...SSE functions is the base key of that 4-point group.
                // The 'i' argument is the offset from that base key.
                // Here, baseKey is the key for pts[0]. So for pts[j], key is baseKey, offset is j.
				switch (compMode) {
				case SEARCH_COMPRESSED:
					if (searchMode == (int)SEARCH_MODE_MA) {
						checkMultiAddressesSSE(true, baseKey, j, pts[j], pts[j + 1], pts[j + 2], pts[j + 3]);
					}
					else if (searchMode == (int)SEARCH_MODE_SA) {
						checkSingleAddressesSSE(true, baseKey, j, pts[j], pts[j + 1], pts[j + 2], pts[j + 3]);
					}
					break;
				case SEARCH_UNCOMPRESSED:
					if (searchMode == (int)SEARCH_MODE_MA) {
						checkMultiAddressesSSE(false, baseKey, j, pts[j], pts[j + 1], pts[j + 2], pts[j + 3]);
					}
					else if (searchMode == (int)SEARCH_MODE_SA) {
						checkSingleAddressesSSE(false, baseKey, j, pts[j], pts[j + 1], pts[j + 2], pts[j + 3]);
					}
					break;
				case SEARCH_BOTH:
					if (searchMode == (int)SEARCH_MODE_MA) {
						checkMultiAddressesSSE(true, baseKey, j, pts[j], pts[j + 1], pts[j + 2], pts[j + 3]);
						checkMultiAddressesSSE(false, baseKey, j, pts[j], pts[j + 1], pts[j + 2], pts[j + 3]);
					}
					else if (searchMode == (int)SEARCH_MODE_SA) {
						checkSingleAddressesSSE(true, baseKey, j, pts[j], pts[j + 1], pts[j + 2], pts[j + 3]);
						checkSingleAddressesSSE(false, baseKey, j, pts[j], pts[j + 1], pts[j + 2], pts[j + 3]);
					}
					break;
				}
			}
		}
		else { // Non-SSE, process one by one
			if (coinType == COIN_BTC) {
				for (int j = 0; j < CPU_GRP_SIZE && !endOfSearch; j++) {
                    // key is baseKey, offset 'i' is j
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, baseKey, j, pts[j]);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, baseKey, j, pts[j]);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, baseKey, j, pts[j]);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, baseKey, j, pts[j]);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, baseKey, j, pts[j]);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, baseKey, j, pts[j]);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, baseKey, j, pts[j]);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, baseKey, j, pts[j]);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, baseKey, j, pts[j]);
							checkMultiAddresses(false, baseKey, j, pts[j]);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, baseKey, j, pts[j]);
							checkSingleAddress(false, baseKey, j, pts[j]);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, baseKey, j, pts[j]);
							checkMultiXPoints(false, baseKey, j, pts[j]);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, baseKey, j, pts[j]);
							checkSingleXPoint(false, baseKey, j, pts[j]);
							break;
						default:
							break;
						}
						break;
					}
				}
			}
			else { // COIN_ETH (typically uncompressed, and no XPoint modes handled here for ETH)
				for (int j = 0; j < CPU_GRP_SIZE && !endOfSearch; j++) {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(baseKey, j, pts[j]);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(baseKey, j, pts[j]);
						break;
					default:
						// ETH does not have XPoint search modes in this structure
						break;
					}
				}
			}
		}
		baseKey.Add((uint64_t)CPU_GRP_SIZE); // Advance base key for the next block of GRP_SIZE keys
		counters[thId] += CPU_GRP_SIZE;
	}
	ph->isRunning = false;

	delete grp;
	delete[] dx;
	delete[] pts;

	delete dy;
	delete dyn;
	delete _s;
	delete _p;
	delete pp;
	delete pn;
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::getGPUStartingKeys(Int & tRangeStart, Int & tRangeEnd, int groupSize, int nbThread, Int * keys, Point * p)
{

	Int tRangeDiff; // Total range for this GPU device
	Int tRangeStartPerThread(tRangeStart); // Start of range for current sub-thread
	Int tRangeEndPerThread;

	Int tThreads;
	tThreads.SetInt32(nbThread); // Number of CUDA threads / logical key streams for this device

	tRangeDiff.Set(&tRangeEnd);
	tRangeDiff.Sub(&tRangeStart); // Total span for this GPU device
	if (nbThread > 0) {
	    tRangeDiff.Div(&tThreads); // Size of sub-range per CUDA thread/stream
	} else {
        // Avoid division by zero if nbThread is 0, though this shouldn't happen if called
        tRangeDiff.SetInt32(0);
    }


	for (int i = 0; i < nbThread; i++) {
		tRangeEndPerThread.Set(&tRangeStartPerThread);
		tRangeEndPerThread.Add(&tRangeDiff);
        if (tRangeEndPerThread.IsGreater(&tRangeEnd) || i == nbThread -1) { // Ensure last thread covers up to tRangeEnd
            tRangeEndPerThread.Set(&tRangeEnd);
        }


		if (rKey <= 0) {
			keys[i].Set(&tRangeStartPerThread);
        } else {
            if (tRangeStartPerThread.IsGreaterOrEqual(&tRangeEndPerThread)) {
                keys[i].Set(&tRangeStartPerThread); // Fallback
            } else {
			    keys[i].Rand(&tRangeStartPerThread, &tRangeEndPerThread); // Random key within the sub-range
            }
        }
		tRangeStartPerThread.Add(&tRangeDiff); // Advance start for next CUDA thread/stream

		Int k_for_pub(keys[i]); // keys[i] is the actual starting private key for this stream
		// p[i] is the public key for keys[i] + groupSize/2 for the GPU kernel's logic.
        // The GPU kernel will calculate points relative to this p[i].
		k_for_pub.Add((uint64_t)(groupSize / 2));
		p[i] = secp->ComputePublicKey(&k_for_pub);
	}

}

void ComputeUnitOptimizer::FindKeyGPU(TH_PARAM * ph)
{

	bool ok = true;

#ifdef WITHGPU

	// Global init
	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;

	GPUEngine* g;
    // Pass performPrefixSearch and targetHexPrefix to GPUEngine if GPU needs to do prefix filtering
    // For now, assuming GPU returns candidates and CPU does final prefix check if needed for SA/SX.
	switch (searchMode) {
	case (int)SEARCH_MODE_MA:
	case (int)SEARCH_MODE_MX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			BLOOM_N, bloom->get_bits(), bloom->get_hashes(), bloom->get_bf(), DATA, TOTAL_COUNT, (rKey != 0));
		break;
	case (int)SEARCH_MODE_SA: // Single Address
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			hash160Keccak, (rKey != 0)/*, this->performPrefixSearch, this->targetHexPrefix*/ ); // Example if GPU handled prefix
		break;
	case (int)SEARCH_MODE_SX: // Single XPoint
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			xpoint, (rKey != 0)/*, this->performPrefixSearch, this->targetHexPrefix*/); // Example
		break;
	default:
		printf("Invalid search mode for GPU\n");
		ph->isRunning = false;
		return;
	}


	int nbCUDAThread = g->GetNbThread(); // Number of logical streams/threads the GPU engine will manage
	Point* p_gpu_starts = new Point[nbCUDAThread]; // Public keys for GPU's starting points
	Int* baseKeys_gpu = new Int[nbCUDAThread]; // Base private keys for each GPU stream
	std::vector<ITEM> found_items;

	printf("GPU ID %d     : %s, %d logical threads\n", ph->gpuId, g->deviceName.c_str(), nbCUDAThread);

	counters[thId] = 0;

    // Distribute tRangeStart to tRangeEnd among the nbCUDAThread logical streams
	getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbCUDAThread, baseKeys_gpu, p_gpu_starts);
	ok = g->SetKeys(p_gpu_starts); // Set the starting public keys for the GPU kernels

	ph->hasStarted = true;
	ph->rKeyRequest = false;

	while (ok && !endOfSearch) {
        bool anyKeyExceeded = false;
        if (rKey <= 0) { // Only check range end if not in random mode
            for(int k=0; k < nbCUDAThread; ++k) {
                if(baseKeys_gpu[k].IsGreaterOrEqual(&tRangeEnd)) { // This check might be too simple, depends on how tRangeEnd was split.
                                                                // A more robust check uses the specific end for *this* GPU thread's portion.
                    anyKeyExceeded = true; break;
                }
            }
        }
        if (anyKeyExceeded) break;


		if (ph->rKeyRequest) {
			getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbCUDAThread, baseKeys_gpu, p_gpu_starts);
			ok = g->SetKeys(p_gpu_starts);
			ph->rKeyRequest = false;
		}

        found_items.clear();
		// Call kernel
		switch (searchMode) {
		case (int)SEARCH_MODE_MA: // Multi-address (Bloom + Binary Search on GPU/CPU)
			ok = g->LaunchSEARCH_MODE_MA(found_items, false);
			for (size_t k = 0; k < found_items.size() && !endOfSearch; k++) {
				ITEM it = found_items[k];
				if (coinType == COIN_BTC) {
					std::string addr = secp->GetAddress(it.mode, it.hash); // it.hash is HASH160
					if (checkPrivKey(addr, baseKeys_gpu[it.thId], it.incr, it.mode)) {
						nbFoundKey++;
					}
				} else { // ETH
					std::string addr = secp->GetAddressETH(it.hash); // it.hash is ETH Keccak
					if (checkPrivKeyETH(addr, baseKeys_gpu[it.thId], it.incr)) {
						nbFoundKey++;
					}
				}
                // Prefix check for MA could be added if a global target prefix is defined
			}
			break;
		case (int)SEARCH_MODE_MX: // Multi-XPoint (Bloom + Binary Search on GPU/CPU)
			ok = g->LaunchSEARCH_MODE_MX(found_items, false);
			for (size_t k = 0; k < found_items.size() && !endOfSearch; k++) {
				ITEM it = found_items[k]; // it.hash contains the 32-byte XPoint
				if (checkPrivKeyX(baseKeys_gpu[it.thId], it.incr, it.mode, it.hash)) {
					nbFoundKey++;
				}
                // Prefix check for MX could be added
			}
			break;
		case (int)SEARCH_MODE_SA: // Single Address (Direct compare on GPU, or GPU returns candidates)
			ok = g->LaunchSEARCH_MODE_SA(found_items, false);
			for (size_t k = 0; k < found_items.size() && !endOfSearch; k++) {
				ITEM it = found_items[k]; // it.hash is HASH160 that fully matched
				if (coinType == COIN_BTC) {
					std::string addr = secp->GetAddress(it.mode, it.hash);
					if (checkPrivKey(addr, baseKeys_gpu[it.thId], it.incr, it.mode)) {
						nbFoundKey++;
					}
				} else { // ETH
					std::string addr = secp->GetAddressETH(it.hash);
					if (checkPrivKeyETH(addr, baseKeys_gpu[it.thId], it.incr)) {
						nbFoundKey++;
					}
				}
                // If GPU doesn't do prefix, CPU can do it here.
                // However, items from LaunchSEARCH_MODE_SA should be full matches.
                // Prefix matches would ideally be found by a different GPU kernel or logic.
                // For now, assuming SA items are full matches only.
                // If GPU kernel also reported prefix matches (e.g. via a flag in ITEM), handle here.
			}
            // If the GPU kernel ONLY does full matches, and we want CPU to check prefixes for ALL points scanned by GPU:
            // This would require the GPU to return all generated points/hashes, not just full matches,
            // or for the CPU to replicate the GPU's point generation to check prefixes.
            // The current design with `found_items` implies items are already "found" (matched).
            // To add prefix checking for SA/SX on GPU-generated points not fully matching,
            // GPUEngine's Launch methods would need to change to allow returning non-matches
            // or point data for CPU-side prefix checking.
            // For simplicity, current prefix logic is tied to CPU path's checkSingleAddress etc.
            // If GPUEngine could be modified to also find prefix matches:
            // std::vector<ITEM> prefix_found_items;
            // g->LaunchSEARCH_MODE_SA_Prefix(prefix_found_items, ...);
            // for (ITEM it : prefix_found_items) { checkAndReportPrefixMatch(...); }

			break;
		case (int)SEARCH_MODE_SX: // Single XPoint
			ok = g->LaunchSEARCH_MODE_SX(found_items, false);
			for (size_t k = 0; k < found_items.size() && !endOfSearch; k++) {
				ITEM it = found_items[k]; // it.hash contains the 32-byte XPoint
				if (checkPrivKeyX(baseKeys_gpu[it.thId], it.incr, it.mode, it.hash)) {
					nbFoundKey++;
				}
                // Similar to SA, prefix logic on GPU items depends on kernel capabilities.
			}
			break;
		default:
            ok = false; // Should not happen if constructor validated
			break;
		}

		if (ok) {
			for (int k = 0; k < nbCUDAThread; k++) {
                // STEP_SIZE is the number of keys each CUDA "thread" processes per Launch call.
				baseKeys_gpu[k].Add((uint64_t)STEP_SIZE);
			}
			counters[thId] += (uint64_t)(STEP_SIZE) * nbCUDAThread;
		}
	}

	delete[] baseKeys_gpu;
	delete[] p_gpu_starts;
	delete g;

#else // WITHGPU not defined
	ph->hasStarted = true;
	printf("GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif

	ph->isRunning = false;
}

// ----------------------------------------------------------------------------

bool ComputeUnitOptimizer::isAlive(TH_PARAM * p)
{
	bool any_alive = false; // Changed to any_alive as threads might finish at different times
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++) {
		if (p[i].isRunning) {
            any_alive = true;
            break;
        }
    }
	return any_alive;
}

// ----------------------------------------------------------------------------

bool ComputeUnitOptimizer::hasStarted(TH_PARAM * p)
{
	bool all_started = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++) {
		if (!p[i].hasStarted && p[i].obj != nullptr) { // Check obj to ensure param is initialized
            all_started = false;
            break;
        }
    }
	return all_started;
}

// ----------------------------------------------------------------------------

uint64_t ComputeUnitOptimizer::getGPUCount()
{
	uint64_t count = 0;
	for (int i = 0; i < nbGPUThread; i++)
		count += counters[0x80 + i]; // GPU counters start at 0x80
	return count;
}

// ----------------------------------------------------------------------------

uint64_t ComputeUnitOptimizer::getCPUCount()
{
	uint64_t count = 0;
	for (int i = 0; i < nbCPUThread; i++)
		count += counters[i]; // CPU counters are 0 to nbCPUThread-1
	return count;
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::rKeyRequest(TH_PARAM * p) {
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		if(p[i].obj != nullptr) p[i].rKeyRequest = true;
}
// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::SetupRanges(uint32_t totalThreads)
{
    if (totalThreads == 0) { // Avoid division by zero
        rangeDiff.Set(&rangeEnd);
        rangeDiff.Sub(&rangeStart); // Full range if no threads (should not happen in normal op)
        return;
    }
	Int threads;
	threads.SetInt32(totalThreads);
	rangeDiff.Set(&rangeEnd);
	rangeDiff.Sub(&rangeStart); // This is the total range for all threads
	rangeDiff.Div(&threads);    // This is the size of each thread's sub-range
                                // Note: rangeDiff member now stores per-thread chunk size
}

// ----------------------------------------------------------------------------

void ComputeUnitOptimizer::Search(int nbCPU, std::vector<int> gpuDeviceIds, std::vector<int> gpuGridSizes, bool& should_exit_flag)
{
	double t0_progress, t1_progress;
	endOfSearch = false;
	nbCPUThread = nbCPU; // Corrected: Use passed nbCPU
	nbGPUThread = useGpu ? (int)gpuDeviceIds.size() : 0;
	nbFoundKey = 0;


    uint32_t totalEffectiveThreads = nbCPUThread + nbGPUThread;
    if (totalEffectiveThreads == 0 && (this->rangeStart.IsZero() && this->rangeEnd.IsZero())) {
        // If no devices and no range, likely an error or specific single-key test not through Search().
        // If range is set, but no threads, this setup won't proceed well.
        printf("Warning: No CPU or GPU threads specified for search.\n");
        // Depending on desired behavior, could exit or default to a single CPU thread.
        // For now, will proceed, but SetupRanges and thread creation might be problematic.
        // If ranges are large, this might just hang or misbehave.
        if (this->rangeStart.IsZero() && this->rangeEnd.IsZero() && targetCounter == 1 && (searchMode == SEARCH_MODE_SA || searchMode == SEARCH_MODE_SX)){
             printf("Assuming single key test without explicit Search threads.\n");
        } else if (totalEffectiveThreads == 0) {
            printf("Error: Search called with zero total threads and a range to cover. Aborting.\n");
            return;
        }

    }

	SetupRanges(totalEffectiveThreads > 0 ? totalEffectiveThreads : 1); // Avoid div by zero if no threads

	memset(counters, 0, sizeof(counters));

	if (!useGpu && nbCPUThread > 0) // Only print if CPUs are actually used and no GPUs
		printf("\nStarting %d CPU thread%s.\n", nbCPUThread, nbCPUThread > 1 ? "s" : "");
    else if (useGpu)
        printf("\n"); // General newline if GPUs are involved

    // Current key range start for distributing to threads
    Int currentRangeStartForThread;
    currentRangeStartForThread.Set(&this->rangeStart);


	TH_PARAM* params = nullptr;
    if (totalEffectiveThreads > 0) {
        params = (TH_PARAM*)malloc(totalEffectiveThreads * sizeof(TH_PARAM));
	    memset(params, 0, totalEffectiveThreads * sizeof(TH_PARAM));
    }


	// Launch CPU threads
	for (int i = 0; i < nbCPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = i; // CPU thread IDs 0 to nbCPUThread-1
		params[i].isRunning = true;
        params[i].hasStarted = false; // Initialize
        params[i].rKeyRequest = false; // Initialize

		params[i].rangeStart.Set(¤tRangeStartForThread);
		currentRangeStartForThread.Add(&rangeDiff); // rangeDiff is per-thread chunk size
        if (i == nbCPUThread - 1 && nbGPUThread == 0) { // If last CPU thread and no GPU threads
            params[i].rangeEnd.Set(&this->rangeEnd); // Ensure last thread covers to the very end
        } else {
		    params[i].rangeEnd.Set(¤tRangeStartForThread);
        }


#ifdef WIN64
		DWORD win_thread_id;
		CreateThread(NULL, 0, _FindKeyCPU, (void*)(params + i), 0, &win_thread_id);
		if (i == 0) ghMutex = CreateMutex(NULL, FALSE, NULL); // Create mutex once
#else
		pthread_t posix_thread_id;
		pthread_create(&posix_thread_id, NULL, &_FindKeyCPU, (void*)(params + i));
		if (i == 0) pthread_mutex_init(&ghMutex, NULL); // Init mutex once
#endif
	}

	// Launch GPU threads
	for (int i = 0; i < nbGPUThread; i++) {
        int param_idx = nbCPUThread + i;
		params[param_idx].obj = this;
		params[param_idx].threadId = 0x80 + i; // GPU thread IDs start from 0x80
		params[param_idx].isRunning = true;
        params[param_idx].hasStarted = false; // Initialize
        params[param_idx].rKeyRequest = false; // Initialize
		params[param_idx].gpuId = gpuDeviceIds[i];
		params[param_idx].gridSizeX = gpuGridSizes[2 * i];
		params[param_idx].gridSizeY = gpuGridSizes[2 * i + 1];

		params[param_idx].rangeStart.Set(¤tRangeStartForThread);
		currentRangeStartForThread.Add(&rangeDiff);
        if (i == nbGPUThread - 1) { // If this is the last GPU thread (overall last thread)
            params[param_idx].rangeEnd.Set(&this->rangeEnd); // Ensure it covers to the global end
        } else {
		    params[param_idx].rangeEnd.Set(¤tRangeStartForThread);
        }

#ifdef WIN64
		DWORD win_thread_id_gpu;
		CreateThread(NULL, 0, _FindKeyGPU, (void*)(params + param_idx), 0, &win_thread_id_gpu);
        if (nbCPUThread == 0 && i == 0) ghMutex = CreateMutex(NULL, FALSE, NULL); // Create if no CPU threads did
#else
		pthread_t posix_thread_id_gpu;
		pthread_create(&posix_thread_id_gpu, NULL, &_FindKeyGPU, (void*)(params + param_idx));
        if (nbCPUThread == 0 && i == 0) pthread_mutex_init(&ghMutex, NULL); // Init if no CPU threads did
#endif
	}

#ifndef WIN64
	setvbuf(stdout, NULL, _IONBF, 0); // Useful for immediate output on Linux
#endif
    // Only print if there are active threads
	if (totalEffectiveThreads > 0) printf("\n");


	uint64_t lastTotalCount = 0;
	uint64_t currentGpuCount = 0;
	uint64_t lastGpuCount = 0;

#define SMOOTH_FILTER_SIZE 8 // Renamed for clarity
	double lastKeyRateHistory[SMOOTH_FILTER_SIZE];
	double lastGpuKeyRateHistory[SMOOTH_FILTER_SIZE];
	uint32_t historyFilterPos = 0;

	double instantKeyRate = 0.0;
	double instantGpuKeyRate = 0.0;
	char timeStrBuff[256];

	memset(lastKeyRateHistory, 0, sizeof(lastKeyRateHistory));
	memset(lastGpuKeyRateHistory, 0, sizeof(lastGpuKeyRateHistory)); // Corrected second memset

	// Wait that all threads have started
    if (totalEffectiveThreads > 0) {
	    while (!hasStarted(params)) {
		    Timer::SleepMillis(200); // Shorter sleep while waiting for startup
	    }
        printf("All %d worker threads started.\n", totalEffectiveThreads);
    }


	Timer::Init(); // Initialize timer system
	t0_progress = Timer::get_tick(); // Time of first progress report baseline
	startTime = t0_progress; // Overall start time of search computation
	
    Int ICountTotal; // Use Int for large counts
	double completedPercentage = 0;
	uint64_t rKeyRolloverCount = 0; // Renamed for clarity

	while (totalEffectiveThreads > 0 && isAlive(params)) {

		int delay_ms = 2000; // Check every 2 seconds
        Timer::SleepMillis(delay_ms); // Sleep first, then gather stats

		currentGpuCount = getGPUCount();
		uint64_t currentCpuCount = getCPUCount();
        uint64_t currentTotalCount = currentCpuCount + currentGpuCount;

		ICountTotal.SetInt64(currentTotalCount);
		int completedKeyBits = ICountTotal.GetBitLength();

		if (rKey <= 0 && !this->rangeDiff2.IsZero()) { // Only calculate percentage if not random and range is meaningful
			completedPercentage = CalcPercantage(ICountTotal, this->rangeStart, this->rangeDiff2);
		}

		t1_progress = Timer::get_tick();
        double elapsed_since_last_report = t1_progress - t0_progress;
        if (elapsed_since_last_report < 0.1) elapsed_since_last_report = 0.1; // Avoid division by zero if timer resolution is low

		instantKeyRate = (double)(currentTotalCount - lastTotalCount) / elapsed_since_last_report;
		instantGpuKeyRate = (double)(currentGpuCount - lastGpuCount) / elapsed_since_last_report;
		
        lastKeyRateHistory[historyFilterPos % SMOOTH_FILTER_SIZE] = instantKeyRate;
		lastGpuKeyRateHistory[historyFilterPos % SMOOTH_FILTER_SIZE] = instantGpuKeyRate;
		historyFilterPos++;

		double avgKeyRate = 0.0;
		double avgGpuKeyRate = 0.0;
		uint32_t numSamplesInAvg;
		for (numSamplesInAvg = 0; (numSamplesInAvg < SMOOTH_FILTER_SIZE) && (numSamplesInAvg < historyFilterPos); numSamplesInAvg++) {
			avgKeyRate += lastKeyRateHistory[numSamplesInAvg];
			avgGpuKeyRate += lastGpuKeyRateHistory[numSamplesInAvg];
		}
        if (numSamplesInAvg > 0) {
		    avgKeyRate /= (double)(numSamplesInAvg);
		    avgGpuKeyRate /= (double)(numSamplesInAvg);
        }


		if (isAlive(params)) { // Check again, as threads might have finished during sleep/calcs
			memset(timeStrBuff, '\0', 256);
            double running_time_seconds = t1_progress - startTime; // Total running time

			printf("\r[%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [C: %.2f %%] [R: %llu] [T: %s (%d bit)] [F: %u]  ",
				toTimeStr((int)running_time_seconds, timeStrBuff),
				avgKeyRate / 1000000.0,
				avgGpuKeyRate / 1000000.0,
				completedPercentage,
				rKeyRolloverCount,
				formatThousands(currentTotalCount).c_str(),
				completedKeyBits,
				nbFoundKey);
            fflush(stdout); // Ensure output is displayed
		}

		if (rKey > 0) {
            // Check if currentTotalCount (derived from counters) has exceeded the next rKey milestone
            // lastrKey stores the total count at the *last* rKey rollover.
			if ((currentTotalCount - lastrKey) >= (1000000 * rKey)) {
				rKeyRequest(params);
				lastrKey = currentTotalCount; // Update for the next milestone
				rKeyRolloverCount++;
                printf("\nRandom key rollover requested. Rollover count: %llu\n", rKeyRolloverCount);
			}
		}

		lastTotalCount = currentTotalCount;
		lastGpuCount = currentGpuCount;
		t0_progress = t1_progress; // Set baseline for next report period

        // Exit conditions
		if (should_exit_flag || (maxFound > 0 && nbFoundKey >= maxFound) || (rKey <= 0 && completedPercentage >= 100.0) ) {
			endOfSearch = true;
            printf("\nSearch termination condition met. Exiting...\n");
        }
	}
    printf("\nSearch loop finished. Total keys found: %u\n", nbFoundKey);

    if (params) { // Wait for threads to actually exit if they were told to.
        if(totalEffectiveThreads > 0) {
             printf("Waiting for all threads to terminate...\n");
             for(int i=0; i < totalEffectiveThreads; ++i) {
                 // How to properly join pthreads/Windows threads would be platform specific
                 // For now, a simple loop checking isRunning
                 while(params[i].isRunning) {
                     Timer::SleepMillis(100);
                 }
             }
             printf("All threads terminated.\n");
        }
	    free(params);
    }

#ifdef WIN64
    if (ghMutex != NULL) CloseHandle(ghMutex);
#else
    // Assuming ghMutex was initialized if used
    // pthread_mutex_destroy(&ghMutex); // If initialized
#endif


}

// ----------------------------------------------------------------------------

std::string ComputeUnitOptimizer::GetHex(std::vector<unsigned char> &buffer)
{
	std::string ret;
	char tmp[3]; // For "%02X" and null terminator
	for (size_t i = 0; i < buffer.size(); i++) {
		sprintf(tmp, "%02X", buffer[i]);
		ret.append(tmp);
	}
	return ret;
}

// ----------------------------------------------------------------------------
// CheckBloomBinary: Returns 1 if found in DATA via binary search, 0 otherwise.
// Relies on DATA being sorted.
// ----------------------------------------------------------------------------
int ComputeUnitOptimizer::CheckBloomBinary(const uint8_t * _xx, uint32_t K_LENGTH)
{
    // First, check the Bloom filter as a quick negative test
	if (bloom->check(_xx, K_LENGTH) == 0) { // Bloom filter says "definitely not in set"
        return 0;
    }

    // Bloom filter is positive (might be in set, or false positive)
    // Now perform binary search on the sorted DATA array
	uint8_t* temp_read;
	uint64_t min_idx, max_idx, current_idx;
	int64_t rcmp;

	min_idx = 0;
	max_idx = TOTAL_COUNT; // TOTAL_COUNT is the number of items, so max_idx is one beyond the last element

	while (min_idx < max_idx) { // Loop while the search space is valid
		current_idx = min_idx + (max_idx - min_idx) / 2; // Avoid overflow, find middle
        if (current_idx >= TOTAL_COUNT) { // Boundary check, should not happen if max_idx is correct
            return 0;
        }
		temp_read = DATA + (current_idx * K_LENGTH);
		rcmp = memcmp(_xx, temp_read, K_LENGTH);

		if (rcmp == 0) {
			return 1;  // Found!
		} else if (rcmp < 0) { // _xx is less than temp_read
			max_idx = current_idx; // Search in the lower half
		} else { // _xx is greater than temp_read
			min_idx = current_idx + 1; // Search in the upper half
		}
	}
	return 0; // Not found after binary search
}

// ----------------------------------------------------------------------------

bool ComputeUnitOptimizer::MatchHash(uint32_t * _h) // _h is a HASH160 (20 bytes = 5 uint32_t)
{
    // hash160Keccak is the target hash (also 5 uint32_t)
	if (_h[0] == hash160Keccak[0] &&
		_h[1] == hash160Keccak[1] &&
		_h[2] == hash160Keccak[2] &&
		_h[3] == hash160Keccak[3] &&
		_h[4] == hash160Keccak[4]) {
		return true;
	}
	else {
		return false;
	}
}

// ----------------------------------------------------------------------------

bool ComputeUnitOptimizer::MatchXPoint(uint32_t * _h) // _h is an XPoint (32 bytes = 8 uint32_t)
{
    // xpoint is the target XPoint (also 8 uint32_t)
	if (_h[0] == xpoint[0] &&
		_h[1] == xpoint[1] &&
		_h[2] == xpoint[2] &&
		_h[3] == xpoint[3] &&
		_h[4] == xpoint[4] &&
		_h[5] == xpoint[5] &&
		_h[6] == xpoint[6] &&
		_h[7] == xpoint[7]) {
		return true;
	}
	else {
		return false;
	}
}

// ----------------------------------------------------------------------------

std::string ComputeUnitOptimizer::formatThousands(uint64_t x)
{
	char buf[32] = "";
	sprintf(buf, "%llu", x);
	std::string s(buf);

	int len = (int)s.length();
	int numCommas = (len - 1) / 3;

	if (numCommas == 0) {
		return s;
	}

	std::string result = "";
    result.reserve(len + numCommas); // Pre-allocate memory

	int firstSegmentLen = len % 3;
    if (firstSegmentLen == 0) firstSegmentLen = 3;

    result.append(s.substr(0, firstSegmentLen));

    for (int i = firstSegmentLen; i < len; i += 3) {
        result += ",";
        result.append(s.substr(i, 3));
    }
	return result;
}

// ----------------------------------------------------------------------------

char* ComputeUnitOptimizer::toTimeStr(int total_seconds, char* timeStr) // Made total_seconds const
{
	if (total_seconds < 0) total_seconds = 0;
	int h, m, s;
	h = (total_seconds / 3600);
	m = (total_seconds % 3600) / 60; // Corrected calculation for minutes
	s = total_seconds % 60;       // Corrected calculation for seconds
	sprintf(timeStr, "%02d:%02d:%02d", h, m, s); // Use %02d for consistent two digits
	return timeStr; // No need to cast to (char*)
}

// ----------------------------------------------------------------------------
// ((input - min) * 100.0) / (max - min)
// Calculates percentage completion.
// currentProgress is the number of keys processed *from the beginning of the entire search space*.
// range_offset is the starting key of the entire search space.
// total_range_span is the total number of keys in the entire search space.
double ComputeUnitOptimizer::CalcPercantage(Int& currentProgress_from_start, Int& range_offset, Int& total_range_span)
{
    if (total_range_span.IsZero()) {
        return currentProgress_from_start.IsZero() ? 0.0 : 100.0; // Avoid division by zero
    }

    // We need to calculate how many keys have been processed *within the current search's defined range*.
    // If currentProgress_from_start is already relative to the search's global start (this->rangeStart),
    // then no subtraction of range_offset is needed before comparison.
    // Assuming currentProgress_from_start IS the count from global this->rangeStart.

    // Int actual_processed_in_range;
    // actual_processed_in_range.Set(¤tProgress_from_start);
    // No, currentProgress_from_start is the total keys from 0 or an absolute start.
    // The Search() function initializes progress from 0 for the given range.
    // So currentProgress_from_start IS effectively (current_key - global_range_start)

    // Using mpf for floating point arithmetic with large integers for precision.
	mpf_class num(currentProgress_from_start.GetBase10().c_str()); // Keys processed in current range
	mpf_class den(total_range_span.GetBase10().c_str());    // Total keys in the current search's range

    if (den == 0) return 0.0; // Avoid division by zero

    mpf_class perc = (num * 100.0) / den;
    double result = perc.get_d();

    if (result < 0.0) result = 0.0;
    if (result > 100.0) result = 100.0; // Cap at 100%

    return result;
}
// ----------------------------------------------------------------------------
