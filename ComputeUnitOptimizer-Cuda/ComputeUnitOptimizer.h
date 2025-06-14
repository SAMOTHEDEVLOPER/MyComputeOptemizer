#ifndef KEYHUNTH
#define KEYHUNTH

#include <string>
#include <vector>
#include "SECP256k1.h"
#include "Bloom.h"
#include "GPU/GPUEngine.h"
#ifdef WIN64
#include <Windows.h>
#else
#include <pthread.h>
#endif

#define CPU_GRP_SIZE (1024*2)

class ComputeUnitOptimizer;

typedef struct {
	ComputeUnitOptimizer* obj;
	int  threadId;
	bool isRunning;
	bool hasStarted;
	int  gridSizeX;
	int  gridSizeY;
	int  gpuId;
	Int rangeStart;
	Int rangeEnd;
	bool rKeyRequest;
} TH_PARAM;


class ComputeUnitOptimizer
{
public:
	// Constructor for address/xpoint list mode
	ComputeUnitOptimizer(const std::string& inputFile, int compMode, int searchMode, int coinType, bool useGpu,
		const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
		const std::string& rangeStart, const std::string& rangeEnd, volatile bool& should_exit);

	// Constructor for single address/xpoint mode
	ComputeUnitOptimizer(const std::vector<unsigned char>& hashORxpoint, int compMode, int searchMode, int coinType,
		bool useGpu, const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
		const std::string& rangeStart, const std::string& rangeEnd, volatile bool& should_exit);

	~ComputeUnitOptimizer();

	// Main entry point to start the search
	void Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, volatile bool& should_exit);

	void FindKeyCPU(TH_PARAM* p);
	void FindKeyGPU(TH_PARAM* p);

private:
	// --- Initialization and Setup ---
	void InitGenratorTable();
	void SetupRanges(uint32_t totalThreads);
	void getCPUStartingKey(Int& tRangeStart, Int& tRangeEnd, Int& key, Point& startP);
	void getGPUStartingKeys(Int& tRangeStart, Int& tRangeEnd, int groupSize, int nbThread, Int* keys, Point* p);
	
	// --- Point Processing and Verification ---
	void processPoint(const Point& p, const Int& baseKey, int index, bool compressed);
	void checkAddressesSSE(bool compressed, Int& key, int i, Point& p1, Point& p2, Point& p3, Point& p4);
	void processGpuResult(const ITEM& item, Int* keys);
	bool checkPrivKey(std::string addr, Int& key, int32_t incr, bool mode);
	bool checkPrivKeyETH(std::string addr, Int& key, int32_t incr);
	bool checkPrivKeyX(Int& key, int32_t incr, bool mode);

	// --- Low-level hash matching ---
	int CheckBloomBinary(const uint8_t* _xx, uint32_t K_LENGTH);
	bool MatchHash(uint32_t* _h);
	bool MatchXPoint(uint32_t* _h);
	
	// --- Thread Management & Reporting ---
	void output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey);
	bool isAlive(TH_PARAM* p);
	bool hasStarted(TH_PARAM* p);
	uint64_t getGPUCount();
	uint64_t getCPUCount();
	void rKeyRequest(TH_PARAM* p);
	
	// --- Utility ---
	std::string GetHex(const std::vector<unsigned char>& buffer);
	std::string formatThousands(uint64_t x);
	char* toTimeStr(int sec, char* timeStr);
	
	// Member Variables
	Secp256K1* secp;
	Bloom* bloom;
	int compMode;
	int searchMode;
	int coinType;
	bool useGpu;
	bool useSSE;
	
	bool endOfSearch;
	int nbCPUThread;
	int nbGPUThread;
	uint64_t counters[256];
	double startTime;

	std::string inputFile;
	uint32_t hash160Keccak[5];
	uint32_t xpoint[8];
	
	Int rangeStart;
	Int rangeEnd;
	Int rangeDiff;
	Int rangeDiff2;
	
	std::string outputFile;
	uint32_t maxFound;
	uint32_t nbFoundKey;
	uint64_t targetCounter;

	uint64_t rKey;
	uint64_t lastrKey;

	uint8_t* DATA;
	uint64_t TOTAL_COUNT;
	uint64_t BLOOM_N;

#ifdef WIN64
	HANDLE outputMutex;
#else
	pthread_mutex_t outputMutex;
#endif
};

#endif // KEYHUNTH
