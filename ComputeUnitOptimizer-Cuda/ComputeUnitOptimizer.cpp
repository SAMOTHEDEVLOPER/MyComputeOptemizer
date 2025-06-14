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
#include <inttypes.h> // For PRIu64
#ifndef WIN64
#include <pthread.h>
#endif

// Precomputed generator points for fast key derivation
Point Gn[CPU_GRP_SIZE / 2];
Point _2Gn; // 2*Gn

ComputeUnitOptimizer::ComputeUnitOptimizer(const std::string& inputFile, int compMode, int searchMode, int coinType, bool useGpu,
	const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
	const std::string& rangeStart, const std::string& rangeEnd, volatile bool& should_exit)
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

	secp = new Secp256K1();
	secp->Init();

	// Load address or xpoint data from file
	FILE* wfd = fopen(this->inputFile.c_str(), "rb");
	if (!wfd) {
		printf("%s can not open\n", this->inputFile.c_str());
		exit(1);
	}

#ifdef WIN64
	_fseeki64(wfd, 0, SEEK_END);
	uint64_t N = _ftelli64(wfd);
#else
	fseek(wfd, 0, SEEK_END);
	uint64_t N = ftell(wfd);
#endif

	int K_LENGTH = (this->searchMode == SEARCH_MODE_MX) ? 32 : 20;

	N = N / K_LENGTH;
	rewind(wfd);

	DATA = (uint8_t*)malloc(N * K_LENGTH);
	memset(DATA, 0, N * K_LENGTH);
	
	uint8_t* buf = (uint8_t*)malloc(K_LENGTH);
	bloom = new Bloom(2 * N, 0.000001);

	printf("\n");
	uint64_t percent = (N > 100) ? (N - 1) / 100 : 0;
	uint64_t i = 0;
	while (i < N && !should_exit) {
		if (fread(buf, 1, K_LENGTH, wfd) == K_LENGTH) {
			bloom->add(buf, K_LENGTH);
			memcpy(DATA + (i * K_LENGTH), buf, K_LENGTH);
			if (percent > 0 && i % percent == 0) {
				// Use PRIu64 for portable uint64_t printing
				printf("\rLoading      : %" PRIu64 " %%", (i / percent));
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
	targetCounter = i;
	printf("\rLoading      : 100 %%\n");
	if (coinType == COIN_BTC) {
		if (searchMode == SEARCH_MODE_MA)
			printf("Loaded       : %s Bitcoin addresses\n", formatThousands(i).c_str());
		else if (searchMode == SEARCH_MODE_MX)
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

ComputeUnitOptimizer::ComputeUnitOptimizer(const std::vector<unsigned char>& hashORxpoint, int compMode, int searchMode, int coinType,
	bool useGpu, const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey,
	const std::string& rangeStart, const std::string& rangeEnd, volatile bool& should_exit)
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
	this->targetCounter = 1;

	secp = new Secp256K1();
	secp->Init();

	if (this->searchMode == SEARCH_MODE_SA) {
		assert(hashORxpoint.size() == 20);
		memcpy(hash160Keccak, hashORxpoint.data(), 20);
	}
	else if (this->searchMode == SEARCH_MODE_SX) {
		assert(hashORxpoint.size() == 32);
		memcpy(xpoint, hashORxpoint.data(), 32);
	}
	printf("\n");

	InitGenratorTable();
}

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

	char ctimeBuff[64];
	time_t now = time(NULL);
#ifdef WIN64
    ctime_s(ctimeBuff, sizeof(ctimeBuff), &now);
	printf("Start Time   : %s", ctimeBuff);
#else
	printf("Start Time   : %s", ctime_r(&now, ctimeBuff));
#endif

	if (rKey > 0) {
		// Use PRIu64 for portable uint64_t printing
		printf("Base Key     : Randomly changes on every %" PRIu64 " Mkeys\n", rKey);
	}
	printf("Global start : %s (%d bit)\n", this->rangeStart.GetBase16().c_str(), this->rangeStart.GetBitLength());
	printf("Global end   : %s (%d bit)\n", this->rangeEnd.GetBase16().c_str(), this->rangeEnd.GetBitLength());
	printf("Global range : %s (%d bit)\n", this->rangeDiff2.GetBase16().c_str(), this->rangeDiff2.GetBitLength());
}

ComputeUnitOptimizer::~ComputeUnitOptimizer()
{
	delete secp;
	if (searchMode == SEARCH_MODE_MA || searchMode == SEARCH_MODE_MX)
		delete bloom;
	if (DATA)
		free(DATA);
}

void ComputeUnitOptimizer::output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey)
{
#ifdef WIN64
	WaitForSingleObject(outputMutex, INFINITE);
#else
	pthread_mutex_lock(&outputMutex);
#endif

	FILE* f = stdout;
	bool needToClose = false;

	if (!outputFile.empty()) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("Cannot open %s for writing\n", outputFile.c_str());
			f = stdout;
		}
		else {
			needToClose = true;
		}
	}

	if (!needToClose) printf("\n");

	fprintf(f, "PubAddress: %s\n", addr.c_str());
	fprintf(stdout, "\n=================================================================================\n");
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

	if (needToClose) fclose(f);

#ifdef WIN64
	ReleaseMutex(outputMutex);
#else
	pthread_mutex_unlock(&outputMutex);
#endif
}

bool ComputeUnitOptimizer::checkPrivKey(std::string addr, Int& key, int32_t incr, bool mode)
{
	Int k(key);
	k.Add(incr);
	
	Point p = secp->ComputePublicKey(&k);
	if (secp->GetAddress(mode, p) != addr) {
		// Try the negative key
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		if (secp->GetAddress(mode, p) != addr) {
			printf("\nERROR: Private key verification failed for address %s\n", addr.c_str());
			return false;
		}
	}
	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

bool ComputeUnitOptimizer::checkPrivKeyETH(std::string addr, Int& key, int32_t incr)
{
	Int k(key);
	k.Add(incr);
	
	Point p = secp->ComputePublicKey(&k);
	if (secp->GetAddressETH(p) != addr) {
		// Try the negative key
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		if (secp->GetAddressETH(p) != addr) {
			printf("\nERROR: Private key verification failed for address %s\n", addr.c_str());
			return false;
		}
	}
	output(addr, "", k.GetBase16(), secp->GetPublicKeyHexETH(p));
	return true;
}

bool ComputeUnitOptimizer::checkPrivKeyX(Int& key, int32_t incr, bool mode)
{
	Int k(key);
	k.Add(incr);
	Point p = secp->ComputePublicKey(&k);
	std::string addr = secp->GetAddress(mode, p);
	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

#ifdef WIN64
DWORD WINAPI _FindKeyCPU(LPVOID lpParam)
#else
void* _FindKeyCPU(void* lpParam)
#endif
{
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyCPU(p);
	return 0;
}

#ifdef WIN64
DWORD WINAPI _FindKeyGPU(LPVOID lpParam)
#else
void* _FindKeyGPU(void* lpParam)
#endif
{
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyGPU(p);
	return 0;
}

void ComputeUnitOptimizer::processPoint(const Point& p, const Int& baseKey, int index, bool compressed)
{
	// Create a non-const copy of baseKey to pass to checker functions
	Int mutableBaseKey = baseKey;
	
	// For ETH, compression is irrelevant as addresses are derived from the full public key
	if (coinType == COIN_ETH) {
		unsigned char h[20];
		secp->GetHashETH(p, h);
		bool match = (searchMode == SEARCH_MODE_MA) ? (CheckBloomBinary(h, 20) > 0) : MatchHash((uint32_t*)h);
		if (match) {
			std::string addr = secp->GetAddressETH(h);
			if (checkPrivKeyETH(addr, mutableBaseKey, index)) {
				nbFoundKey++;
			}
		}
		return;
	}

	// For BTC and other coins that use hash160 or X-points
	switch (searchMode) {
	case SEARCH_MODE_MA: {
		unsigned char h[20];
		secp->GetHash160(compressed, p, h);
		if (CheckBloomBinary(h, 20) > 0) {
			std::string addr = secp->GetAddress(compressed, h);
			if (checkPrivKey(addr, mutableBaseKey, index, compressed)) {
				nbFoundKey++;
			}
		}
		break;
	}
	case SEARCH_MODE_SA: {
		unsigned char h[20];
		secp->GetHash160(compressed, p, h);
		if (MatchHash((uint32_t*)h)) {
			std::string addr = secp->GetAddress(compressed, h);
			if (checkPrivKey(addr, mutableBaseKey, index, compressed)) {
				nbFoundKey++;
			}
		}
		break;
	}
	case SEARCH_MODE_MX: {
		unsigned char h[32];
		secp->GetXBytes(compressed, p, h);
		if (CheckBloomBinary(h, 32) > 0) {
			if (checkPrivKeyX(mutableBaseKey, index, compressed)) {
				nbFoundKey++;
			}
		}
		break;
	}
	case SEARCH_MODE_SX: {
		unsigned char h[32];
		secp->GetXBytes(compressed, p, h);
		if (MatchXPoint((uint32_t*)h)) {
			if (checkPrivKeyX(mutableBaseKey, index, compressed)) {
				nbFoundKey++;
			}
		}
		break;
	}
	}
}

void ComputeUnitOptimizer::checkAddressesSSE(bool compressed, Int& key, int i, Point& p1, Point& p2, Point& p3, Point& p4)
{
	unsigned char h0[20], h1[20], h2[20], h3[20];
	secp->GetHash160(compressed, p1, p2, p3, p4, h0, h1, h2, h3);

	auto checkAndVerify = [&](unsigned char* h, int offset) {
		bool match = (searchMode == SEARCH_MODE_MA) ? (CheckBloomBinary(h, 20) > 0) : MatchHash((uint32_t*)h);
		if (match) {
			std::string addr = secp->GetAddress(compressed, h);
			if (checkPrivKey(addr, key, i + offset, compressed)) {
				nbFoundKey++;
			}
		}
	};

	checkAndVerify(h0, 0);
	checkAndVerify(h1, 1);
	checkAndVerify(h2, 2);
	checkAndVerify(h3, 3);
}

void ComputeUnitOptimizer::getCPUStartingKey(Int& tRangeStart, Int& tRangeEnd, Int& key, Point& startP)
{
	if (rKey <= 0) {
		key.Set(&tRangeStart);
	}
	else {
		key.Rand(&tRangeEnd);
	}
	Int km(key);
	km.Add(CPU_GRP_SIZE / 2);
	startP = secp->ComputePublicKey(&km);
}

void ComputeUnitOptimizer::FindKeyCPU(TH_PARAM* ph)
{
	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;
	counters[thId] = 0;

	IntGroup grp(CPU_GRP_SIZE / 2 + 1);
	Int* dx = new Int[CPU_GRP_SIZE / 2 + 1];
	Point* pts = new Point[CPU_GRP_SIZE];
	grp.Set(dx);

	// Use stack-based objects for intermediate calculations to avoid heap allocation overhead
	Int dy, dyn, _s, _p;
	Point pp, pn;

	Int key;
	Point startP;
	getCPUStartingKey(tRangeStart, tRangeEnd, key, startP);

	ph->hasStarted = true;
	ph->rKeyRequest = false;

	while (!endOfSearch) {

		if (ph->rKeyRequest) {
			getCPUStartingKey(tRangeStart, tRangeEnd, key, startP);
			ph->rKeyRequest = false;
		}

		// Fill group with delta-x values for batch modular inversion
		int i;
		int hLength = (CPU_GRP_SIZE / 2 - 1);
		for (i = 0; i < hLength; i++) {
			dx[i].ModSub(&Gn[i].x, &startP.x);
		}
		dx[i].ModSub(&Gn[i].x, &startP.x);      // For the first point
		dx[i + 1].ModSub(&_2Gn.x, &startP.x);   // For the next center point

		grp.ModInv(); // Perform batch modular inversion

		// center point
		pts[CPU_GRP_SIZE / 2] = startP;

		// Calculate points in the group: P +/- i*G
		for (i = 0; i < hLength && !endOfSearch; i++) {
			pp = startP;
			pn = startP;

			// P = startP + i*G
			dy.ModSub(&Gn[i].y, &pp.y);
			_s.ModMulK1(&dy, &dx[i]);
			_p.ModSquareK1(&_s);
			pp.x.ModNeg();
			pp.x.ModAdd(&_p);
			pp.x.ModSub(&Gn[i].x);
			pp.y.ModSub(&Gn[i].x, &pp.x);
			pp.y.ModMulK1(&_s);
			pp.y.ModSub(&Gn[i].y);

			// P = startP - i*G
			dyn.Set(&Gn[i].y);
			dyn.ModNeg();
			dyn.ModSub(&pn.y);
			_s.ModMulK1(&dyn, &dx[i]);
			_p.ModSquareK1(&_s);
			pn.x.ModNeg();
			pn.x.ModAdd(&_p);
			pn.x.ModSub(&Gn[i].x);
			pn.y.ModSub(&Gn[i].x, &pn.x);
			pn.y.ModMulK1(&_s);
			pn.y.ModAdd(&Gn[i].y);

			pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
			pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
		}

		// First point (startP - (GRP_SIZE/2)*G)
		pn = startP;
		dyn.Set(&Gn[i].y);
		dyn.ModNeg();
		dyn.ModSub(&pn.y);
		_s.ModMulK1(&dyn, &dx[i]);
		_p.ModSquareK1(&_s);
		pn.x.ModNeg();
		pn.x.ModAdd(&_p);
		pn.x.ModSub(&Gn[i].x);
		pn.y.ModSub(&Gn[i].x, &pn.x);
		pn.y.ModMulK1(&_s);
		pn.y.ModAdd(&Gn[i].y);
		pts[0] = pn;

		// Next start point (startP + GRP_SIZE*G)
		pp = startP;
		dy.ModSub(&_2Gn.y, &pp.y);
		_s.ModMulK1(&dy, &dx[i + 1]);
		_p.ModSquareK1(&_s);
		pp.x.ModNeg();
		pp.x.ModAdd(&_p);
		pp.x.ModSub(&_2Gn.x);
		pp.y.ModSub(&_2Gn.x, &pp.x);
		pp.y.ModMulK1(&_s);
		pp.y.ModSub(&_2Gn.y);
		startP = pp;

		// Check generated points
		if (useSSE && coinType != COIN_ETH) {
			for (i = 0; i < CPU_GRP_SIZE && !endOfSearch; i += 4) {
				if (compMode == SEARCH_COMPRESSED || compMode == SEARCH_BOTH) {
					checkAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
				}
				if (compMode == SEARCH_UNCOMPRESSED || compMode == SEARCH_BOTH) {
					checkAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
				}
			}
		}
		else {
			for (i = 0; i < CPU_GRP_SIZE && !endOfSearch; i++) {
				if (coinType == COIN_ETH) {
					processPoint(pts[i], key, i, false);
				}
				else {
					if (compMode == SEARCH_COMPRESSED || compMode == SEARCH_BOTH) {
						processPoint(pts[i], key, i, true);
					}
					if (compMode == SEARCH_UNCOMPRESSED || compMode == SEARCH_BOTH) {
						processPoint(pts[i], key, i, false);
					}
				}
			}
		}

		key.Add(CPU_GRP_SIZE);
		counters[thId] += CPU_GRP_SIZE;
	}
	ph->isRunning = false;

	delete[] dx;
	delete[] pts;
}

void ComputeUnitOptimizer::getGPUStartingKeys(Int& tRangeStart, Int& tRangeEnd, int groupSize, int nbThread, Int* keys, Point* p)
{
	Int tRangeDiff(tRangeEnd);
	Int tRangeStart2(tRangeStart);
	Int tRangeEnd2(tRangeStart);

	Int tThreads;
	tThreads.SetInt32(nbThread);
	tRangeDiff.Set(&tRangeEnd);
	tRangeDiff.Sub(&tRangeStart);
	tRangeDiff.Div(&tThreads);

	for (int i = 0; i < nbThread; i++) {
		tRangeEnd2.Set(&tRangeStart2);
		tRangeEnd2.Add(&tRangeDiff);

		if (rKey <= 0)
			keys[i].Set(&tRangeStart2);
		else
			keys[i].Rand(&tRangeEnd2);

		tRangeStart2.Add(&tRangeDiff);

		Int k(keys + i);
		k.Add((uint64_t)(groupSize / 2));	// Starting key is at the middle of the group
		p[i] = secp->ComputePublicKey(&k);
	}
}

void ComputeUnitOptimizer::processGpuResult(const ITEM& item, Int* keys)
{
	if (endOfSearch) return;

	bool found = false;
	switch (searchMode) {
	case SEARCH_MODE_MA:
	case SEARCH_MODE_SA:
		if (coinType == COIN_BTC) {
			std::string addr = secp->GetAddress(item.mode, item.hash);
			found = checkPrivKey(addr, keys[item.thId], item.incr, item.mode);
		}
		else { // COIN_ETH
			std::string addr = secp->GetAddressETH(item.hash);
			found = checkPrivKeyETH(addr, keys[item.thId], item.incr);
		}
		break;
	case SEARCH_MODE_MX:
	case SEARCH_MODE_SX:
		found = checkPrivKeyX(keys[item.thId], item.incr, item.mode);
		break;
	}

	if (found) {
		nbFoundKey++;
	}
}


void ComputeUnitOptimizer::FindKeyGPU(TH_PARAM* ph)
{
#ifdef WITHGPU
	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;

	GPUEngine* g;
	switch (searchMode) {
	case SEARCH_MODE_MA:
	case SEARCH_MODE_MX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			BLOOM_N, bloom->get_bits(), bloom->get_hashes(), bloom->get_bf(), DATA, TOTAL_COUNT, (rKey != 0));
		break;
	case SEARCH_MODE_SA:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			hash160Keccak, (rKey != 0));
		break;
	case SEARCH_MODE_SX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			xpoint, (rKey != 0));
		break;
	default:
		printf("Invalid search mode for GPU");
		ph->isRunning = false;
		return;
	}

	int nbThread = g->GetNbThread();
	Point* p = new Point[nbThread];
	Int* keys = new Int[nbThread];
	std::vector<ITEM> found;

	printf("GPU          : %s\n\n", g->deviceName.c_str());
	counters[thId] = 0;

	getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
	bool ok = g->SetKeys(p);

	ph->hasStarted = true;
	ph->rKeyRequest = false;

	while (ok && !endOfSearch) {
		if (ph->rKeyRequest) {
			getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
			ok = g->SetKeys(p);
			ph->rKeyRequest = false;
		}

		// Launch kernel and check for results
		found.clear();
		switch (searchMode) {
		case SEARCH_MODE_MA: ok = g->LaunchSEARCH_MODE_MA(found, false); break;
		case SEARCH_MODE_MX: ok = g->LaunchSEARCH_MODE_MX(found, false); break;
		case SEARCH_MODE_SA: ok = g->LaunchSEARCH_MODE_SA(found, false); break;
		case SEARCH_MODE_SX: ok = g->LaunchSEARCH_MODE_SX(found, false); break;
		default: ok = false; break;
		}

		if (!found.empty()) {
			for (const auto& item : found) {
				processGpuResult(item, keys);
				if (endOfSearch) break;
			}
		}

		if (ok) {
			for (int i = 0; i < nbThread; i++) {
				keys[i].Add(STEP_SIZE);
			}
			counters[thId] += (uint64_t)STEP_SIZE * nbThread;
		}
	}

	delete[] keys;
	delete[] p;
	delete g;

#else
	ph->hasStarted = true;
	printf("GPU support not compiled. Please use -DWITHGPU during compilation.\n");
#endif

	ph->isRunning = false;
}

bool ComputeUnitOptimizer::isAlive(TH_PARAM* p)
{
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		if (!p[i].isRunning) return false;
	return true;
}

bool ComputeUnitOptimizer::hasStarted(TH_PARAM* p)
{
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		if (!p[i].hasStarted) return false;
	return true;
}

uint64_t ComputeUnitOptimizer::getGPUCount()
{
	uint64_t count = 0;
	for (int i = 0; i < nbGPUThread; i++)
		count += counters[0x80L + i];
	return count;
}

uint64_t ComputeUnitOptimizer::getCPUCount()
{
	uint64_t count = 0;
	for (int i = 0; i < nbCPUThread; i++)
		count += counters[i];
	return count;
}

void ComputeUnitOptimizer::rKeyRequest(TH_PARAM* p) {
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		p[i].rKeyRequest = true;
}

void ComputeUnitOptimizer::SetupRanges(uint32_t totalThreads)
{
	Int threads;
	threads.SetInt32(totalThreads);
	rangeDiff.Set(&rangeEnd);
	rangeDiff.Sub(&rangeStart);
	rangeDiff.Div(&threads);
}

void ComputeUnitOptimizer::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, volatile bool& should_exit)
{
	endOfSearch = false;
	nbCPUThread = nbThread;
	nbGPUThread = useGpu ? (int)gpuId.size() : 0;
	nbFoundKey = 0;
	uint32_t totalThreads = nbCPUThread + nbGPUThread;

	if (totalThreads == 0) {
		printf("Error: No CPU or GPU threads specified.\n");
		return;
	}

	SetupRanges(totalThreads);
	memset(counters, 0, sizeof(counters));

	if (!useGpu) printf("\n");

	TH_PARAM* params = new TH_PARAM[totalThreads];
	memset(params, 0, totalThreads * sizeof(TH_PARAM));

#ifdef WIN64
	outputMutex = CreateMutex(NULL, FALSE, NULL);
#else
	pthread_mutex_init(&outputMutex, NULL);
#endif

	// Launch CPU threads
	for (int i = 0; i < nbCPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = i;
		params[i].isRunning = true;
		params[i].rangeStart.Set(&rangeStart);
		rangeStart.Add(&rangeDiff);
		params[i].rangeEnd.Set(&rangeStart);

#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyCPU, (void*)¶ms[i], 0, &thread_id);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyCPU, (void*)¶ms[i]);
#endif
	}

	// Launch GPU threads
	for (int i = 0; i < nbGPUThread; i++) {
		int param_idx = nbCPUThread + i;
		params[param_idx].obj = this;
		params[param_idx].threadId = 0x80L + i; // Differentiate GPU counters
		params[param_idx].isRunning = true;
		params[param_idx].gpuId = gpuId[i];
		params[param_idx].gridSizeX = gridSize.empty() ? -1 : gridSize[2*i];
		params[param_idx].gridSizeY = gridSize.empty() ? 128 : gridSize[2*i+1];

		params[param_idx].rangeStart.Set(&rangeStart);
		rangeStart.Add(&rangeDiff);
		params[param_idx].rangeEnd.Set(&rangeStart);

#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyGPU, (void*)¶ms[param_idx], 0, &thread_id);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyGPU, (void*)¶ms[param_idx]);
#endif
	}

#ifndef WIN64
	setvbuf(stdout, NULL, _IONBF, 0);
#endif
	printf("\n");

	uint64_t lastCount = 0;
	uint64_t lastGPUCount = 0;

	// Key rate smoothing filter
	const int FILTER_SIZE = 8;
	double lastkeyRate[FILTER_SIZE] = { 0 };
	double lastGpukeyRate[FILTER_SIZE] = { 0 };
	uint32_t filterPos = 0;

	// Wait for all threads to start
	while (!hasStarted(params)) {
		Timer::SleepMillis(500);
	}

	Timer::Init();
	double t0 = Timer::get_tick();
	startTime = t0;
	Int p100, ICount;
	p100.SetInt32(100);
	uint64_t rKeyCount = 0;
	
	while (isAlive(params)) {
		Timer::SleepMillis(2000);

		uint64_t gpuCount = getGPUCount();
		uint64_t count = getCPUCount() + gpuCount;

		double completedPerc = 0.0;
		if (rKey <= 0 && !rangeDiff2.IsZero()) {
			ICount.SetInt64(count);
			ICount.Mult(&p100);
			ICount.Div(&this->rangeDiff2);
			completedPerc = std::stod(ICount.GetBase10());
		}

		double t1 = Timer::get_tick();
		double elapsed = (t1 - t0 > 0.0) ? (t1 - t0) : 1.0;
		double keyRate = (double)(count - lastCount) / elapsed;
		double gpuKeyRate = (double)(gpuCount - lastGPUCount) / elapsed;
		
		lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
		lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
		filterPos++;

		// Average keyrate
		double avgKeyRate = 0.0;
		double avgGpuKeyRate = 0.0;
		uint32_t nbSample = std::min((uint32_t)FILTER_SIZE, filterPos);
		for (uint32_t i = 0; i < nbSample; i++) {
			avgKeyRate += lastkeyRate[i];
			avgGpuKeyRate += lastGpukeyRate[i];
		}
		avgKeyRate /= (double)nbSample;
		avgGpuKeyRate /= (double)nbSample;
		
		char timeStr[256];
		// Use PRIu64 for portable uint64_t printing
		printf("\r[%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [C: %.2f %%] [R: %" PRIu64 "] [T: %s] [F: %u]  ",
			toTimeStr(t1 - startTime, timeStr),
			avgKeyRate / 1000000.0,
			avgGpuKeyRate / 1000000.0,
			completedPerc,
			rKeyCount,
			formatThousands(count).c_str(),
			nbFoundKey);
		fflush(stdout);

		if (rKey > 0) {
			if ((count - lastrKey) > (1000000 * rKey)) {
				rKeyRequest(params);
				lastrKey = count;
				rKeyCount++;
			}
		}

		lastCount = count;
		lastGPUCount = gpuCount;
		t0 = t1;

		if (should_exit || (maxFound > 0 && nbFoundKey >= maxFound) || (rKey <= 0 && completedPerc >= 100.0)) {
			endOfSearch = true;
		}
	}

	delete[] params;
}

std::string ComputeUnitOptimizer::GetHex(const std::vector<unsigned char>& buffer)
{
	std::string ret;
	char tmp[4];
	for (unsigned char val : buffer) {
		sprintf(tmp, "%02X", val);
		ret.append(tmp);
	}
	return ret;
}

int ComputeUnitOptimizer::CheckBloomBinary(const uint8_t* _xx, uint32_t K_LENGTH)
{
	if (bloom->check(_xx, K_LENGTH) > 0) {
		// Bloom filter match, perform binary search on the sorted list
		uint64_t min = 0;
		uint64_t max = TOTAL_COUNT;
		while (min < max) {
			uint64_t mid = min + (max - min) / 2;
			int rcmp = memcmp(_xx, DATA + (mid * K_LENGTH), K_LENGTH);
			if (rcmp == 0) {
				return 1; // Found
			}
			if (rcmp < 0) {
				max = mid;
			}
			else {
				min = mid + 1;
			}
		}
	}
	return 0;
}

bool ComputeUnitOptimizer::MatchHash(uint32_t* _h)
{
	return memcmp(_h, hash160Keccak, 20) == 0;
}

bool ComputeUnitOptimizer::MatchXPoint(uint32_t* _h)
{
	return memcmp(_h, xpoint, 32) == 0;
}

std::string ComputeUnitOptimizer::formatThousands(uint64_t x)
{
	std::string s = std::to_string(x);
	int n = s.length() - 3;
	while (n > 0) {
		s.insert(n, ",");
		n -= 3;
	}
	return s;
}

char* ComputeUnitOptimizer::toTimeStr(int sec, char* timeStr)
{
	int h = sec / 3600;
	int m = (sec % 3600) / 60;
	int s = sec % 60;
	sprintf(timeStr, "%02d:%02d:%02d", h, m, s);
	return timeStr;
}
