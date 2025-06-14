/*
* This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
* Copyright (c) 2019 Jean Luc PONS.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, version 3.
*
* This program is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file CuInt.cuh
 * @brief A CUDA device-side library for 256-bit integer arithmetic on the secp256k1 curve.
 *
 * This library provides highly optimized functions for modular arithmetic using raw
 * 64-bit integer arrays and inline PTX assembly for performance-critical operations.
 * The functions operate on numbers represented as arrays of 64-bit unsigned integers.
 */

#ifndef CU_INT_H
#define CU_INT_H

#include <stdint.h>

namespace CuInt {

// --- Configuration Constants ---

// Size of the group for batch processing.
constexpr int GRP_SIZE = 1024 * 2;
// Number of 64-bit words for 320-bit arithmetic (256 bits + 64-bit headroom).
constexpr int NUM_WORDS = 5;


// --- Low-Level PTX Assembly Macros for 64-bit Arithmetic ---
// These macros leverage the GPU's carry flag for efficient multi-precision arithmetic.

// Add with carry-out set
#define UADDO(c, a, b) asm volatile ("add.cc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b) : "memory" );
// Add with carry-in and carry-out
#define UADDC(c, a, b) asm volatile ("addc.cc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b) : "memory" );
// Add with carry-in
#define UADD(c, a, b) asm volatile ("addc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b));

// In-place add with carry-out set
#define UADDO1(c, a) asm volatile ("add.cc.u64 %0, %0, %1;" : "+l"(c) : "l"(a) : "memory" );
// In-place add with carry-in and carry-out
#define UADDC1(c, a) asm volatile ("addc.cc.u64 %0, %0, %1;" : "+l"(c) : "l"(a) : "memory" );
// In-place add with carry-in
#define UADD1(c, a) asm volatile ("addc.u64 %0, %0, %1;" : "+l"(c) : "l"(a));

// Subtract with carry-out set
#define USUBO(c, a, b) asm volatile ("sub.cc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b) : "memory" );
// Subtract with carry-in and carry-out
#define USUBC(c, a, b) asm volatile ("subc.cc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b) : "memory" );
// Subtract with carry-in
#define USUB(c, a, b) asm volatile ("subc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b));

// In-place subtract with carry-out set
#define USUBO1(c, a) asm volatile ("sub.cc.u64 %0, %0, %1;" : "+l"(c) : "l"(a) : "memory" );
// In-place subtract with carry-in and carry-out
#define USUBC1(c, a) asm volatile ("subc.cc.u64 %0, %0, %1;" : "+l"(c) : "l"(a) : "memory" );
// In-place subtract with carry-in
#define USUB1(c, a) asm volatile ("subc.u64 %0, %0, %1;" : "+l"(c) : "l"(a) );

// 64x64 multiplication
#define UMULLO(lo,a, b) asm volatile ("mul.lo.u64 %0, %1, %2;" : "=l"(lo) : "l"(a), "l"(b));
#define UMULHI(hi,a, b) asm volatile ("mul.hi.u64 %0, %1, %2;" : "=l"(hi) : "l"(a), "l"(b));

// 64x64 Fused-Multiply-Add (FMA)
#define MADDO(r,a,b,c) asm volatile ("mad.hi.cc.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c) : "memory" );
#define MADDC(r,a,b,c) asm volatile ("madc.hi.cc.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c) : "memory" );
#define MADD(r,a,b,c) asm volatile ("madc.hi.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
#define MADDS(r,a,b,c) asm volatile ("madc.hi.s64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));

// --- Curve Constants ---

// Constant for modular inverse: -P^-1 mod 2^64
static const uint64_t MOD_INV_CONSTANT_64 = 0xD838091DD2253531ULL;
// Constant for reduction: 2^32 + 977
static const uint64_t P_REDUCTION_TERM = 0x1000003D1ULL;
// SECP256k1 prime P
static const uint64_t P[4] = {
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};

// --- Inline Utility Functions ---

__device__ __forceinline__ bool isZero(const uint64_t* a) {
    return (a[4] | a[3] | a[2] | a[1] | a[0]) == 0ULL;
}

__device__ __forceinline__ bool isOne(const uint64_t* a) {
    return (a[4] == 0ULL) && (a[3] == 0ULL) && (a[2] == 0ULL) && (a[1] == 0ULL) && (a[0] == 1ULL);
}

__device__ __forceinline__ bool isNegative(const uint64_t* x) {
    return ((int64_t)(x[4])) < 0LL;
}

/**
 * @brief Adds the prime P to a number (r = r + P).
 */
__device__ __forceinline__ void addP(uint64_t* r) {
  UADDO1(r[0], P[0]);
  UADDC1(r[1], P[1]);
  UADDC1(r[2], P[2]);
  UADDC1(r[3], P[3]);
  UADD1(r[4], 0ULL);
}

/**
 * @brief Subtracts the prime P from a number (r = r - P).
 */
__device__ __forceinline__ void subP(uint64_t* r) {
  USUBO1(r[0], P[0]);
  USUBC1(r[1], P[1]);
  USUBC1(r[2], P[2]);
  USUBC1(r[3], P[3]);
  USUB1(r[4], 0ULL);
}

/**
 * @brief Negates a 320-bit number (r = -r).
 */
__device__ __forceinline__ void negate(uint64_t* r) {
    USUBO(r[0], 0ULL, r[0]);
    USUBC(r[1], 0ULL, r[1]);
    USUBC(r[2], 0ULL, r[2]);
    USUBC(r[3], 0ULL, r[3]);
    USUB(r[4], 0ULL, r[4]);
}

/**
 * @brief Copies a 320-bit number from a to r.
 */
__device__ __forceinline__ void load(uint64_t* r, const uint64_t* a) {
    r[0] = a[0]; r[1] = a[1]; r[2] = a[2]; r[3] = a[3]; r[4] = a[4];
}

/**
 * @brief Copies a 256-bit number from a to r.
 */
__device__ __forceinline__ void load256(uint64_t* r, const uint64_t* a) {
    r[0] = a[0]; r[1] = a[1]; r[2] = a[2]; r[3] = a[3];
}

// --- Core Arithmetic Functions ---

/**
 * @brief Multiplies a 320-bit integer 'a' by a 64-bit integer 'b'.
 */
__device__ __forceinline__ void uMult(uint64_t* r, const uint64_t* a, uint64_t b) {
  UMULLO(r[0], a[0], b);
  UMULLO(r[1], a[1], b);
  MADDO(r[1], a[0], b, r[1]);
  UMULLO(r[2], a[2], b);
  MADDC(r[2], a[1], b, r[2]);
  UMULLO(r[3], a[3], b);
  MADDC(r[3], a[2], b, r[3]);
  MADD(r[4], a[3], b, 0ULL);
}

/**
 * @brief Shifts a 320-bit number right by 62 bits.
 */
__device__ void shiftR62(uint64_t* r) {
    r[0] = (r[1] << 2) | (r[0] >> 62);
    r[1] = (r[2] << 2) | (r[1] >> 62);
    r[2] = (r[3] << 2) | (r[2] >> 62);
    r[3] = (r[4] << 2) | (r[3] >> 62);
    r[4] = (int64_t)(r[4]) >> 62; // Sign extend
}

__device__ void shiftR62(uint64_t* dest, const uint64_t* r, uint64_t carry) {
    dest[0] = (r[1] << 2) | (r[0] >> 62);
    dest[1] = (r[2] << 2) | (r[1] >> 62);
    dest[2] = (r[3] << 2) | (r[2] >> 62);
    dest[3] = (r[4] << 2) | (r[3] >> 62);
    dest[4] = (carry << 2) | (r[4] >> 62);
}

/**
 * @brief Multiplies a 320-bit integer 'a' by a signed 64-bit integer 'b'.
 */
__device__ uint64_t iMultC(uint64_t* r, const uint64_t* a, int64_t b, uint64_t* temp) {
    uint64_t carry;
    if (b < 0) {
        b = -b;
        USUBO(temp[0], 0ULL, a[0]); USUBC(temp[1], 0ULL, a[1]); USUBC(temp[2], 0ULL, a[2]); USUBC(temp[3], 0ULL, a[3]); USUB(temp[4], 0ULL, a[4]);
    } else {
        load(temp, a);
    }

    UMULLO(r[0], temp[0], b);
    UMULLO(r[1], temp[1], b); MADDO(r[1], temp[0], b, r[1]);
    UMULLO(r[2], temp[2], b); MADDC(r[2], temp[1], b, r[2]);
    UMULLO(r[3], temp[3], b); MADDC(r[3], temp[2], b, r[3]);
    UMULLO(r[4], temp[4], b); MADDC(r[4], temp[3], b, r[4]);
    MADDS(carry, temp[4], b, 0ULL);
    return carry;
}

/**
 * @brief Special multiplication for modular reduction step: r = -a * (2^32+977).
 */
__device__ void mulP(uint64_t* r, uint64_t a) {
    uint64_t ah, al;
    UMULLO(al, a, P_REDUCTION_TERM);
    UMULHI(ah, a, P_REDUCTION_TERM);
    USUBO(r[0], 0ULL, al);
    USUBC(r[1], 0ULL, ah);
    USUBC(r[2], 0ULL, 0ULL);
    USUBC(r[3], 0ULL, 0ULL);
    USUB(r[4], a, 0ULL);
}

/**
 * @brief Subtracts two 256-bit numbers modulo P: r = (a - b) mod P.
 */
__device__ void modSub256(uint64_t* r, const uint64_t* a, const uint64_t* b) {
    uint64_t borrow;
    USUBO(r[0], a[0], b[0]);
    USUBC(r[1], a[1], b[1]);
    USUBC(r[2], a[2], b[2]);
    USUBC(r[3], a[3], b[3]);
    USUB(borrow, 0ULL, 0ULL); // borrow = 0xFF... if borrow occurred, 0 otherwise
    
    // If borrow occurred, add P back
    UADDO1(r[0], P[0] & borrow);
    UADDC1(r[1], P[1] & borrow);
    UADDC1(r[2], P[2] & borrow);
    UADD1(r[3], P[3] & borrow);
}

/**
 * @brief PTX intrinsic for counting trailing zeros.
 */
__device__ __forceinline__ uint32_t ctz(uint64_t x) {
    uint32_t n;
    asm("{\n\t .reg .u64 tmp;\n\t brev.b64 tmp, %1;\n\t clz.b64 %0, tmp;\n\t}" : "=r"(n) : "l"(x));
    return n;
}

// Forward declarations for modular inverse dependencies
__device__ void _DivStep62(uint64_t u[NUM_WORDS], uint64_t v[NUM_WORDS], int32_t* pos, int64_t* uu, int64_t* uv, int64_t* vu, int64_t* vv);
__device__ void MatrixVecMulHalf(uint64_t dest[NUM_WORDS], const uint64_t u[NUM_WORDS], const uint64_t v[NUM_WORDS], int64_t _11, int64_t _12, uint64_t* carry);
__device__ uint64_t AddCh(uint64_t r[NUM_WORDS], const uint64_t a[NUM_WORDS], uint64_t carry);

/**
 * @brief Computes modular inverse of R mod P using a 320-bit Lehmer-style GCD algorithm.
 * @param R Input number (320-bit), must be > 0 and < P. Result is stored in-place.
 * If no inverse exists, R is set to 0.
 */
__device__ __noinline__ void modInv(uint64_t* R) {
    int64_t  uu, uv, vu, vv;
    int32_t  pos = NUM_WORDS - 1;

    uint64_t u[NUM_WORDS], v[NUM_WORDS], r[NUM_WORDS], s[NUM_WORDS];
    uint64_t tr[NUM_WORDS], ts[NUM_WORDS], r0[NUM_WORDS], s0[NUM_WORDS];
    uint64_t carryR, carryS;

    u[0] = P[0]; u[1] = P[1]; u[2] = P[2]; u[3] = P[3]; u[4] = 0;
    load(v, R);
    r[0] = 0; s[0] = 1; r[1] = 0; s[1] = 0; r[2] = 0; s[2] = 0; r[3] = 0; s[3] = 0; r[4] = 0; s[4] = 0;
    
    // Temporary storage for iMultC
    uint64_t temp[NUM_WORDS];

    while (true) {
        _DivStep62(u, v, &pos, &uu, &uv, &vu, &vv);

        MatrixVecMulHalf(tr, r, s, uu, uv, &carryR);
        MatrixVecMulHalf(ts, r, s, vu, vv, &carryS);

        if (isNegative(u)) { negate(u); uu = -uu; uv = -uv; }
        if (isNegative(v)) { negate(v); vu = -vu; vv = -vv; }
        
        shiftR62(u);
        shiftR62(v);
        
        uint64_t mr0 = (tr[0] * MOD_INV_CONSTANT_64) & 0x3FFFFFFFFFFFFFFFULL;
        mulP(r0, mr0);
        carryR = AddCh(tr, r0, carryR);

        if (isZero(v)) {
            shiftR62(r, tr, carryR);
            break;
        }

        uint64_t ms0 = (ts[0] * MOD_INV_CONSTANT_64) & 0x3FFFFFFFFFFFFFFFULL;
        mulP(s0, ms0);
        carryS = AddCh(ts, s0, carryS);
        
        shiftR62(r, tr, carryR);
        shiftR62(s, ts, carryS);
    }
    
    if (!isOne(u)) { // No inverse if GCD is not 1
        R[0] = R[1] = R[2] = R[3] = R[4] = 0ULL;
        return;
    }

    // Normalize result to be within [1, P-1]
    while (isNegative(r)) addP(r);
    while (!isNegative(r)) subP(r);
    addP(r);

    load(R, r);
}

/**
 * @brief Computes modular multiplication: r = (a * b) mod P.
 */
__device__ void modMult(uint64_t* r, const uint64_t* a, const uint64_t* b) {
    uint64_t r512[8] = {0};
    uint64_t t[NUM_WORDS];

    // 256x256 -> 512 bit multiplication
    uMult(r512, a, b[0]);
    uMult(t, a, b[1]);
    UADDO1(r512[1], t[0]); UADDC1(r512[2], t[1]); UADDC1(r512[3], t[2]); UADDC1(r512[4], t[3]); UADD1(r512[5], t[4]);
    uMult(t, a, b[2]);
    UADDO1(r512[2], t[0]); UADDC1(r512[3], t[1]); UADDC1(r512[4], t[2]); UADDC1(r512[5], t[3]); UADD1(r512[6], t[4]);
    uMult(t, a, b[3]);
    UADDO1(r512[3], t[0]); UADDC1(r512[4], t[1]); UADDC1(r512[5], t[2]); UADDC1(r512[6], t[3]); UADD1(r512[7], t[4]);
    
    // Reduce from 512 to 320 bits
    uMult(t, r512 + 4, P_REDUCTION_TERM);
    UADDO1(r512[0], t[0]); UADDC1(r512[1], t[1]); UADDC1(r512[2], t[2]); UADDC1(r512[3], t[3]);
    
    // Reduce from 320 to 256 bits
    uint64_t ah, al;
    UADD1(t[4], 0ULL);
    UMULLO(al, t[4], P_REDUCTION_TERM);
    UMULHI(ah, t[4], P_REDUCTION_TERM);
    UADDO(r[0], r512[0], al);
    UADDC(r[1], r512[1], ah);
    UADDC(r[2], r512[2], 0ULL);
    UADD(r[3], r512[3], 0ULL);
}

/**
 * @brief Computes modular squaring: r = (a * a) mod P.
 */
__device__ void modSqr(uint64_t* r, const uint64_t* a) {
    // Re-use multiplication for squaring. For some architectures, a dedicated
    // squaring implementation can be faster, but this is safe and correct.
    modMult(r, a, a);
}

/**
 * @brief Computes the modular inverse of a group of numbers.
 * This is much faster than calling modInv for each number individually.
 * @param r A 2D array of numbers. The result is stored in-place.
 */
__device__ __noinline__ void modInvGrouped(uint64_t (*r)[4]) {
    constexpr uint32_t count = GRP_SIZE / 2 + 1;
    uint64_t subp[count][4];
    uint64_t newValue[4];
    uint64_t inverse[NUM_WORDS];

    // 1. Compute cumulative products
    load256(subp[0], r[0]);
    for (uint32_t i = 1; i < count; i++) {
        modMult(subp[i], subp[i - 1], r[i]);
    }

    // 2. Compute one modular inverse on the last product
    load256(inverse, subp[count - 1]);
    inverse[4] = 0;
    modInv(inverse);

    // 3. Work backwards to find the inverse of each element
    for (uint32_t i = count - 1; i > 0; i--) {
        modMult(newValue, subp[i - 1], inverse);
        modMult(inverse, r[i]);
        load256(r[i], newValue);
    }
    load256(r[0], inverse);
}


// --- Helper definitions for modInv ---
#define SWAP(tmp,x,y) tmp = x; x = y; y = tmp;
__device__ void _DivStep62(uint64_t u[NUM_WORDS], uint64_t v[NUM_WORDS], int32_t* pos, int64_t* uu, int64_t* uv, int64_t* vu, int64_t* vv) {
    *uu = 1; *uv = 0; *vu = 0; *vv = 1;
    uint32_t bitCount = 62;
    uint64_t u0 = u[0], v0 = v[0];
    uint64_t uh, vh;

    while (*pos > 0 && (u[*pos] | v[*pos]) == 0) (*pos)--;
    
    if (*pos == 0) {
        uh = u[0]; vh = v[0];
    } else {
        uint32_t s = __clzll(u[*pos] | v[*pos]);
        uh = (s == 0) ? u[*pos] : (u[*pos] << s) | (u[*pos-1] >> (64-s));
        vh = (s == 0) ? v[*pos] : (v[*pos] << s) | (v[*pos-1] >> (64-s));
    }

    while (true) {
        uint32_t zeros = ctz(v0 | (1ULL << bitCount));
        v0 >>= zeros; vh >>= zeros; *uu <<= zeros; *uv <<= zeros;
        bitCount -= zeros;

        if (bitCount == 0) break;

        if (vh < uh) {
            uint64_t tw; int64_t tx, ty, tz;
            SWAP(tw, uh, vh); SWAP(tw, u0, v0); SWAP(tx, *uu, *vu); SWAP(ty, *uv, *vv);
        }
        vh -= uh; v0 -= u0; *vv -= *uv; *vu -= *uu;
    }
}

__device__ void MatrixVecMulHalf(uint64_t* dest, const uint64_t* u, const uint64_t* v, int64_t _11, int64_t _12, uint64_t* carry) {
    uint64_t t1[NUM_WORDS], t2[NUM_WORDS], temp[NUM_WORDS];
    uint64_t c1 = iMultC(t1, u, _11, temp);
    uint64_t c2 = iMultC(t2, v, _12, temp);
    UADDO(dest[0], t1[0], t2[0]); UADDC(dest[1], t1[1], t2[1]); UADDC(dest[2], t1[2], t2[2]);
    UADDC(dest[3], t1[3], t2[3]); UADDC(dest[4], t1[4], t2[4]);
    UADD(*carry, c1, c2);
}

__device__ uint64_t AddCh(uint64_t* r, const uint64_t* a, uint64_t carry) {
    uint64_t carryOut;
    UADDO1(r[0], a[0]); UADDC1(r[1], a[1]); UADDC1(r[2], a[2]);
    UADDC1(r[3], a[3]); UADDC1(r[4], a[4]);
    UADD(carryOut, carry, 0ULL);
    return carryOut;
}


} // namespace CuInt

#endif // CU_INT_H
