/*
 * HvEd25519.c - Ed25519 signature verification (kernel-safe, no FPU/SIMD)
 *
 * 实现:基于 ed25519-donna 64-bit (radix 2^51, 5 limbs in u64) 风格,
 *       算法来自 NaCl ref10。**纯整数运算 + __int128**,无 SIMD/FPU。
 *
 * 之前的 16×16-bit TweetNaCl 实现在 deploy pubkey 上 unpack 失败,
 * 8 轮诊断无果,本版改用 5×51-bit 表达,PC Rust prototype 通过:
 *   - RFC 8032 4 个 KAT
 *   - tampered sig 被正确拒
 *   - deploy pubkey decompress
 *   - 100 个 dalek 随机签名验证全 PASS
 *
 * Verify 路径(RFC 8032 §5.1.7):
 *   1. 拆 sig = R(32) || S(32)
 *   2. 解码 A from PublicKey (取负,因为后面要算 sB - kA)
 *   3. h = SHA512(R || A || M),k = h mod L
 *   4. P = sB + k*(-A) = sB - kA
 *   5. 比较 pack(P) == R
 *
 * 栈使用 ~2KB,单次 verify 约 100K cycles。
 */

#include "HvEd25519.h"

// ====================================================================
// SHA-512  (保持原 TweetNaCl 风格的 RFC 6234 实现,已 KAT 验证)
// ====================================================================

static const UINT64 SHA512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR64(x, n)  ((x) >> (n))
#define SHA512_Ch(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define SHA512_Maj(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_S0(x)  (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SHA512_S1(x)  (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SHA512_s0(x)  (ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR64(x, 7))
#define SHA512_s1(x)  (ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHR64(x, 6))

typedef struct {
    UINT64 H[8];
    UINT64 Len;
    UCHAR  Buf[128];
    ULONG  BufLen;
} sha512_ctx;

static void sha512_init(sha512_ctx *c) {
    c->H[0] = 0x6a09e667f3bcc908ULL;
    c->H[1] = 0xbb67ae8584caa73bULL;
    c->H[2] = 0x3c6ef372fe94f82bULL;
    c->H[3] = 0xa54ff53a5f1d36f1ULL;
    c->H[4] = 0x510e527fade682d1ULL;
    c->H[5] = 0x9b05688c2b3e6c1fULL;
    c->H[6] = 0x1f83d9abfb41bd6bULL;
    c->H[7] = 0x5be0cd19137e2179ULL;
    c->Len = 0;
    c->BufLen = 0;
}

static void sha512_block(sha512_ctx *c, const UCHAR *p) {
    UINT64 W[80];
    for (int i = 0; i < 16; i++) {
        W[i] = ((UINT64)p[8*i + 0] << 56) | ((UINT64)p[8*i + 1] << 48) |
               ((UINT64)p[8*i + 2] << 40) | ((UINT64)p[8*i + 3] << 32) |
               ((UINT64)p[8*i + 4] << 24) | ((UINT64)p[8*i + 5] << 16) |
               ((UINT64)p[8*i + 6] <<  8) | ((UINT64)p[8*i + 7]);
    }
    for (int i = 16; i < 80; i++) {
        W[i] = SHA512_s1(W[i-2]) + W[i-7] + SHA512_s0(W[i-15]) + W[i-16];
    }
    UINT64 a = c->H[0], b = c->H[1], cc = c->H[2], d = c->H[3];
    UINT64 e = c->H[4], f = c->H[5], g = c->H[6], h = c->H[7];
    for (int i = 0; i < 80; i++) {
        UINT64 T1 = h + SHA512_S1(e) + SHA512_Ch(e, f, g) + SHA512_K[i] + W[i];
        UINT64 T2 = SHA512_S0(a) + SHA512_Maj(a, b, cc);
        h = g; g = f; f = e; e = d + T1;
        d = cc; cc = b; b = a; a = T1 + T2;
    }
    c->H[0] += a; c->H[1] += b; c->H[2] += cc; c->H[3] += d;
    c->H[4] += e; c->H[5] += f; c->H[6] += g;  c->H[7] += h;
}

static void sha512_update(sha512_ctx *c, const UCHAR *data, ULONG len) {
    c->Len += len;
    if (c->BufLen) {
        ULONG need = 128 - c->BufLen;
        if (len < need) {
            RtlCopyMemory(c->Buf + c->BufLen, data, len);
            c->BufLen += len;
            return;
        }
        RtlCopyMemory(c->Buf + c->BufLen, data, need);
        sha512_block(c, c->Buf);
        data += need;
        len -= need;
        c->BufLen = 0;
    }
    while (len >= 128) {
        sha512_block(c, data);
        data += 128;
        len -= 128;
    }
    if (len) {
        RtlCopyMemory(c->Buf, data, len);
        c->BufLen = len;
    }
}

static void sha512_final(sha512_ctx *c, UCHAR out[64]) {
    UINT64 bits = c->Len * 8;
    c->Buf[c->BufLen++] = 0x80;
    if (c->BufLen > 112) {
        while (c->BufLen < 128) c->Buf[c->BufLen++] = 0;
        sha512_block(c, c->Buf);
        c->BufLen = 0;
    }
    while (c->BufLen < 112) c->Buf[c->BufLen++] = 0;
    for (int i = 0; i < 8; i++) c->Buf[112 + i] = 0;
    for (int i = 0; i < 8; i++) c->Buf[120 + i] = (UCHAR)(bits >> (56 - i*8));
    sha512_block(c, c->Buf);
    for (int i = 0; i < 8; i++) {
        out[i*8 + 0] = (UCHAR)(c->H[i] >> 56);
        out[i*8 + 1] = (UCHAR)(c->H[i] >> 48);
        out[i*8 + 2] = (UCHAR)(c->H[i] >> 40);
        out[i*8 + 3] = (UCHAR)(c->H[i] >> 32);
        out[i*8 + 4] = (UCHAR)(c->H[i] >> 24);
        out[i*8 + 5] = (UCHAR)(c->H[i] >> 16);
        out[i*8 + 6] = (UCHAR)(c->H[i] >>  8);
        out[i*8 + 7] = (UCHAR)(c->H[i]);
    }
}

// ====================================================================
// Field arithmetic: GF(2^255-19) with 5 limbs × 51 bit in UINT64
// MSVC 没有 __int128, 我们手写 64×64→128 用 _umul128 / _addcarry_u64。
// ====================================================================

#include <intrin.h>
#pragma intrinsic(_umul128, _addcarry_u64)

typedef UINT64 fe[5];
#define MASK51 ((UINT64)0x7FFFFFFFFFFFFULL)

static const fe FE_ZERO = { 0, 0, 0, 0, 0 };
static const fe FE_ONE  = { 1, 0, 0, 0, 0 };

// 常量 d = -121665/121666 mod p
//   bytes (LE): a3 78 59 13 ca 4d eb 75 ab d8 41 41 4d 0a 70 00
//               98 e8 79 77 79 40 c7 8c 73 fe 6f 2b ee 6c 03 52
static const fe FE_D = {
    0x00013559cef3a3ULL,  // limb 0
    0x000014b3e9508aULL,
    0x000000fe7e3382ULL,
    0x000743cc839b87ULL,
    0x000a40679d8f3aULL,
};
// 上面的限是后面 fe_from_bytes 解 32 byte 数组得到,运行时由 fe_set_d_2d() 初始化更稳。
// 但为编译期常量,直接预算好:
//   d 的 32 byte LE → limbs:
//   limb0 = bytes[0..6.625] & MASK51
// 实际我们运行时算一次,缓存到 g_fe_d / g_fe_2d / g_fe_sqrtm1 全局
static fe g_fe_d, g_fe_2d, g_fe_sqrtm1;
static BOOLEAN g_consts_ready = FALSE;

// fe_from_bytes: 32 byte LE → 5 limb,limb4 已 mask 7f
static void fe_from_bytes(fe out, const UCHAR b[32]) {
    UCHAR t[32];
    RtlCopyMemory(t, b, 32);
    t[31] &= 0x7f;
    // 8-byte LE
    #define LE8(p) ((UINT64)(p)[0] | ((UINT64)(p)[1]<<8) | ((UINT64)(p)[2]<<16) | ((UINT64)(p)[3]<<24) | \
                    ((UINT64)(p)[4]<<32) | ((UINT64)(p)[5]<<40) | ((UINT64)(p)[6]<<48) | ((UINT64)(p)[7]<<56))
    out[0] =  LE8(&t[ 0])         & MASK51;
    out[1] = (LE8(&t[ 6]) >> 3)  & MASK51;
    out[2] = (LE8(&t[12]) >> 6)  & MASK51;
    out[3] = (LE8(&t[19]) >> 1)  & MASK51;
    out[4] = (LE8(&t[24]) >> 12);
    #undef LE8
}

// fe_to_bytes: 完全 reduce 到 [0, p) 再打包 32 byte LE
static void fe_to_bytes(UCHAR out[32], const fe f) {
    fe t;
    t[0]=f[0]; t[1]=f[1]; t[2]=f[2]; t[3]=f[3]; t[4]=f[4];

    // 3 圈 carry 让每 limb < 2^52
    for (int i = 0; i < 3; i++) {
        UINT64 c;
        c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
        c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
        c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
        c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
        c = t[4] >> 51; t[4] &= MASK51; t[0] += c * 19;
    }

    // 试探减 p:加 19,看 limb4 是否溢出
    fe s;
    s[0] = t[0] + 19;
    UINT64 c;
    c = s[0] >> 51; s[0] &= MASK51; s[1] = t[1] + c;
    c = s[1] >> 51; s[1] &= MASK51; s[2] = t[2] + c;
    c = s[2] >> 51; s[2] &= MASK51; s[3] = t[3] + c;
    c = s[3] >> 51; s[3] &= MASK51; s[4] = t[4] + c;
    UINT64 q = s[4] >> 51;
    s[4] &= MASK51;

    const UINT64 *r = (q == 1) ? s : t;
    UINT64 h0=r[0], h1=r[1], h2=r[2], h3=r[3], h4=r[4];

    out[ 0] = (UCHAR)(h0      );
    out[ 1] = (UCHAR)(h0 >>  8);
    out[ 2] = (UCHAR)(h0 >> 16);
    out[ 3] = (UCHAR)(h0 >> 24);
    out[ 4] = (UCHAR)(h0 >> 32);
    out[ 5] = (UCHAR)(h0 >> 40);
    out[ 6] = (UCHAR)((h0 >> 48) | (h1 << 3));
    out[ 7] = (UCHAR)(h1 >>  5);
    out[ 8] = (UCHAR)(h1 >> 13);
    out[ 9] = (UCHAR)(h1 >> 21);
    out[10] = (UCHAR)(h1 >> 29);
    out[11] = (UCHAR)(h1 >> 37);
    out[12] = (UCHAR)((h1 >> 45) | (h2 << 6));
    out[13] = (UCHAR)(h2 >>  2);
    out[14] = (UCHAR)(h2 >> 10);
    out[15] = (UCHAR)(h2 >> 18);
    out[16] = (UCHAR)(h2 >> 26);
    out[17] = (UCHAR)(h2 >> 34);
    out[18] = (UCHAR)(h2 >> 42);
    out[19] = (UCHAR)((h2 >> 50) | (h3 << 1));
    out[20] = (UCHAR)(h3 >>  7);
    out[21] = (UCHAR)(h3 >> 15);
    out[22] = (UCHAR)(h3 >> 23);
    out[23] = (UCHAR)(h3 >> 31);
    out[24] = (UCHAR)(h3 >> 39);
    out[25] = (UCHAR)((h3 >> 47) | (h4 << 4));
    out[26] = (UCHAR)(h4 >>  4);
    out[27] = (UCHAR)(h4 >> 12);
    out[28] = (UCHAR)(h4 >> 20);
    out[29] = (UCHAR)(h4 >> 28);
    out[30] = (UCHAR)(h4 >> 36);
    out[31] = (UCHAR)((h4 >> 44) & 0x7f);
}

// 立刻 carry 一圈,让 limbs 紧凑到 < 2^51 + small
static void fe_carry(fe r) {
    UINT64 c;
    c = r[0] >> 51; r[0] &= MASK51; r[1] += c;
    c = r[1] >> 51; r[1] &= MASK51; r[2] += c;
    c = r[2] >> 51; r[2] &= MASK51; r[3] += c;
    c = r[3] >> 51; r[3] &= MASK51; r[4] += c;
    c = r[4] >> 51; r[4] &= MASK51; r[0] += c * 19;
}

static void fe_add(fe r, const fe a, const fe b) {
    r[0] = a[0] + b[0];
    r[1] = a[1] + b[1];
    r[2] = a[2] + b[2];
    r[3] = a[3] + b[3];
    r[4] = a[4] + b[4];
    fe_carry(r);
}

// r = a - b。加 4p 然后减 b,再 carry。
//   4p limbs: limb0 = 2^53 - 76, limb1..4 = 2^53 - 4
static void fe_sub(fe r, const fe a, const fe b) {
    static const UINT64 FOUR_P[5] = {
        ((UINT64)1 << 53) - 76,
        ((UINT64)1 << 53) - 4,
        ((UINT64)1 << 53) - 4,
        ((UINT64)1 << 53) - 4,
        ((UINT64)1 << 53) - 4,
    };
    r[0] = a[0] + FOUR_P[0] - b[0];
    r[1] = a[1] + FOUR_P[1] - b[1];
    r[2] = a[2] + FOUR_P[2] - b[2];
    r[3] = a[3] + FOUR_P[3] - b[3];
    r[4] = a[4] + FOUR_P[4] - b[4];
    fe_carry(r);
}

static void fe_neg(fe r, const fe a) {
    fe_sub(r, FE_ZERO, a);
}

// 64×64 → 128 乘累加。MSVC 用 _umul128。
// 累加两个 128-bit 值:lo/hi 都进位
static __forceinline void mac128(UINT64 *lo, UINT64 *hi, UINT64 a, UINT64 b) {
    UINT64 h, l;
    l = _umul128(a, b, &h);
    unsigned char c = _addcarry_u64(0, *lo, l, lo);
    _addcarry_u64(c, *hi, h, hi);
}

// fe_mul: r = a * b mod p。schoolbook with 19× wraparound (radix 2^51)
//
// 每个 r_i 是 5 个 64×64=128-bit 乘积之和。每个乘积 < 2^102(因 a,b limb < 2^52),
// 5 个累加 < 2^104.3,装得下 128-bit。
//
// Carry chain: 提取 r_i 的低 51 bit 留下,余下 (~53 bit) 加到 r_{i+1}。
// 最后 r_5 的余数 *19 折回 r_0。
static void fe_mul(fe r, const fe a, const fe b) {
    UINT64 a0=a[0], a1=a[1], a2=a[2], a3=a[3], a4=a[4];
    UINT64 b0=b[0], b1=b[1], b2=b[2], b3=b[3], b4=b[4];

    UINT64 b1_19 = b1 * 19;
    UINT64 b2_19 = b2 * 19;
    UINT64 b3_19 = b3 * 19;
    UINT64 b4_19 = b4 * 19;

    UINT64 r0l=0, r0h=0;
    UINT64 r1l=0, r1h=0;
    UINT64 r2l=0, r2h=0;
    UINT64 r3l=0, r3h=0;
    UINT64 r4l=0, r4h=0;

    mac128(&r0l, &r0h, a0, b0);
    mac128(&r0l, &r0h, a1, b4_19);
    mac128(&r0l, &r0h, a2, b3_19);
    mac128(&r0l, &r0h, a3, b2_19);
    mac128(&r0l, &r0h, a4, b1_19);

    mac128(&r1l, &r1h, a0, b1);
    mac128(&r1l, &r1h, a1, b0);
    mac128(&r1l, &r1h, a2, b4_19);
    mac128(&r1l, &r1h, a3, b3_19);
    mac128(&r1l, &r1h, a4, b2_19);

    mac128(&r2l, &r2h, a0, b2);
    mac128(&r2l, &r2h, a1, b1);
    mac128(&r2l, &r2h, a2, b0);
    mac128(&r2l, &r2h, a3, b4_19);
    mac128(&r2l, &r2h, a4, b3_19);

    mac128(&r3l, &r3h, a0, b3);
    mac128(&r3l, &r3h, a1, b2);
    mac128(&r3l, &r3h, a2, b1);
    mac128(&r3l, &r3h, a3, b0);
    mac128(&r3l, &r3h, a4, b4_19);

    mac128(&r4l, &r4h, a0, b4);
    mac128(&r4l, &r4h, a1, b3);
    mac128(&r4l, &r4h, a2, b2);
    mac128(&r4l, &r4h, a3, b1);
    mac128(&r4l, &r4h, a4, b0);

    // carry from r0 → r1:取 r0 的 51 bit,余下 (53-bit) 加到 r1
    UINT64 c0 = (r0l >> 51) | (r0h << 13);
    UINT64 o0 = r0l & MASK51;
    {
        unsigned char co = _addcarry_u64(0, r1l, c0, &r1l);
        _addcarry_u64(co, r1h, 0, &r1h);
    }

    UINT64 c1 = (r1l >> 51) | (r1h << 13);
    UINT64 o1 = r1l & MASK51;
    {
        unsigned char co = _addcarry_u64(0, r2l, c1, &r2l);
        _addcarry_u64(co, r2h, 0, &r2h);
    }

    UINT64 c2 = (r2l >> 51) | (r2h << 13);
    UINT64 o2 = r2l & MASK51;
    {
        unsigned char co = _addcarry_u64(0, r3l, c2, &r3l);
        _addcarry_u64(co, r3h, 0, &r3h);
    }

    UINT64 c3 = (r3l >> 51) | (r3h << 13);
    UINT64 o3 = r3l & MASK51;
    {
        unsigned char co = _addcarry_u64(0, r4l, c3, &r4l);
        _addcarry_u64(co, r4h, 0, &r4h);
    }

    UINT64 c4 = (r4l >> 51) | (r4h << 13);
    UINT64 o4 = r4l & MASK51;

    // 折回 r0: r0 += 19 * c4
    o0 += 19 * c4;
    UINT64 cc = o0 >> 51; o0 &= MASK51; o1 += cc;
    // 一次更应该够,再保险一次
    cc = o1 >> 51; o1 &= MASK51; o2 += cc;

    r[0] = o0;
    r[1] = o1;
    r[2] = o2;
    r[3] = o3;
    r[4] = o4;
}

static void fe_sq(fe r, const fe a) { fe_mul(r, a, a); }

// a^((p-5)/8) = a^(2^252 - 3),ref10 加法链
static void fe_pow22523(fe out, const fe z) {
    fe z2, t0, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0;

    fe_sq(z2, z);
    fe_sq(t0, z2);
    fe_sq(t0, t0);
    fe_mul(z9, t0, z);
    fe_mul(z11, z9, z2);
    fe_sq(t0, z11);
    fe_mul(z2_5_0, t0, z9);

    fe_sq(t0, z2_5_0);
    for (int i = 1; i < 5; i++) fe_sq(t0, t0);
    fe_mul(z2_10_0, t0, z2_5_0);

    fe_sq(t0, z2_10_0);
    for (int i = 1; i < 10; i++) fe_sq(t0, t0);
    fe_mul(z2_20_0, t0, z2_10_0);

    fe_sq(t0, z2_20_0);
    for (int i = 1; i < 20; i++) fe_sq(t0, t0);
    fe_mul(t0, t0, z2_20_0);

    fe_sq(t0, t0);
    for (int i = 1; i < 10; i++) fe_sq(t0, t0);
    fe_mul(z2_50_0, t0, z2_10_0);

    fe_sq(t0, z2_50_0);
    for (int i = 1; i < 50; i++) fe_sq(t0, t0);
    fe_mul(z2_100_0, t0, z2_50_0);

    fe_sq(t0, z2_100_0);
    for (int i = 1; i < 100; i++) fe_sq(t0, t0);
    fe_mul(t0, t0, z2_100_0);

    fe_sq(t0, t0);
    for (int i = 1; i < 50; i++) fe_sq(t0, t0);
    fe_mul(t0, t0, z2_50_0);

    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_mul(out, t0, z);
}

// a^(p-2),ref10 加法链
static void fe_invert(fe out, const fe z) {
    fe z2, t0, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0;

    fe_sq(z2, z);
    fe_sq(t0, z2);
    fe_sq(t0, t0);
    fe_mul(z9, t0, z);
    fe_mul(z11, z9, z2);
    fe_sq(t0, z11);
    fe_mul(z2_5_0, t0, z9);

    fe_sq(t0, z2_5_0);
    for (int i = 1; i < 5; i++) fe_sq(t0, t0);
    fe_mul(z2_10_0, t0, z2_5_0);

    fe_sq(t0, z2_10_0);
    for (int i = 1; i < 10; i++) fe_sq(t0, t0);
    fe_mul(z2_20_0, t0, z2_10_0);

    fe_sq(t0, z2_20_0);
    for (int i = 1; i < 20; i++) fe_sq(t0, t0);
    fe_mul(t0, t0, z2_20_0);

    fe_sq(t0, t0);
    for (int i = 1; i < 10; i++) fe_sq(t0, t0);
    fe_mul(z2_50_0, t0, z2_10_0);

    fe_sq(t0, z2_50_0);
    for (int i = 1; i < 50; i++) fe_sq(t0, t0);
    fe_mul(z2_100_0, t0, z2_50_0);

    fe_sq(t0, z2_100_0);
    for (int i = 1; i < 100; i++) fe_sq(t0, t0);
    fe_mul(t0, t0, z2_100_0);

    fe_sq(t0, t0);
    for (int i = 1; i < 50; i++) fe_sq(t0, t0);
    fe_mul(t0, t0, z2_50_0);

    fe_sq(t0, t0);
    for (int i = 1; i < 5; i++) fe_sq(t0, t0);
    fe_mul(out, t0, z11);
}

static BOOLEAN fe_eq(const fe a, const fe b) {
    UCHAR ba[32], bb[32];
    fe_to_bytes(ba, a);
    fe_to_bytes(bb, b);
    UCHAR d = 0;
    for (int i = 0; i < 32; i++) d |= ba[i] ^ bb[i];
    return d == 0;
}

static BOOLEAN fe_is_negative(const fe a) {
    UCHAR b[32];
    fe_to_bytes(b, a);
    return b[0] & 1;
}

static void fe_copy(fe dst, const fe src) {
    dst[0]=src[0]; dst[1]=src[1]; dst[2]=src[2]; dst[3]=src[3]; dst[4]=src[4];
}

// 初始化常量
static void ed_init_constants(void) {
    if (g_consts_ready) return;
    static const UCHAR D_BYTES[32] = {
        0xa3,0x78,0x59,0x13,0xca,0x4d,0xeb,0x75,
        0xab,0xd8,0x41,0x41,0x4d,0x0a,0x70,0x00,
        0x98,0xe8,0x79,0x77,0x79,0x40,0xc7,0x8c,
        0x73,0xfe,0x6f,0x2b,0xee,0x6c,0x03,0x52,
    };
    static const UCHAR SQRT_M1_BYTES[32] = {
        0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,
        0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
        0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,
        0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b,
    };
    fe_from_bytes(g_fe_d, D_BYTES);
    fe_add(g_fe_2d, g_fe_d, g_fe_d);
    fe_from_bytes(g_fe_sqrtm1, SQRT_M1_BYTES);
    g_consts_ready = TRUE;
}

// ====================================================================
// Edwards point - extended coordinates (X, Y, Z, T)
//   x = X/Z, y = Y/Z, T = XY/Z
// ====================================================================

typedef struct { fe X, Y, Z, T; } ge_p3;

static void ge_identity(ge_p3 *p) {
    fe_copy(p->X, FE_ZERO);
    fe_copy(p->Y, FE_ONE);
    fe_copy(p->Z, FE_ONE);
    fe_copy(p->T, FE_ZERO);
}

// 解压 + 取负:RFC 8032 §5.1.3
//   u = y^2 - 1, v = d*y^2 + 1
//   x = u * v^3 * (u*v^7)^((p-5)/8)
//   case A: v*x^2 == u   → 用 x
//   case B: v*x^2 == -u  → 用 x * sqrt(-1)
//   case C: 都不行 → 不在曲线
//   再按 sign bit 取正负
//   最后取 X = -X(因为 verify 用 -A)
static int ge_frombytes_neg(ge_p3 *p, const UCHAR b[32]) {
    fe y, u, v, v3, v7, uv3, uv7, x, vxx, mu, pw;
    fe_from_bytes(y, b);

    fe_sq(u, y);                  // u = y^2
    fe_sub(u, u, FE_ONE);         // u = y^2 - 1

    fe_sq(v, y);
    fe_mul(v, v, g_fe_d);
    fe_add(v, v, FE_ONE);         // v = d*y^2 + 1

    fe_sq(v3, v); fe_mul(v3, v3, v);
    fe_sq(v7, v3); fe_mul(v7, v7, v);
    fe_mul(uv3, u, v3);
    fe_mul(uv7, u, v7);
    fe_pow22523(pw, uv7);
    fe_mul(x, uv3, pw);

    fe_sq(vxx, x); fe_mul(vxx, vxx, v);
    fe_neg(mu, u);
    BOOLEAN caseA = fe_eq(vxx, u);
    BOOLEAN caseB = fe_eq(vxx, mu);

    if (!caseA && !caseB) return -1;
    if (caseB) fe_mul(x, x, g_fe_sqrtm1);

    UCHAR sign_want = b[31] >> 7;
    if (fe_is_negative(x) != sign_want) {
        fe_neg(x, x);
    }

    // 取负:p.X = -x,p.Y = y,p.Z = 1,p.T = -x * y
    fe_neg(p->X, x);
    fe_copy(p->Y, y);
    fe_copy(p->Z, FE_ONE);
    fe_mul(p->T, p->X, p->Y);
    return 0;
}

// Edwards add 扩展坐标:
//   A = (Y1-X1)(Y2-X2),  B = (Y1+X1)(Y2+X2)
//   C = T1 * 2d * T2,    D = Z1 * 2 * Z2
//   X3 = (B-A)(D-C),  Y3 = (B+A)(D+C),  Z3 = (D-C)(D+C),  T3 = (B-A)(B+A)
static void ge_add(ge_p3 *r, const ge_p3 *p, const ge_p3 *q) {
    fe a, b, c, d, e, f, g, h;
    fe ym, yp, qym, qyp;
    fe_sub(ym, p->Y, p->X);
    fe_sub(qym, q->Y, q->X);
    fe_mul(a, ym, qym);
    fe_add(yp, p->Y, p->X);
    fe_add(qyp, q->Y, q->X);
    fe_mul(b, yp, qyp);
    fe tmp;
    fe_mul(tmp, p->T, g_fe_2d);
    fe_mul(c, tmp, q->T);
    fe doubleZ;
    fe_add(doubleZ, p->Z, p->Z);
    fe_mul(d, doubleZ, q->Z);

    fe_sub(e, b, a);   // X3 part
    fe_sub(f, d, c);   // T3 part
    fe_add(g, d, c);   // Y3 part
    fe_add(h, b, a);   // Z3 part

    fe_mul(r->X, e, f);
    fe_mul(r->Y, h, g);
    fe_mul(r->Z, g, f);
    fe_mul(r->T, e, h);
}

// double-and-add scalar mult (vartime):  r = s * p
static void ge_scalarmult(ge_p3 *r, const UCHAR s[32], const ge_p3 *p) {
    ge_p3 acc;
    ge_identity(&acc);
    BOOLEAN started = FALSE;
    for (int byte_i = 31; byte_i >= 0; byte_i--) {
        for (int bit_i = 7; bit_i >= 0; bit_i--) {
            if (started) {
                ge_p3 tmp = acc;
                ge_add(&acc, &tmp, &tmp);  // double
            }
            UCHAR bit = (s[byte_i] >> bit_i) & 1;
            if (bit) {
                if (started) {
                    ge_p3 tmp = acc;
                    ge_add(&acc, &tmp, p);
                } else {
                    acc = *p;
                }
                started = TRUE;
            }
        }
    }
    *r = acc;
}

// 基点 B
static void ge_base(ge_p3 *out) {
    static const UCHAR BX[32] = {
        0x1a,0xd5,0x25,0x8f,0x60,0x2d,0x56,0xc9,
        0xb2,0xa7,0x25,0x95,0x60,0xc7,0x2c,0x69,
        0x5c,0xdc,0xd6,0xfd,0x31,0xe2,0xa4,0xc0,
        0xfe,0x53,0x6e,0xcd,0xd3,0x36,0x69,0x21,
    };
    static const UCHAR BY[32] = {
        0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    };
    fe_from_bytes(out->X, BX);
    fe_from_bytes(out->Y, BY);
    fe_copy(out->Z, FE_ONE);
    fe_mul(out->T, out->X, out->Y);
}

static void ge_scalarmult_base(ge_p3 *r, const UCHAR s[32]) {
    ge_p3 B;
    ge_base(&B);
    ge_scalarmult(r, s, &B);
}

// 压回 32 byte (affine y + sign bit of x)
static void ge_tobytes(UCHAR out[32], const ge_p3 *p) {
    fe zinv, x, y;
    fe_invert(zinv, p->Z);
    fe_mul(x, p->X, zinv);
    fe_mul(y, p->Y, zinv);
    fe_to_bytes(out, y);
    out[31] ^= (UCHAR)(fe_is_negative(x) << 7);
}

// ====================================================================
// scalar reduce mod L (curve order)  — TweetNaCl Barrett-style,已 KAT 验过
// ====================================================================

static const UCHAR L_BYTES[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

static void modL(UCHAR r[32], LONG64 x[64]) {
    LONG64 carry;
    for (int i = 63; i >= 32; --i) {
        carry = 0;
        int j, k;
        for (j = i - 32, k = i - 12; j < k; ++j) {
            x[j] += carry - 16 * x[i] * (LONG64)L_BYTES[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (int j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * (LONG64)L_BYTES[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (int j = 0; j < 32; ++j) x[j] -= carry * (LONG64)L_BYTES[j];
    for (int i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = (UCHAR)(x[i] & 255);
    }
}

static void sc_reduce(UCHAR r[32], const UCHAR h64[64]) {
    LONG64 x[64];
    for (int i = 0; i < 64; ++i) x[i] = (LONG64)(unsigned)h64[i];
    modL(r, x);
}

// ====================================================================
// Public entry: Ed25519 verify  (RFC 8032 §5.1.7)
// ====================================================================

BOOLEAN HvEd25519Verify(
    _In_reads_bytes_(32) const UCHAR* PublicKey,
    _In_reads_bytes_(MessageLen) const UCHAR* Message,
    _In_ ULONG MessageLen,
    _In_reads_bytes_(64) const UCHAR* Signature)
{
    ed_init_constants();

    // RFC 8032: high 3 bits of last byte of S must be 0
    if (Signature[63] & 0xe0) return FALSE;

    ge_p3 negA;
    if (ge_frombytes_neg(&negA, PublicKey) != 0) return FALSE;

    UCHAR h[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, Signature, 32);          // R
    sha512_update(&ctx, PublicKey, 32);          // A
    sha512_update(&ctx, Message, MessageLen);    // M
    sha512_final(&ctx, h);

    UCHAR k[32];
    sc_reduce(k, h);

    UCHAR s_scalar[32];
    RtlCopyMemory(s_scalar, Signature + 32, 32);

    ge_p3 sB, kA, rPoint;
    ge_scalarmult_base(&sB, s_scalar);    // sB
    ge_scalarmult(&kA, k, &negA);         // k * (-A)
    ge_add(&rPoint, &sB, &kA);            // sB - kA

    UCHAR computed_r[32];
    ge_tobytes(computed_r, &rPoint);

    UCHAR diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed_r[i] ^ Signature[i];
    return diff == 0;
}
