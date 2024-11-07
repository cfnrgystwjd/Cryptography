/*
 * Copyright(c) 2020-2024 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <gmp.h>
#include "pkcs.h"
#include "sha2.h"

/*
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */
void rsa_generate_key(void *_e, void *_d, void *_n, int mode)
{
    mpz_t p, q, p_1, q_1, lambda, e, d, n, gcd;
    gmp_randstate_t state;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, p_1, q_1, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     * (p-1) and (q-1) are relatively prime to 2^16+1 (65537).
     */
    do {
        /*
         * Select a random prime p, where (p-1) is relatively prime to 65537.
         */
        do {
            do {
                mpz_urandomb(p, state, RSAKEYSIZE/2);
                mpz_setbit(p, 0);
                mpz_setbit(p, RSAKEYSIZE/2-1);
            } while (mpz_probab_prime_p(p, 50) == 0);
            mpz_sub_ui(p_1, p, 1);
        } while (mpz_gcd_ui(gcd, p_1, 65537) != 1);
        /*
         * Select a random prime q, where (q-1) is relatively prime to 65537.
         */
        do {
            do {
                mpz_urandomb(q, state, RSAKEYSIZE/2);
                mpz_setbit(q, 0);
                mpz_setbit(q, RSAKEYSIZE/2-1);
            } while (mpz_probab_prime_p(q, 50) == 0);
            mpz_sub_ui(q_1, q, 1);
        } while (mpz_gcd_ui(gcd, q_1, 65537) != 1);
        /*
         * Compute n = p * q
         */
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE-1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_lcm(lambda, p_1, q_1);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else do {
        mpz_urandomb(e, state, RSAKEYSIZE);
        mpz_gcd(gcd, e, lambda);
    } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE/8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE/8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE/8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, p_1, q_1, lambda, e, d, n, gcd, NULL);
}


/*
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns PKCS_MSG_OUT_OF_RANGE, otherwise returns 0 for success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n)
{
    mpz_t m, k, n;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE/8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE/8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE/8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return PKCS_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE/8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}

/*
 *  음수가 아닌 정수를 지정된 길이의 옥텟 문자열로 반환한다.
 * x: 변환할 정수, xLen: 결과로 나올 길이, X: x를 xLen 길이로 변환한 옥텟 문자열
 */
void i2osp(int x, int xLen, unsigned char *X)
{
    // x값이 xLen 길이 표현 최대 가능값 초과시 종료
    if(x >= (1U << (8 * xLen)))
        return;
    
    // x 역순으로 1바이트씩 X에 저장
    for(int i=xLen-1; i>=0; i--){
        X[i] = x & 0xFF; // 하위 8비트 X에 저장
        x >>= 8; // 다음 8비트를 위해 오른쪽으로 쉬프트
    }
}

/*
 * sha2 함수를 정해서 해당 sha 함수를 호출한다.
 * message: 해시할 메시지, len: 메시지 길이, digest: 해시 결과 저장될 배열, sha2_ndx: 해시 함수
 */
int choose_sha2(const unsigned char *message, unsigned int len, unsigned char *digest, int sha2_ndx)
{
    switch(sha2_ndx){
        case SHA224:
            sha224(message, len, digest);
            break;
        case SHA256:
            sha256(message, len, digest);
            break;
        case SHA384:
            sha384(message, len, digest);
            break;
        case SHA512:
            sha512(message, len, digest);
            break;
        case SHA512_224:
            sha512_224(message, len, digest);
            break;
        case SHA512_256:
            sha512_256(message, len, digest);
            break;
        default:
            return -1;
    }
    return 0;
}

/*
 * mgf1 - 해시 함수에 기반한 마스크 생성 함수
 * mgfS: Seed 값, sLen: Seed 길이, m: mLen 길이의 옥텟 문자열 형태의 마스크, mLen: 마스크의 길이, sha2_ndx: 해시 함수
 * mgfS를 받아서 mLen 길이의 m으로 return한다.
 */
unsigned char *mgf1(const unsigned char *mgfS, size_t sLen, unsigned char *m, size_t mLen, int sha2_ndx)
{
    size_t hLen; // 해시 함수 출력 길이

    // 해시 값에 따른 해시 길이 설정
    switch(sha2_ndx){
        case SHA224: 
            hLen = SHA224_DIGEST_SIZE;
            break;
        case SHA256:
            hLen = SHA256_DIGEST_SIZE;
            break;
        case SHA384:
            hLen = SHA384_DIGEST_SIZE;
            break;
        case SHA512:
            hLen = SHA512_DIGEST_SIZE;
            break;
        case SHA512_224:
            hLen = SHA224_DIGEST_SIZE;
            break;
        case SHA512_256:
            hLen = SHA256_DIGEST_SIZE;
            break;
        default:
            return NULL;
    }

    // 최대 마스크 길이 확인
    if(mLen > (0xFFFFFFFF * hLen))
        return NULL;

    // 해시 계산 횟수 -> count = ceil(mLen / hLen)
    uint32_t count = (mLen + hLen -1) / hLen; 
    
    // mgfTemp: 시드와 카운트를 담을 배열, temp: 해시 결과 저장 배열
    unsigned char mgfTemp[sLen + 4];
    unsigned char temp[count * hLen];
    
    // mgfS를 mfgTemp에 복사
    memcpy(mgfTemp, mgfS, sLen);

    // 마스크 생성 루프
    for(uint32_t i=0; i<count; i++){
        i2osp(i, 4, mgfTemp + sLen); // i를 4바이트로 변환하여 mgfTemp 끝에 추가
        choose_sha2(mgfTemp, sLen + 4, temp + hLen * i, sha2_ndx); // 함수로 해시 값 생성하고 temp에 저장
    }

    // temp 배열의 앞에서 mLen 만큼 복사해서 마스크 값 생성
    memcpy(m, temp, mLen);
    return m;
}


/*
 * rsaes_oaep_encrypt() - RSA encrytion with the EME-OAEP encoding method
 * 길이가 len 바이트인 메시지 m을 공개키 (e,n)으로 암호화한 결과를 c에 저장한다.
 * label은 데이터를 식별하기 위한 라벨 문자열로 NULL을 입력하여 생략할 수 있다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. c의 크기는 RSAKEYSIZE와 같아야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_encrypt(const void *m, size_t mLen, const void *label, const void *e, const void *n, void *c, int sha2_ndx)
{
}

/*
 * rsaes_oaep_decrypt() - RSA decrytion with the EME-OAEP encoding method
 * 암호문 c를 개인키 (d,n)을 사용하여 원본 메시지 m과 길이 len을 회복한다.
 * label과 sha2_ndx는 암호화할 때 사용한 것과 일치해야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d, const void *n, const void *c, int sha2_ndx)
{
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s, int sha2_ndx)
{
    unsigned char mHash[SHA512_DIGEST_SIZE]; // Hash된 m 값 
    unsigned char salt[SHA512_DIGEST_SIZE];  // Salt 값
    unsigned char m_prime[1 + SHA512_DIGEST_SIZE + sizeof(salt)]; // M' = 0x00 || mHash || salt
    unsigned char h[SHA512_DIGEST_SIZE]; // Hash된 M' 값 
    unsigned char db[RSAKEYSIZE / 8 - SHA512_DIGEST_SIZE -1]; // 마스크 db 생성 
    unsigned char em[RSAKEYSIZE / 8]; // Encoded message 값
    size_t hLen, emLen = sizeof(em); // hLen은 해시 함수의 출력 길이, emLen은 최종적으로 서명된 메시지 길이 

    // 1. 메시지 해싱 
    if (choose_sha2(m, mLen, mHash, sha2_ndx) != 0) {
        return PKCS_HASH_TOO_LONG; // Hash가 너무 긴 경우 오류 반환 
    }

    // 2. 무작위로 salt 값 생성 
    arc4random_buf(salt, sizeof(salt));

    // 3. Hash 함수에 따라 길이 설정 
    switch (sha2_ndx) {
        case SHA224: hLen = SHA224_DIGEST_SIZE; break;
        case SHA256: hLen = SHA256_DIGEST_SIZE; break;
        case SHA384: hLen = SHA384_DIGEST_SIZE; break;
        case SHA512: hLen = SHA512_DIGEST_SIZE; break;
        case SHA512_224: hLen = SHA224_DIGEST_SIZE; break;
        case SHA512_256: hLen = SHA256_DIGEST_SIZE; break;
        default: return PKCS_INVALID_PD2; // 유효하지 않은 Hash의 경우 오류 반환 
    }

    // 4. M' 생성: M' = 0x00 || mHash || salt
    m_prime[0] = 0x00;
    memcpy(m_prime + 1, mHash, hLen);
    memcpy(m_prime + 1 + hLen, salt, sizeof(salt));

    // 5. M' 해싱 (= H)
    if (choose_sha2(m_prime, 1 + hLen + sizeof(salt), h, sha2_ndx) != 0) {
        return PKCS_HASH_TOO_LONG; // Hash가 너무 긴 경우 오류 반환 
    }

    // 6. H를 mgf1을 이용해 db 생성
    mgf1(h, hLen, db, emLen - hLen - 1, sha2_ndx);

    // 7. sign encoded message
    memcpy(em, db, emLen - hLen - 1); // db 복사
    memcpy(em + emLen - hLen - 1, h, hLen); // h 복사
    em[emLen - 1] = 0xbc; // 마지막 바이트는 0xbc

    // 8. RSA 서명: 인코딩된 em 메시지를 RSA 개인키로 암호화하여 서명 생성 
    if (rsa_cipher(s, em, d) != 0) {
        return PKCS_MSG_OUT_OF_RANGE; // 암호화 실패 시, 오류 반환 
    }

    return 0; 
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e,n)으로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s, int sha2_ndx)
{
}
