/*
 * Copyright(c) 2020-2024 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */

/*
 * 학과: 컴퓨터학부
 * --------------------1---------------------
 * 학번: 2019060637
 * 이름: 추효정
 * 
 * 1차 수정일: 2024.11.07.목요일
 * 1차 수정 내용: rsaes_oaep_encrypt 구현 및 주석 삽입
 *
 * 2차 수정일: 2024.11.08.금요일
 * 2차 수정 내용: rsaes_oaep_encrypt 오류 수정 및 주석 삽입, rsaes_oaep_decrypt 구현 및 주석 삽입
 * 3차 수정일: 2024.11.11.월요일
 * 3차 수정 내용: rsaes_oaep_decrypt 오류 수정 (Error code: 5) 및 디버깅 코드 삽입
 *
 * 4차 수정일: 2024.11.12.화요일
 * 4차 수정 내용: rsaes_oaep_decrypt 오류 수정 (Error code: 4, 5, 6)
 * --------------------2---------------------
 * 학번: 2021043209
 * 이름: 노은솔
 * 
 * 1차 수정일: 2024.11.06 수요일
 * 1차 수정 내용: rsassa_pss_sign 구현 및 주석 삽입
 * 
 * 2차 수정일: 2024.11.10 금요일
 * 2차 수정 내용: rsassa_pss_sign 피드백 반영 및 수정 
 * 
 * 3차 수정일: 2024.11.11 월요일
 * 3차 수정 내용: rsassa_pss_sign 2차 피드백 반영 및 지역 함수로 변환 
 * --------------------3---------------------
 * 학번: 202187083
 * 이름: 이예나
 * 
 * 1차 수정일: 2024.11.04. 월요일
 * 1차 수정 내용: i2osp, mgf1, choose_sha2 구현 및 주석 삽입
 * 
 * 2차 수정일: 2024.11.09 토요일
 * 2차 수정 내용: rsassa_pss_verify 구현 및 주석 삽입
 * 
 * 3차 수정일: 2024.11.12 화요일
 * 3차 수정 내용: i2osp, mgf1 수정
 * 
 * 4차 수정일: 2024.11.13 수요일
 * 4차 수정 내용: rsassa_pss_verify 수정
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
    for(int i=0; i<xLen; i++){
        X[xLen - 1 - i] = x & 0x000000ff;
        x >>= 8;
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
 * SHA-2 해시 길이 설정 함수
 */
size_t get_sha2_digest_size(int sha2_ndx) {
    switch (sha2_ndx) {
        case SHA224: return SHA224_DIGEST_SIZE;
        case SHA256: return SHA256_DIGEST_SIZE;
        case SHA384: return SHA384_DIGEST_SIZE;
        case SHA512: return SHA512_DIGEST_SIZE;
        case SHA512_224: return SHA224_DIGEST_SIZE;
        case SHA512_256: return SHA256_DIGEST_SIZE;
        default: return PKCS_INVALID_PD2; // 유효하지 않은 Hash의 경우 오류 반환
    }
}

/*
 * mgf1 - 해시 함수에 기반한 마스크 생성 함수
 * mgfS: Seed 값, sLen: Seed 길이, m: mLen 길이의 옥텟 문자열 형태의 마스크, mLen: 마스크의 길이, sha2_ndx: 해시 함수
 * mgfS를 받아서 mLen 길이의 m으로 return한다.
 */
unsigned char *mgf1(const unsigned char *mgfS, size_t sLen, unsigned char *m, size_t mLen, int sha2_ndx)
{
    // 해시 값에 따른 해시 길이 설정
    size_t hLen = get_sha2_digest_size(sha2_ndx);

    // 최대 마스크 길이 확인
    //if(mLen > (0xFFFFFFFF * hLen))
    //    return NULL;

    // 해시 계산 횟수 -> count = ceil(mLen / hLen) - 1
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
	// hash function에 따른 label의 길이 검증을 위해 hLen부터 결정.
    size_t hLen = get_sha2_digest_size(sha2_ndx);
    size_t labelLen = 0; // 기본적으로 label을 0이라고 고려.
    const size_t MAX_LABEL_LENGTH = (1ULL << 61) - 1;
    const size_t k = RSAKEYSIZE / 8; // k는 RSA 모듈러스 n의 길이를 바이트 단위로 나타낸 값

	// label이 NULL이 아니라면
	if (label != NULL) {
		labelLen = strlen((const char *) label); // label의 길이 저장
		if (labelLen > MAX_LABEL_LENGTH) return PKCS_LABEL_TOO_LONG; // label의 길이가 최대 hash 값을 넘어서면 오류 반환
	}

	// DataBlock의 길이 상수 선언
	// DB의 길이 = 전체 길이 k에서 masekedSeed의 길이 hLen과 맨 앞 0x00 바이트(1바이트)를 뺀 값.
	const size_t dbLen = k - hLen - 1;
	// message 길이 검증
	if (mLen > dbLen - hLen - 1) return PKCS_MSG_TOO_LONG;

	// label을 hash하여 저장할 변수 선언
	unsigned char lHash[hLen];

	// label에 hash function 적용
	choose_sha2(label, labelLen, lHash, sha2_ndx);
	
	// padding string(PS) 생성
	// padding string의 길이 = DataBlock 길이에서 hash된 label의 길이와 메시지 m의 길이, Padding String 구분자 0x01(1바이트)를 뺀 값.
	const size_t psLen = dbLen - hLen - mLen - 1;
	unsigned char paddingStr[psLen];
	memset(paddingStr, 0, psLen);

	// Data Block 구성
	unsigned char dataBlock[dbLen];

	// dataBlock에 lHash, paddingStr, 0x01, m 순서대로 복사
	size_t offset = 0;
	// lHash 복사
	memcpy(dataBlock + offset, lHash, hLen);
	offset += hLen;
	// paddingStr 복사
	memcpy(dataBlock + offset, paddingStr, psLen);
	offset += psLen;
	// paddingStr 구분자 0x01 추가
	dataBlock[offset] = 0x01;
	offset += 1;
	// m 복사
	memcpy(dataBlock + offset, m, mLen);

	// seed 생성
	unsigned char seed[hLen];
	arc4random_buf(seed, hLen);

	// 생성된 seed가 MGF를 거침. 이게 dbMask.
	unsigned char dbMask[dbLen];
	mgf1(seed, hLen, dbMask, dbLen, sha2_ndx);

	// DB와 dbMask XOR 연산 진행하여 DB에 저장 (Masked DB 도출)
	for (size_t i = 0; i < dbLen; i++) {
		dataBlock[i] ^= dbMask[i];
	}

	// masked DB가 MGF를 거침. 이게 seedMask.
	unsigned char seedMask[hLen];
	mgf1(dataBlock, dbLen, seedMask, hLen, sha2_ndx);

	// seed와 seedMask XOR 연산 진행하기
	for (size_t i = 0; i < hLen; i++) {
		seed[i] ^= seedMask[i];
	}

	// Encoded Message 구성
	unsigned char EM[k];
	offset = 0;
	EM[offset] = 0x00;
	offset += 1;
	memcpy(EM + offset, seed, hLen);
	offset += hLen;
	memcpy(EM + offset, dataBlock, dbLen);
	offset += dbLen;

	// rsa_cipher의 결과가 0이 아니면 오류 return
	if (rsa_cipher(EM, e, n) != 0) return PKCS_MSG_OUT_OF_RANGE;

	// 암호화된 결과 EM을 c에 복사
	memcpy(c, EM, k);
	
	// 성공적으로 암호화가 완료됐다면 return 0;
	return 0;
}

/*
 * rsaes_oaep_decrypt() - RSA decrytion with the EME-OAEP encoding method
 * 암호문 c를 개인키 (d,n)을 사용하여 원본 메시지 m과 길이 len을 회복한다.
 * label과 sha2_ndx는 암호화할 때 사용한 것과 일치해야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d, const void *n, const void *c, int sha2_ndx)
{	
	// label이 NULL인 경우를 대비해 기본 길이를 0으로 설정
	size_t labelLen = 0;
	const size_t MAX_LABEL_LENGTH = (1ULL << 61) - 1;

	// label이 NULL이 아니라면
	if (label != NULL) {
		labelLen = strlen((const char *) label); // label의 길이 저장
		if (labelLen > MAX_LABEL_LENGTH) return PKCS_LABEL_TOO_LONG; // label의 길이가 최대 hash 값을 넘어서면 오류 반환
	}

	// hash function에 따른 label의 길이 검증을 위해 hLen부터 결정.
    size_t hLen = get_sha2_digest_size(sha2_ndx);
	
	// label에 대한 hash 진행. (추후 복원된 DB에서 추출한 lHash와 비교를 위함.)
	unsigned char labelHash[hLen];
	choose_sha2(label, labelLen, labelHash, sha2_ndx);

	// RSA decrypt 진행
	if (rsa_cipher((void *)c, d, n) != 0) return PKCS_MSG_OUT_OF_RANGE;

	// RSA decrytion 후 얻은 암호화된 메시지 c를 EM에 저장
	unsigned char *EM = (unsigned char *) c;	

	// EM 검증 진행
	// EM의 첫 바이트가 0x00이 아니면 오류 return
	size_t offset = 0;
	if (EM[offset] != 0x00) return PKCS_INITIAL_NONZERO;

	offset += 1;

	// maskedSeed 추출
	unsigned char maskedSeed[hLen];
	memcpy(maskedSeed, EM + offset, hLen);
	offset += hLen;
	
	// maskedDB 추출
	size_t dbLen = RSAKEYSIZE / 8 - hLen - 1;
	unsigned char maskedDB[dbLen];
	memcpy(maskedDB, EM + offset, dbLen);

	// Seed 복원
	// maskedSeed = Seed ^ seedMask
	// seedMask = MGF1(maskedDB)
	unsigned char seedMask[hLen];
	// maskedDB에 mgf1을 적용시켜서 seedMask을 얻음.
	mgf1(maskedDB, dbLen, seedMask, hLen, sha2_ndx);
	// maskedSeed와 seedMask를 XOR 연산하여 seed를 얻음.
	unsigned char seed[hLen];
	for (size_t i = 0; i < hLen; i++) {
		seed[i] = maskedSeed[i] ^ seedMask[i];
	}

	// DB 복원
	// maskedDB = dbMask ^ DB
	// dbMask = MGF1(seed)
	// dbMask를 저장할  변수 선언
	unsigned char dbMask[dbLen];
	// seed에 mgf1을 적용시켜서 dbMask를 얻음.
	mgf1(seed, hLen, dbMask, dbLen, sha2_ndx);
	// dbMask와 maskedDB를 XOR 연산하여 DB를 얻음.
	unsigned char dataBlock[dbLen];
	for (size_t i = 0; i < dbLen; i++) {
		dataBlock[i] = maskedDB[i] ^ dbMask[i];
	}

	// 복원된 DB에 대해서 검증
	offset = 0;
	unsigned char lHash[hLen];
	memcpy(lHash, dataBlock + offset, hLen);
	offset += hLen;

	for (size_t i = 0; i < hLen; i++) {
		if (labelHash[i] != lHash[i]) return PKCS_HASH_MISMATCH;
	}

	// paddingStr 파트 지나가기
	size_t psLen = 0;
	while (offset < dbLen && dataBlock[offset] == 0x00) {
		offset++;
		psLen++;
	}

	// paddingStr 파트가 끝나고 그 다음 차례에 구분자 0x01이 오지 않으면 오류 return
	if (offset >= dbLen || dataBlock[offset] != 0x01) return PKCS_INVALID_PS;

	// 구분자 검증 완료하면 offset 1 증가
	offset++;

	*mLen = dbLen - hLen - psLen - 1;
	memcpy(m, dataBlock + offset, *mLen);

	return 0;
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s, int sha2_ndx)
{
    size_t hLen = get_sha2_digest_size(sha2_ndx);
    unsigned char mHash[hLen]; // Hash된 m 값 
    unsigned char salt[hLen];  // Salt 값
    unsigned char m_prime[8 + hLen + hLen]; // M' = 0x00...0 || mHash || salt
    unsigned char h[hLen]; // Hash된 M' 값 
    unsigned char em[RSAKEYSIZE / 8]; // Encoded message 값
    size_t emLen = sizeof(em); // hLen은 해시 함수의 출력 길이, emLen은 최종적으로 서명된 메시지 길이 

    // mLen이 RSA키 크기보다 큰지 확인 
    if (mLen > emLen - hLen - 1) {
        return PKCS_MSG_TOO_LONG; // 메시지가 너무 긴 경우 오류 반환
    }

    // 1. 메시지 해싱 
    if (choose_sha2(m, mLen, mHash, sha2_ndx) != 0) {
        return PKCS_HASH_TOO_LONG; // Hash가 너무 긴 경우 오류 반환 
    }

    // 2. 무작위로 salt 값 생성 
    arc4random_buf(salt, hLen); // 해시 길이만큼 salt 초기화 

    // 3. M' 생성: M' = 0x00...00 || mHash || salt
    memset(m_prime, 0x00, 8); // 첫 8바이트 0x00 패딩
    memcpy(m_prime + 8, mHash, hLen);
    memcpy(m_prime + 8 + hLen, salt, hLen);

    // 4. M' 해싱 (= H)
    if (choose_sha2(m_prime, 8 + hLen + hLen, h, sha2_ndx) != 0) {
        return PKCS_HASH_TOO_LONG; // Hash가 너무 긴 경우 오류 반환 
    }

    // 5. db 생성: db = 0x00...0 || 0x01 || salt
    unsigned char db[emLen - hLen - 1]; // db 생성 
    memset(db, 0x00, emLen - hLen - hLen - 2); // 0 패딩
    db[emLen - hLen - hLen - 2] = 0x01; // 중간에 0x01 추가
    memcpy(db + emLen - hLen - hLen - 1, salt, hLen); // salt 추가

    // 6. h를 mgf1을 이용해 db에 XOR하여 maskedDB 생성
    unsigned char mgf_out[emLen - hLen - 1];
    mgf1(h, hLen, mgf_out, emLen - hLen - 1, sha2_ndx);

    for (size_t i = 0; i < emLen - hLen - 1; i++) {
        db[i] ^= mgf_out[i];
    }

    // 7. maskedDB와 h로 em 구성
    memcpy(em, db, emLen - hLen - 1); // maskedDB 복사
    memcpy(em + emLen - hLen - 1, h, hLen); // h 복사
    em[emLen - 1] = 0xbc; // 마지막 바이트는 0xbc

    // 8. 첫 비트 0으로 설정
    em[0] &= 0x7F;

    // 9. RSA 서명: 인코딩된 em 메시지를 RSA 개인키로 암호화하여 서명 생성 
    if (rsa_cipher(em, d, n) != 0) {
        return PKCS_MSG_OUT_OF_RANGE; // 암호화 실패 시, 오류 반환 
    }

    memcpy(s, em, RSAKEYSIZE / 8);

    return 0; 
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e,n)으로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s, int sha2_ndx)
{
    // 해시 및 키 크기 계산
    size_t hLen = get_sha2_digest_size(sha2_ndx);
    size_t emLen = RSAKEYSIZE / 8;
    size_t dbLen = emLen - hLen - 1;
    size_t m_primeLen = hLen * 2 + 8;

    // 변수 선언
    unsigned char mHash[hLen]; // 해시된 m 값
    unsigned char em[emLen]; // 서명된 메시지 복사본
    unsigned char maskedDb[dbLen]; // EM에서 마스크된 DB 추출
    unsigned char h[hLen]; // EM에서 추출한 H
    unsigned char dbMask[dbLen]; // MGF로 생성한 dbMask
    unsigned char db[dbLen]; // maskedDb와 dbMask를 XOR하여 얻은 DB
    unsigned char salt[hLen]; // 추출된 salt 값
    unsigned char m_prime[m_primeLen]; // M' 값
    unsigned char hashPrime[hLen]; // M'을 해시한 H'

    // 1. 메시지 길이 확인
    if (mLen > 0x1fffffffffffffff) {
        return PKCS_MSG_TOO_LONG;
    }

    // 2. 메시지 해싱
    if (choose_sha2(m, mLen, mHash, sha2_ndx) != 0) {
        return PKCS_HASH_TOO_LONG;
    }

    // 3. EM 복사 및 RSA 검증z
    memcpy(em, s, emLen);
    rsa_cipher((void *)em, e, n);

    // 4. 마지막 바이트 검사
    if (em[emLen - 1] != 0xbc) {
        return PKCS_INVALID_LAST;
    }

    // 5. maskedDB 추출
    memcpy(maskedDb, em, dbLen);

    // 6. H 추출
    memcpy(h, em + dbLen, hLen);

    // 7. EM의 첫 비트 확인
    if ((em[0] >> 7) != 0) {
        return PKCS_INVALID_INIT;
    }

    // 8. dbMask 생성
    mgf1(h, hLen, dbMask, dbLen, sha2_ndx);

    // 9. maskedDB와 dbMask를 XOR하여 DB 복원
    for (size_t i = 0; i < dbLen; i++) {
        db[i] = maskedDb[i] ^ dbMask[i];
    }

    // 10. DB 패딩 확인 (앞쪽이 0x00으로 패딩되고 마지막은 0x01이어야 함)
    size_t padLen = dbLen - hLen;
    if (db[padLen - 1] != 0x01) {
        return PKCS_INVALID_PD2;
    }

    // 11. salt 추출
    memcpy(salt, db + padLen, hLen);

    // 12. M' 생성 (M' = 0x00...00 || mHash || salt)
    memset(m_prime, 0x00, 8);
    memcpy(m_prime + 8, mHash, hLen);
    memcpy(m_prime + 8 + hLen, salt, hLen);

    // 13. M' 해싱하여 H' 계산
    if (choose_sha2(m_prime, m_primeLen, hashPrime, sha2_ndx) != 0) {
        return PKCS_HASH_TOO_LONG;
    }

    // 14. H와 H' 비교
    if (memcmp(hashPrime, h, hLen) != 0) {
        return PKCS_HASH_MISMATCH;
    }

    return 0; // 검증 성공
}
