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
 * 1차 수정일: 2024.11.26.화요일
 * 1차 수정 내용: ecdsa_p256_sign() 함수 구현 및 주석 삽입, 테스트 시 발생한 컴파일 오류 팀원 보고
 *
 * 2차 수정일: 2024.11.28.목요일
 * 2차 수정 내용: Segmentation fault 발생지 탐색 및 오류 해결을 위한 코드 수정
 *
 * 3차 수정일: 2024.12.01.일요일
 * 3차 수정 내용: ecdsa_p256_sign() 함수에서 발생한 ECDSA_MSG_TOO_LONG(오류 코드 1) 에러 해결
 * 
 * 4차 수정일: 2024.12.06.금요일
 * 4차 수정 내용: ecdsa_p256_sign() 함수에서 발생한 Segmentation fault, MP: Cannot allocate memory, k may not be random 에러 해결
 * 
 * --------------------2---------------------
 * 학번: 2021043209
 * 이름: 노은솔
 * 
 * 1차 수정일: 2024.11.30.SAT
 * 1차 수정 내용: ecdsa_p256_verify() 함수 구현 및 주석 추가
 * 
 * 2차 수정일: 2024.12.07 SAT
 * 2차 수정 내용: ecdsa_p256_verify() 함수 디버깅 및 코드 개선
 * 
 * 3차 수정일: 2024.12.09 MON
 * 3차 수정 내용: 전반적인 코드 수정
 * 
 * --------------------3---------------------
 * 학번: 202187083
 * 이름: 이예나
 * 
 * 1차 수정일: 2024.11.24. 일요일
 * 1차 수정 내용: choose_sha2(), get_sha2_digest_size(), ecdsa_point_add(), ecdsa_point_double(), ecdsa_mul(), 
 *               ecdsa_p256_init(), ecdsa_p256__clear(), ecdsa_p256_key() 구현 및 주석 삽입
 * 
 * 2차 수정일: 2024.11.27. 수요일
 * 2차 수정 내용: ecdsa_mul(), ecdsa_p256_key() 수정
 * 
 * 3차 수정일: 2024.12.05. 목요일
 * 3차 수정 내용: ecdsa_p256_key() 수정
 * 
 * 4차 수정일: 2024.12.09 MON
 * 4차 수정 내용: 전반적인 코드 수정
 */

#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include "ecdsa.h"
#include "sha2.h"
#include <gmp.h>
#include <stdbool.h>
#include <string.h>

mpz_t p, n; // 타원곡선의 소수 p와 차수 n
ecdsa_p256_t G; // 기저점 G

/*
 * sha2 함수를 정해서 해당 sha 함수를 호출한다.
 * message: 해시할 메시지, len: 메시지 길이, digest: 해시 결과 저장할 배열, sha2_ndx: 해시 함수 
 */
void choose_sha2(const unsigned char *message, unsigned int len, unsigned char *digest, int sha2_ndx){
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
    }
}

/*
 * SHA-2 해시 길이 설정 함수
 */
int get_sha2_digest_size(int sha2_ndx){
    switch (sha2_ndx)
    {
        case SHA224:
            return SHA224_DIGEST_SIZE;
            break;
        case SHA256:
            return SHA256_DIGEST_SIZE;
            break;
        case SHA384:
            return SHA384_DIGEST_SIZE;
            break;
        case SHA512:
            return SHA512_DIGEST_SIZE;
            break;
        case SHA512_224:
            return SHA224_DIGEST_SIZE;
            break;
        case SHA512_256:
            return SHA256_DIGEST_SIZE;
    }
    return 0;
}

/*
 * 타원곡선 상에서 점 덧셈
 * P + Q = R 계산 (P != 0)
 * p: 소수, R: 결과점, P: 점P, Q: 점Q
 */
int ecdsa_point_add(ecdsa_p256_t *P, ecdsa_p256_t *Q, ecdsa_p256_t *R){
    mpz_t Px, Py, Qx, Qy, Rx, Ry, lambda, temp;
    mpz_inits(Px, Py, Qx, Qy, Rx, Ry, lambda, temp, NULL);
    
    mpz_import(Px, ECDSA_P256/8, 1, 1, 1, 0, P->x);
    mpz_import(Py, ECDSA_P256/8, 1, 1, 1, 0, P->y);
    mpz_import(Qx, ECDSA_P256/8, 1, 1, 1, 0, Q->x);
    mpz_import(Qy, ECDSA_P256/8, 1, 1, 1, 0, Q->y);

    if(mpz_cmp_ui(Px, 0) == 0 && mpz_cmp_ui(Py, 0) == 0) {
        // O + Q = Q 
        mpz_set(Rx, Qx);
        mpz_set(Ry, Qy);
    } else if(mpz_cmp_ui(Qx, 0) == 0 && mpz_cmp_ui(Qy, 0) == 0) {
        // P + O = P 
        mpz_set(Rx, Px);
        mpz_set(Ry, Py);
    } else {
        // lambda 계산
        mpz_sub(lambda, Qy, Py);   // lambda = Qy - Py
        mpz_sub(temp, Qx, Px);     // temp = Qx - Px

        // P + Q = O일 경우, return 1
        if(mpz_cmp_ui(temp, 0) == 0) {
            mpz_clears(Px, Py, Qx, Qy, Rx, Ry, lambda, temp, NULL);
            return 1;
        }

        mpz_invert(temp, temp, p);     // temp = (Qx - Px)^(-1) mod p
        mpz_mul(lambda, lambda, temp); // lambda = (Qy - Py) / (Qx - Px)
        mpz_mod(lambda, lambda, p);    // lambda mod p

        // Rx 계산
        mpz_mul(Rx, lambda, lambda); // Rx = lambda^2
        mpz_sub(Rx, Rx, Px);         // Rx = lambda^2 - Px
        mpz_sub(Rx, Rx, Qx);         // Rx = lambda^2 - Px - Qx
        mpz_mod(Rx, Rx, p);          // Rx mod p

        // Ry 계산
        mpz_sub(Ry, Px, Rx);         // Ry = Px - Rx
        mpz_mul(Ry, lambda, Ry);     // Ry = lambda * (Px - Rx)
        mpz_sub(Ry, Ry, Py);         // Ry = lambda * (Px - Rx) - Py
        mpz_mod(Ry, Ry, p);          // Ry mod p
    }

    mpz_export(R->x, NULL, 1, ECDSA_P256/8, 1, 0, Rx);
    mpz_export(R->y, NULL, 1, ECDSA_P256/8, 1, 0, Ry);

    mpz_clears(Px, Py, Qx, Qy, Rx, Ry, lambda, temp, NULL);
    return 0;
}

/*
 * 타원곡선 상에서 점 두 배 계산
 * P + P = R 계산
 * p: 소수, R: 결과점, P: 점P
 */
int ecdsa_point_double(ecdsa_p256_t *P, ecdsa_p256_t *R){
    mpz_t Px, Py, Rx, Ry, lambda, temp;
    mpz_inits(Px, Py, Rx, Ry, lambda, temp, NULL);
    mpz_import(Px, ECDSA_P256 / 8, 1, 1, 1, 0, P->x);
    mpz_import(Py, ECDSA_P256 / 8, 1, 1, 1, 0, P->y);

    // Lambda = (3 * Px^2 + a) / (2 * Py) mod p
    mpz_mul(lambda, Px, Px);          // Lambda = Px^2
    mpz_mul_ui(lambda, lambda, 3);    // Lambda *= 3 => 3 * Px^2
    mpz_sub_ui(lambda, lambda, 3);    // Lambda += a => 3 * Px^2 + a

    mpz_mul_ui(temp, Py, 2);        // temp = 2 * Py
    mpz_invert(temp, temp, p);      // temp = (2 * py) ^(-1) mod p
    mpz_mul(lambda, lambda, temp);  // Lambda *= temp => (3 * Px^2 - 3) / 2Py
    mpz_mod(lambda, lambda, p);     // Lambda = Lambda mod p

    // Rx = Lamdba^2 - 2 * Px mod p
    mpz_mul(Rx, lambda, lambda);    // Rx = Lambda^2 => ((3Px^2 - 3) / 2Py)^2
    mpz_sub(Rx, Rx, Px);            // Rx -= Px => ((3Px^2 - 3) / 2Py)^2 - Px
    mpz_sub(Rx, Rx, Px);            // Rx -= Px => ((3Px^2 - 3) / 2Py)^2 - 2 * Px
    mpz_mod(Rx, Rx, p);             // Rx = Rx mod p

    // Ry = Lambda * (Px - Rx) - Py mod p
    mpz_sub(Ry, Px, Rx);      // Ry = Px - Rx
    mpz_mul(Ry, lambda, Ry);  // Ry *= Lambda => Ry = ((3 * Px^2 - 3) / 2Py) * (Px - Rx)
    mpz_sub(Ry, Ry, Py);      // Ry -= Py = ((3 * Px^2 - 3) / 2Py) * (Px - Rx) - Py
    mpz_mod(Ry, Ry, p);       // Ry = Ry mod p
  
    mpz_export(R->x, NULL, 1, ECDSA_P256/8, 1, 0, Rx);
    mpz_export(R->y, NULL, 1, ECDSA_P256/8, 1, 0, Ry);

    mpz_clears(Px, Py, Rx, Ry, temp, NULL);
    return 0;
}

/*
 * Sclalar multiplication on elliptic curve
 * k * P = Q 계산
 * p: 소수, Q: 결과점, k: 스칼라, P: 점P
 * 가장 높은 비트부터 반복하며 비트가 1이면 현재 결과에 G 더하고, 각 단계에서 점을 두 배로 늘림
 * k의 이진 표현을 따라 kG를 효율적으로 계산
 */
void ecdsa_mul(ecdsa_p256_t *a, const mpz_t d, ecdsa_p256_t *b) {
    ecdsa_p256_t temp; // 임시 변수로 곱셈 계산 결과를 저장
    unsigned long num_bits = mpz_sizeinbase(d, 2); // 스칼라 d의 이진 표현에서 비트 수 계산

    memset(b->x, 0, ECDSA_P256 / 8); // 결과 b를 초기화 (x = 0)
    memset(b->y, 0, ECDSA_P256 / 8); // 결과 b를 초기화 (y = 0)

    memcpy(&temp, a, sizeof(ecdsa_p256_t)); // temp에 a를 복사 (초기화)

    // 반복적으로 비트마다 처리
    for (unsigned long i = 0; i < num_bits; ++i) {
        if (mpz_tstbit(d, i)) { // d의 i번째 비트가 1인지 확인
            ecdsa_point_add(b, &temp, b); // b = b + temp
        }
        ecdsa_point_double(&temp, &temp); // temp = 2 * temp
    }
}


/*
 * Initialize 256 bit ECDSA parameters
 * 시스템파라미터 p, n, G의 공간을 할당하고 값을 초기화한다.
 */
void ecdsa_p256_init(void)
{
    mpz_t Gx, Gy;

    mpz_inits(Gx, Gy, NULL);

    mpz_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    mpz_set_str(Gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    mpz_set_str(Gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);

    mpz_export(G.x, NULL, 1, ECDSA_P256 / 8, 1, 0, Gx);
    mpz_export(G.y, NULL, 1, ECDSA_P256 / 8, 1, 0, Gy);

    mpz_clears(Gx, Gy, NULL);
}

/*
 * Clear 256 bit ECDSA parameters
 * 할당된 파라미터 공간을 반납한다.
 */
void ecdsa_p256_clear(void)
{
    mpz_clears(p, n, NULL);
}

/*
 * ecdsa_p256_key() - generates Q = dG
 * 사용자의 개인키와 공개키를 무작위로 생성한다.
 */
void ecdsa_p256_key(void *d, ecdsa_p256_t *Q)
{
    mpz_t private_key;
    mpz_init(private_key);

    // d를 랜덤으로 생성 
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    mpz_urandomm(private_key, state, n);   

    // Q = dG 
    ecdsa_p256_t temp;  // G값을 저장하고 계산에 이용할 임시 변수
    memset(Q->x, 0, ECDSA_P256 / 8);        // Q->x 초기화
    memset(Q->y, 0, ECDSA_P256 / 8);        // Q->y 초기화
    memcpy(&temp.x, &G.x, ECDSA_P256 / 8);  // G의 x값 복사
    memcpy(&temp.y, &G.y, ECDSA_P256 / 8);  // G의 x값 복사
    ecdsa_mul(&temp, private_key, Q);
    
    mpz_export(d, NULL, 1, ECDSA_P256 / 8, 1, 0, private_key); 

    mpz_clear(private_key);
}


/*
 * ecdsa_p256_sign(msg, len, d, r, s) - ECDSA Signature Generation
 * 길이가 len 바이트인 메시지 m을 개인키 d로 서명한 결과를 r, s에 저장한다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. r과 s의 길이는 256비트이어야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_sign(const void *msg, size_t len, const void *d, void *_r, void *_s, int sha2_ndx)
{
    // 변수 선언
    mpz_t e_mpz, d_mpz, k, r, s;
    ecdsa_p256_t sign;
    gmp_randstate_t state;

    const size_t MAX_MSG_LEN = (1ULL << 64) - 1;
    if (len > MAX_MSG_LEN) return ECDSA_MSG_TOO_LONG;

    // 1. e = H(msg)
    size_t hlen = get_sha2_digest_size(sha2_ndx); // 사용하는 hash 함수의 길이 저장 
    unsigned char e[hlen];
    choose_sha2(msg, len, e, sha2_ndx);
    
    // 2. e의 길이가 n의 길이(256비트)보다 길면 뒷 부분은 자른다. bitlen(e) ≤ bitlen(n) 
    if (sha2_ndx == SHA384 || sha2_ndx == SHA512) hlen = SHA256_DIGEST_SIZE;  // 256bit
    else hlen = get_sha2_digest_size(sha2_ndx); // 기존 비트 수 유지
    mpz_inits(e_mpz, d_mpz, k, r, s, NULL);
    mpz_import(e_mpz, hlen, 1, 1, 1, 0, e);  // 해시 길이만큼 e를 잘라서 저장
    mpz_import(d_mpz, ECDSA_P256 / 8, 1, 1, 1, 0, d);
    
    // G값을 저장하고 계산에 이용할 임시 변수
    ecdsa_p256_t tempG;  
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());

    do
    {
        // 3. 비밀값 k를 무작위로 선택한다. (0 < k < n) 
        do {
        	mpz_urandomm(k, state, n); 
		} while (mpz_cmp_ui(k, 0) == 0);

        // 4. (x1, y1) = kG 
        memset(sign.x, 0, ECDSA_P256 / 8);          // x1 초기화
        memset(sign.y, 0, ECDSA_P256 / 8);          // y1 초기화
        memcpy(&tempG.x, &G.x, ECDSA_P256 / 8);     // G의 x값 복사
        memcpy(&tempG.y, &G.y, ECDSA_P256 / 8);     // G의 y값 복사

        ecdsa_mul(&tempG, k, &sign);   // (x1, y1 생성)

        // 5. r = x1 mod n 생성
        mpz_import(r, ECDSA_P256 / 8, 1, 1, 1, 0, sign.x); // x1 == sign.x
        mpz_mod(r, r, n);

        // 6. s = k^-1 * (e + r * d) mod n 
        mpz_invert(k, k, n);            // k = k^-1
        mpz_mul(d_mpz, r, d_mpz);       // d_mpz = rd
        mpz_add(d_mpz, e_mpz, d_mpz);   // d_mpz = e + rd
        mpz_mul(s, k, d_mpz);           // s = k^-1 * (e + rd)
        mpz_mod(s, s, n);               // s = k^-1 * (e + rd) mod n

    } while (mpz_cmp_ui(r, 0) == 0 || mpz_cmp_ui(s, 0) == 0);

    mpz_export(_r, NULL, 1, ECDSA_P256 / 8, 1, 0, r);
    mpz_export(_s, NULL, 1, ECDSA_P256 / 8, 1, 0, s);

    mpz_clears(e_mpz, d_mpz, k, r, s, NULL);

    return 0;
}

/*
 * ecdsa_p256_verify(msg, len, Q, r, s) - ECDSA signature veryfication
 * It returns 0 if valid, nonzero otherwise.
 * 길이가 len 바이트인 메시지 m에 대한 서명이 (r,s)가 맞는지 공개키 Q로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *_Q, const void *_r, const void *_s, int sha2_ndx)
{
    const size_t MAX_MSG_LEN = (1ULL << 64) - 1;
    if (len > MAX_MSG_LEN) return ECDSA_MSG_TOO_LONG;
   
    // 변수 선언
    mpz_t r, s, e_mpz, temp, w, u1, u2, x1;
    ecdsa_p256_t u1G, u2Q, XY;

    mpz_inits(r, s, e_mpz, w, temp, u1, u2, x1, NULL);
    mpz_import(r, ECDSA_P256/8, 1, 1, 1, 0, _r);
    mpz_import(s, ECDSA_P256/8, 1, 1, 1, 0, _s);   

    // 1. r, s 범위 검증 => r과 s는 [1, n-1] 범위 내에 있어야 함 
    if (mpz_cmp_ui(r, 0) <= 0 || mpz_cmp(r, n) >= 0 ||  // 1 <= r < n
        mpz_cmp_ui(s, 0) <= 0 || mpz_cmp(s, n) >= 0) {  // 1 <= s < n
        mpz_clears(r, s, NULL);
        return ECDSA_SIG_INVALID;
    }

    // 2. e = H(msg)
    size_t hlen = get_sha2_digest_size(sha2_ndx);
    unsigned char e[hlen];
    choose_sha2(msg, len, e, sha2_ndx);
    
    // 3. e의 길이가 n의 길이(256비트)보다 길면 뒷 부분을 자른다. bitlen(e) <= bitlen(n) 
    if (sha2_ndx == SHA384 || sha2_ndx == SHA512) hlen = SHA256_DIGEST_SIZE;  // 256bit
    else hlen = get_sha2_digest_size(sha2_ndx); // 기존 비트 수 유지
    mpz_import(e_mpz, hlen, 1, 1, 1, 0, e);  // 해시 길이만큼 e를 잘라서 저장

    // 4. s 역원인 w 계산 => w = 1/s mod n
    if (!mpz_invert(w, s, n)) { // s와 n이 서로소가 아닌 경우, 오류 반환
        return ECDSA_SIG_INVALID; 
    }

    // 5. u1, u2 계산 => u1 = e * w mod n, u2 = r * w mod n
    mpz_mul(u1, e_mpz, w);   // u1 = e*s^-1 
    mpz_mod(u1, u1, n);      // u1 = u1 mod n
    mpz_mul(u2, r, w);       // u2 = r*s^-1 
    mpz_mod(u2, u2, n);      // u2 = u2 mod n

    // 6. 점(x1, y1) 계산 => (x1, y1) = u1 * G + u2 * Q 
    ecdsa_p256_t tempG;  // G값을 저장하고 계산에 이용할 임시 변수
    ecdsa_p256_t tempQ;  // Q값을 저장하고 계산에 이용할 임시 변수
    memcpy(&tempG.x, &G.x, ECDSA_P256 / 8);    // G의 x값 복사
    memcpy(&tempG.y, &G.y, ECDSA_P256 / 8);    // G의 y값 복사
    memcpy(&tempQ.x, _Q->x, ECDSA_P256 / 8);   // Q의 x값 복사
    memcpy(&tempQ.y, _Q->y, ECDSA_P256 / 8);   // Q의 y값 복사

    // u1G, u2Q를 0으로 초기화
    memset(u1G.x, 0, ECDSA_P256 / 8);   
    memset(u1G.y, 0, ECDSA_P256 / 8);
    memset(u2Q.x, 0, ECDSA_P256 / 8);
    memset(u2Q.y, 0, ECDSA_P256 / 8);

    // u1 * G
    ecdsa_mul(&tempG, u1, &u1G);

    // u2 * Q
    ecdsa_mul(&tempQ, u2, &u2Q);

    // u1 * G + u2 * Q
    if (ecdsa_point_add(&u1G, &u2Q, &XY)==1) return ECDSA_SIG_INVALID;

    // 8. x1 mod n == r 검증 
    mpz_import(x1, ECDSA_P256 / 8, 1, 1, 1, 0, XY.x);
    mpz_mod(x1, x1, n);   // x1 = x1 mod n

    if(mpz_cmp(x1, r)!= 0) {
        return ECDSA_SIG_MISMATCH;
    }

    mpz_clears(r, s, e_mpz, temp, w, u1, u2, x1, NULL);
    return 0;
}