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
 * 1차 수정 내용: ecdsa_p256_sign() 함수 구현 및 주석 삽입
 * --------------------2---------------------
 * 학번: 2021043209
 * 이름: 노은솔
 * --------------------3---------------------
 * 학번: 202187083
 * 이름: 이예나
 * 
 * 1차 수정일: 2024.11.24. 일요일
 * 1차 수정 내용: choose_sha2(), get_sha2_digest_size(), ecdsa_point_add(), ecdsa_point_double(), ecdsa_mul(), 
 *               ecdsa_p256_init(), ecdsa_p256__clear(), ecdsa_p256_key() 구현 및 주석 삽입
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

mpz_t p, n; // 타원곡선의 소수 p와 차수 n
ecdsa_p256_t G; // 기저점 G

/*
 * sha2 함수를 정해서 해당 sha 함수를 호출한다.
 * message: 해시할 메시지, len: 메시지 길이, digest: 해시 결과 저장할 배열, sha2_ndx: 해시 함수 
 */
int choose_sha2(const unsigned char *message, unsigned int len, unsigned char *digest, int sha2_ndx){
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
size_t get_sha2_digest_size(int sha2_ndx){
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
        default:
            return 0;
    }
}

/*
 * 타원곡선 상에서 점 덧셈
 * P + Q = R 계산 (P != 0)
 * p: 소수, R: 결과점, P: 점P, Q: 점Q
 */
void ecdsa_point_add(mpz_t *Rx, mpz_t *Ry, const mpz_t *Px, const mpz_t *Py, const mpz_t *Qx, const mpz_t *Qy, const mpz_t p){
    mpz_t lambda, temp;

    mpz_inits(lambda, temp, NULL);

    // Lambda = (Qy - Py) / (Qx - Px) mod p
    mpz_sub(temp, *Qy, *Py); // temp = Qy - Py
    mpz_sub(lambda, *Qx, *Px); // Lambda = Qx - Px
    mpz_invert(lambda, lambda, p); // Lambda = (Qx - Px)^(-1) mod p
    mpz_mul(lambda, lambda, temp); // Lamda *= (Qy - Py)
    mpz_mod(lambda, lambda, p); // Lambda = Lambda mod p

    // Rx = Lambda^2 - Px - Qx mod p
    mpz_powm_ui(temp, lambda, 2, p); // temp = Lambda^2
    mpz_sub(temp, temp, *Px); // temp -= Px
    mpz_sub(temp, temp, *Qx); // temp -= Qx
    mpz_mod(*Rx, temp, p); // Rx = temp mod p

    // Ry = Lambda * (Px - Rx) - Py mod p
    mpz_sub(temp, *Px, *Rx); // temp = Px - Rx
    mpz_mul(temp, lambda, temp); //temp *= Lambda
    mpz_sub(temp, temp, *Py); // temp -= Py
    mpz_mod(*Ry, temp, p); // Ry = temp mod p

    mpz_clears(lambda, temp, NULL);
}

/*
 * 타원곡선 상에서 점 두 배 계산
 * P + P = R 계산
 * p: 소수, R: 결과점, P: 점P
 */
void ecdsa_point_double(mpz_t *Rx, mpz_t *Ry, const mpz_t *Px, const mpz_t *Py, const mpz_t a, const mpz_t p){
    mpz_t lambda, temp;

    mpz_inits(lambda, temp, NULL);

    //Lambda = (3 * Px^2 + a) / (2 * Py) mod p
    mpz_powm_ui(lambda, *Px, 2, p); // Lambda = Px^2
    mpz_mul_ui(lambda, lambda, 3); // Lambda *= 3
    mpz_add(lambda, lambda, a); // Lambda += a

    mpz_mul_ui(temp, *Py, 2); // temp = 2 * Py
    mpz_invert(temp, temp, p); // temp = (2 * py) ^(-1) mod p
    mpz_mul(lambda, lambda, temp); // Lambda *= temp
    mpz_mod(lambda, lambda, p); // Lambda = Lambda mod p

    // Rx = Lamdba^2 - 2 * Px mod p
    mpz_powm_ui(temp, lambda, 2, p); // temp = Lambda^2
    mpz_sub(temp, temp, *Px); // temp -= Px
    mpz_sub(temp, temp, *Px); // temp -= Px
    mpz_mod(*Rx, temp, p); // Rx = temp mod p

    // Ry = Lambda * (Px - Rx) - Py mod p
    mpz_sub(temp, *Px, *Rx); // temp = Px - Rx
    mpz_mul(temp, lambda, temp); // temp *= Lambda
    mpz_sub(temp, temp, *Py); // temp -= Py
    mpz_mod(*Ry, temp, p); // Ry = temp mod p

    mpz_clears(lambda, temp, NULL);
}

/*
 * Sclalar multiplication on elliptic curve
 * k * P = Q 계산
 * p: 소수, Q: 결과점, k: 스칼라, P: 점P
 * 가장 높은 비트부터 반복하며 비트가 1이면 현재 결과에 G 더하고, 각 단계에서 점을 두 배로 늘림
 * k의 이진 표현을 따라 kG를 효율적으로 계산
 */
void ecdsa_mul(const mpz_t k, const ecdsa_p256_t G, mpz_t *Qx, mpz_t *Qy){
    mpz_t Px, Py;
    mpz_inits(Px, Py, NULL);

    mpz_import(Px, sizeof(G.x), 1, 1, 1, 0, G.x); // G의 x 좌표
    mpz_import(Py, sizeof(G.y), 1, 1, 1, 0, G.y); // G의 y 좌표

    bool first = true;

    for(int i = mpz_sizeinbase(k, 2)-1; i>=0; i--){ // k의 각 비트 처리
        if(!first){
            ecdsa_point_double(Qx, Qy, Qx, Qy, NULL, p); // 점 두 배
        }

        if(mpz_tstbit(k, i)){ // 현재 비트가 1이면 점 덧셈 수행
            if(first){
                mpz_set(*Qx, Px);
                mpz_set(*Qy, Py);
                first = false;
            }else{
                ecdsa_point_add(Qx, Qy, Qx, Qy, &Px, &Py, p);
            }
        }
    }
    mpz_clears(Px, Py, temp_x, temp_y, NULL);
}

/*
 * Initialize 256 bit ECDSA parameters
 * 시스템파라미터 p, n, G의 공간을 할당하고 값을 초기화한다.
 */
void ecdsa_p256_init(void)
{
    mpz_t Gx, Gy;

    mpz_inits(p, n, Gx, Gy, NULL);

    mpz_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    mpz_set_str(Gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    mpz_set_str(Gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);

    mpz_export(G.x, NULL, 1, ECDSA_P256 / 8, 0, Gx);
    mpz_export(G.y, NULL, 1, ECDSA_P256 / 8, 0, Gy);

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
    // 개인키 초기화
    mpz_t private_key;
    mpz_init(private_key);

    // 난수 생성기 초기화
    gmp_randstate_t state;
    gmp_randinit_default(state);
    // 난수 생성기로 개인키 d 생성
    gmp_randseed_ui(state, arc4random());
    gmp_urandomm(private_key, state, n);

    // G의 좌표 임시 변수 temp에 복사
    ecdsa_p256_t temp;
    memset(Q->x, 0, ECDSA_P256 / 8);
    memset(Q->y, 0, ECDSA_P256 / 8);
    memcpy(&temp.x, &G.x, ECDSA_P256 / 8);
    memcpy(&temp.y, &G.y, ECDSA_P256 / 8);
    // dG 계산하여 Q 생성
    ecdsa_mul(&temp, private_key, Q);

    //개인키 저장 (mpz_t 형식의 d를 바이트 배열로 변환해 저장)
    mpz_export(d, NULL, 1, ECDSA_P256 / 8, 1, 0, private_key);

    // 공간 반납
    gmp_randclear(state);
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
    if (len > ECDSA_P256 / 8) return ECDSA_MSG_TOO_LONG;

    // 사용하는 hash함수의 길이 저장
    const size_t hlen = get_sha2_digest_size(sha2_ndx);
    // e = H(m)
    unsigned char e[hlen];
    choose_sha2(msg, len, e, sha2_ndx);

    // e의 길이가 n의 길이(256비트)보다 클 경우
    if (hlen > ECDSA_P256 / 8) {
        // 바이트 배열로 선언된 e를 mpz_t 타입으로 변환
        mpz_t e_truncated;
        mpz_init(e_truncated);
        mpz_import(e_truncated, hlen, 1, 1, 1, 0, e);

        // e_truncated를 자르기 위해서 mask 생성
        mpz_t mask;
        mpz_init(mask);
        mpz_set_ui(mask, 0);
        mpz_setbit(mask, ECDSA_P256);
        mpz_sub_ui(mask, mask, 1);

        mpz_and(e_truncated, e_truncated, mask);
        mpz_clear(mask);

        size_t e_len = 0;
        mpz_export(e, &e_len, 1, 1, 1, 0, e_truncated);
        mpz_clear(e_truncated);
    }

    mpz_t r, s;
    mpz_inits(r, s, NULL);

    do {
        // k값 무작위 선택
        mpz_t k;
        mpz_init(k);
        gmp_randstate_t state;
        gmp_randinit_default(state);
        mpz_urandomm(k, state, n); // 범위는 (0, n)

        // (x1, y1) = kG
        mpz_t x1, y1;
        mpz_inits(x1, y1, NULL);
        ecdsa_mul(k, G, &x1, &y1);

        // r = x1 mod n
        mpz_mod(r, x1, n);

        mpz_t k_inverse;
        mpz_init(k_inverse);
        mpz_invert(k_inverse, k, n);

        mpz_t tmp;
        mpz_init(tmp);
        // 바이트 배열로 저장된 d를 mpz_t로 변환
        mpz_t d_mpz;
        mpz_import(d_mpz, ECDSA_P256 / 8, 1, 1, 1, 0, d);
        // 바이트 배열로 저장된 e를 mpz_t로 변환
        mpz_t e_mpz;
        mpz_import(e_mpz, hlen, 1, 1, 1, 0, e);
        // tmp = r * d
        mpz_mul(tmp, r, d);
        // tmp = e + r * d
        mpz_add(tmp, e_mpz, tmp);
        // s = k^(-1) * (e + r * d) = k^(-1) * tmp
        mpz_mul(s, k_inverse, tmp);
    } while(mpz_cmp_ui(r, 0) == 0 || mpz_cmp_ui(s, 0) == 0);

    mpz_export(_r, NULL, 1, ECDSA_P256 / 8, 1, 0, r);
    mpz_export(_s, NULL, 1, ECDSA_P256 / 8, 1, 0, s);

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
}
