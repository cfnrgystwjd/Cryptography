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
 * --------------------2---------------------
 * 학번: 2021043209
 * 이름: 노은솔
 * 
 * 1차 수정일: 2024.11.30.SAT
 * 1차 수정 내용: ecdsa_p256_verify() 함수 구현 및 주석 추가
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
        default:
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

    // Lambda = (Qy - Py) / (Qx - Px) mod p
    mpz_sub(temp, Qy, Py); // temp = Qy - Py
    mpz_sub(lambda, Qx, Px); // Lambda = Qx - Px
    mpz_invert(lambda, lambda, p); // Lambda = (Qx - Px)^(-1) mod p
    mpz_mul(lambda, lambda, temp); // Lamda *= (Qy - Py)
    mpz_mod(lambda, lambda, p); // Lambda = Lambda mod p

    // Rx = Lambda^2 - Px - Qx mod p
    mpz_powm_ui(temp, lambda, 2, p); // temp = Lambda^2
    mpz_sub(temp, temp, Px); // temp -= Px
    mpz_sub(temp, temp, Qx); // temp -= Qx
    mpz_mod(Rx, temp, p); // Rx = temp mod p

    // Ry = Lambda * (Px - Rx) - Py mod p
    mpz_sub(temp, Px, Rx); // temp = Px - Rx
    mpz_mul(temp, lambda, temp); //temp *= Lambda
    mpz_sub(temp, temp, Py); // temp -= Py
    mpz_mod(Ry, temp, p); // Ry = temp mod p

    mpz_export(R->x, NULL, 1, ECDSA_P256/8, 1, 0, Rx);
    mpz_export(R->y, NULL, 1, ECDSA_P256/8, 1, 0, Ry);
    mpz_clears(lambda, temp, NULL);
    return 0;
}

/*
 * 타원곡선 상에서 점 두 배 계산
 * P + P = R 계산
 * p: 소수, R: 결과점, P: 점P
 */
int ecdsa_point_double(ecdsa_p256_t *P, ecdsa_p256_t *R){
    mpz_t Rx, Ry, Px, Py;
    mpz_t lambda, temp;

    mpz_inits(Rx, Ry, Px, Py, lambda, temp, NULL);
    mpz_import(Px, ECDSA_P256/8, 1, 1, 1, 0, P->x);
    mpz_import(Py, ECDSA_P256/8, 1, 1, 1, 0, P->y);

    //Lambda = (3 * Px^2 + a) / (2 * Py) mod p
    mpz_powm_ui(lambda, Px, 2, p); // Lambda = Px^2
    mpz_mul_ui(lambda, lambda, 3); // Lambda *= 3
    mpz_add(lambda, lambda, -3); // Lambda += a

    mpz_mul_ui(temp, Py, 2); // temp = 2 * Py
    mpz_invert(temp, temp, p); // temp = (2 * py) ^(-1) mod p
    mpz_mul(lambda, lambda, temp); // Lambda *= temp
    mpz_mod(lambda, lambda, p); // Lambda = Lambda mod p

    // Rx = Lamdba^2 - 2 * Px mod p
    mpz_powm_ui(temp, lambda, 2, p); // temp = Lambda^2
    mpz_sub(temp, temp, Px); // temp -= Px
    mpz_sub(temp, temp, Px); // temp -= Px
    mpz_mod(Rx, temp, p); // Rx = temp mod p

    // Ry = Lambda * (Px - Rx) - Py mod p
    mpz_sub(temp, Px, Rx); // temp = Px - Rx
    mpz_mul(temp, lambda, temp); // temp *= Lambda
    mpz_sub(temp, temp, Py); // temp -= Py
    mpz_mod(Ry, temp, p); // Ry = temp mod p

    mpz_export(R->x, NULL, 1, ECDSA_P256/8, 1, 0, Rx);
    mpz_export(R->y, NULL, 1, ECDSA_P256/8, 1, 0, Ry);

    mpz_clears(Rx, Ry, Px, Py, lambda, temp, NULL);
    return 0;
}

/*
 * Sclalar multiplication on elliptic curve
 * k * P = Q 계산
 * p: 소수, Q: 결과점, k: 스칼라, P: 점P
 * 가장 높은 비트부터 반복하며 비트가 1이면 현재 결과에 G 더하고, 각 단계에서 점을 두 배로 늘림
 * k의 이진 표현을 따라 kG를 효율적으로 계산
 */
void ecdsa_mul(ecdsa_p256_t *a, mpz_t d, ecdsa_p256_t *b){
    unsigned long int i = 0;
    unsigned long int bitts = ECDSA_P256;

    while(i <= bitts){
        if(mpz_tstbit(d, i) == 1){
            ecdsa_point_add(b, a, b);
        }

        ecdsa_point_double(a, a);
        i++;
    }
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
    // 개인키 초기화
    mpz_t private_key;
    mpz_init(private_key);

    // 난수 생성기 초기화
    gmp_randstate_t state;
    gmp_randinit_default(state);

    // 난수 생성기로 개인키 d 생성
    gmp_randseed_ui(state, arc4random());
    mpz_urandomm(private_key, state, n);

    // G의 x, y 좌표를 mpz_t로 변환
    mpz_t Gx, Gy, Qx, Qy;
    mpz_inits(Gx, Gy, Qx, Qy, NULL);

    mpz_import(Gx, sizeof(G.x), 1, 1, 1, 0, G.x); // G의 x 좌표를 mpz_t로 변환
    mpz_import(Gy, sizeof(G.y), 1, 1, 1, 0, G.y); // G의 y 좌표를 mpz_t로 변환

    // Q = private_key * G
    ecdsa_mul(private_key, G, &Qx, &Qy);

    // Q의 결과를 ecdsa_p256_t로 저장
    memset(Q->x, 0, ECDSA_P256 / 8);
    memset(Q->y, 0, ECDSA_P256 / 8);
    mpz_export(Q->x, NULL, 1, ECDSA_P256 / 8, 1, 0, Qx);
    mpz_export(Q->y, NULL, 1, ECDSA_P256 / 8, 1, 0, Qy);

    // 개인키 d를 내보내기
    memset(d, 0, ECDSA_P256 / 8);
    mpz_export(d, NULL, 1, ECDSA_P256 / 8, 1, 0, private_key);

    // 리소스 해제
    mpz_clears(private_key, Gx, Gy, Qx, Qy, NULL);
    gmp_randclear(state);
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
    size_t hlen = get_sha2_digest_size(sha2_ndx);
    // e = H(m)
    unsigned char e[hlen];
    choose_sha2(msg, len, e, sha2_ndx);

    mpz_t ee, dd, k, r, s;
    mpz_inits(ee, dd, k, r, s, NULL);

    ecdsa_p256_t sign;
    gmp_randstate_t state;

    // e의 길이가 n의 길이(256비트)보다 클 경우
    if (hlen > ECDSA_P256 / 8) {
        hlen = SHA256_DIGEST_SIZE;
    }

    mpz_import(ee, hlen, 1, 1, 1, 0, d);
    mpz_import(dd, ECDSA_P256/8, 1, 1, 1, 0, d);

    ecdsa_p256_t temp;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());

    do {
        // k값 무작위 선택
        mpz_t k;
        mpz_urandomm(k, state, n);

        // (x1, y1) = kG
        memset(sign.x, 0, ECDSA_P256/8);
        memset(sign.y, 0, ECDSA_P256/8);
        memcpy(&temp.x, &G.x, ECDSA_P256/8);
        memcpy(&temp.y, &G.y, ECDSA_P256/8);

        ecdsa_mul(&temp, k, &sign);

        // r = x1 mod n
        mpz_import(r, ECDSA_P256/8, 1, 1, 1, 0, sign.x);
        mpz_mod(r, r, n);

        mpz_invert(k, k, n);
        mpz_mul(dd, r, dd);
        mpz(dd, ee, dd);
        mpz_mul(s, k, dd);
        mpz_mod(s, s, n);
    } while(mpz_cmp_ui(r, 0) == 0 || mpz_cmp_ui(s, 0) == 0);

    mpz_export(_r, NULL, 1, ECDSA_P256 / 8, 1, 0, r);
    mpz_export(_s, NULL, 1, ECDSA_P256 / 8, 1, 0, s);

    mpz_clears(ee, dd, k, r, s, NULL);

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

    // 1. r, s 범위 검증 => r과 s는 [1, n-1] 범위 내에 있어야 함 
    mpz_t r, s;
    mpz_inits(r, s, NULL);
    mpz_import(r, ECDSA_P256 / 8, 1, 1, 1, 0, _r);
    mpz_import(s, ECDSA_P256 / 8, 1, 1, 1, 0, _s);

    if (mpz_cmp_ui(r, 1) < 0 || mpz_cmp(r, n) >= 0 ||  // 1 <= r < n
        mpz_cmp_ui(s, 1) < 0 || mpz_cmp(s, n) >= 0) {  // 1 <= s < n
        // mpz_clears(r, s, NULL);
        return ECDSA_SIG_INVALID;
    }

// printf("r = "); mpz_out_str(stdout, 10, r); printf("\n");
// printf("s = "); mpz_out_str(stdout, 10, s); printf("\n");
// printf("n = "); mpz_out_str(stdout, 10, n); printf("\n");

    // 2. 메시지 Hash 계산 => e = H(msg)
    size_t hlen = get_sha2_digest_size(sha2_ndx);
    unsigned char e[hlen];
    if(choose_sha2(msg, len, e, sha2_ndx) != 0) {
        return ECDSA_SIG_INVALID;
    }

// printf("Hash of message (e): ");
// for (size_t i = 0; i < hlen; i++) {
//     printf("%02x", e[i]);
// }
// printf("\n");

    // 3. Hash 값 e가 n보다 클 경우
    mpz_t e_truncated;
    mpz_init(e_truncated);
    if (hlen > ECDSA_P256 / 8) {
        hlen = SHA256_DIGEST_SIZE;
        mpz_import(e_truncated, hlen, 1, 1, 1, 0, e);  // 해시 길이만큼 e를 잘라서 저장


// printf("Truncated Hash (e): ");
// for (size_t i = 0; i < ECDSA_P256 / 8; i++) {
//     printf("%02x", e[i]);
// }
// printf("\n");

        mpz_clear(e_truncated);
    }

    // 4. s 역원인 w 계산 => w = 1/s mod n
    mpz_t w; // s의 역원
    mpz_init(w);
    if (!mpz_invert(w, s, n)) { // s와 n이 서로소가 아닌 경우, 오류 반환
        mpz_clears(r, s, w, NULL);
        return ECDSA_SIG_INVALID; 
    }

// printf("w = "); mpz_out_str(stdout, 10, w); printf("\n");

    // 5. u1, u2 계산 => u1 = e * w mod n, u2 = r * w mod n
    mpz_t u1, u2, e_mpz;
    mpz_inits(u1, u2, e_mpz, NULL);
    mpz_import(e_mpz, hlen, 1, 1, 1, 0, e_truncated); // e 배열을 mpz_t 타입(e_mpz)로 변환
    mpz_mul(u1, e_mpz, w);
    mpz_mod(u1, u1, n);
    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, n);

    // 6. 점(x1, y1) 계산 => (x1, y1) = u1 * G + u2 * Q
    ecdsa_p256_t tempG;
    ecdsa_p256_t tempQ;
    ecdsa_p256_t u1G, u2Q, XY;

    memcpy(&tempG.x, &G.x, ECDSA_P256 / 8);
    memcpy(&tempG.y, &G.y, ECDSA_P256 / 8);
    memcpy(&tempQ.x, _Q->x, ECDSA_P256 / 8);
    memcpy(&tempQ.y, _Q->y, ECDSA_P256 / 8);

    // u1G, u2Q를 0으로 초기화 
    memset(u1G.x, 0, ECDSA_P256 / 8);
    memset(u1G.y, 0, ECDSA_P256 / 8);
    memset(u1Q.x, 0, ECDSA_P256 / 8);
    memset(u1Q.y, 0, ECDSA_P256 / 8);

    ecdsa_mul(&tempG, u1, &u1G);
    ecdsa_mul(&tempQ, u2, &u2Q);

    if (ecdsa_point_add(&u1G, &u2Q, &XY)==1) {
        return ECDSA_SIG_INVALID;
    }

// printf("u1 * G: (x, y) = ");
// mpz_out_str(stdout, 10, u1G_x); printf(", ");
// mpz_out_str(stdout, 10, u1G_y); printf("\n");
// printf("u2 * Q: (x, y) = ");
// mpz_out_str(stdout, 10, u2Q_x); printf(", ");
// mpz_out_str(stdout, 10, u2Q_y); printf("\n");
// printf("Result: (x1, y1) = ");
// mpz_out_str(stdout, 10, x1); printf(", ");
// mpz_out_str(stdout, 10, y1); printf("\n");

    // // 7. 점이 무한점인지 확인
    // if (mpz_cmp_ui(x1, 0) == 0 && mpz_cmp_ui(y1, 0) == 0) {
    //     mpz_clears(e, r, s, w, u1, u2, qx, qy, x1, y1, u1G_x, u1G_y, u2Q_x, u2Q_y, NULL);
    //     return ECDSA_SIG_INVALID;
    // }

    // printf("Point check: x1 = "); mpz_out_str(stdout, 10, x1); printf(", y1 = "); mpz_out_str(stdout, 10, y1); printf("\n");

    // 8. x1 mod n = r 검증
    mpz_t x1;
    mpz_init(x1);
    mpz_import(x1, ECDSA_P256 / 8, 1, 1, 1, 0, XY.x);
    mpz_mod(x1, x1, n);   // v = x1 mod n
// printf("x1 mod n = "); mpz_out_str(stdout, 10, x1); printf("\n");
// printf("r = "); mpz_out_str(stdout, 10, r); printf("\n");

    if (mpz_cmp(x1, r) != 0) {
        printf("Signature verification failed: x1 mod n does not match r.\n");
        mpz_clears(r, s, w, u1, u2, e_mpz, x1, NULL);
        return ECDSA_SIG_MISMATCH;
    }

    mpz_clears(r, s, w, u1, u2, x1, e_mpz, e_truncated, NULL);

    return 0;
}