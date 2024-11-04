# Cryptography
cryptography team project_ team#8_project#5 & #6

## 과제 목표
IETF RFC 8017에 명시된 RSA 공개키 암호체계 PKCS#1 ver. 2.2 구현

## 과제 배경 지식
- **PKCS#1의 종류**
  - **RSAES-OAEP**
    - 암복호 알고리즘 (Encryption/decryption Scheme based on the Optimal Asymmetric Encryption Padding)
  - **RSASSA-PSS**
    - 확률적 전자서명 알고리즘 (Signature Scheme with Appendix based on the Probabilistic Signature Scheme)

## 과제 구현
1. **RSAES-OAEP**: 암호화할 메시지 M을 EM으로 변환한 후, 공개키 (e, n)을 사용하여 $$EM^e mod n$$ 계산
   - Data Block은 Hash(Label) + 00 + 01 + Message로 구성됨.
   - Hash function: 길이가 최소 224비트인 SHA-2 계열의 함수 사용
   - 난수 Seed의 길이 = Hash function의 길이
   - EM의 길이 = RSA의 길이 = 2048bit
2. **RSASSA-PSS**: 서명할 메시지 M을 EM으로 변환한 후, 개인키 (d, n)을 사용하여 $$EM^d mod n$$ 계산
   - Hash function: 길이가 최소 224비트인 SHA-2 계열의 함수 사용
   - 난수 salt의 길이 = Hash function 길이
   - M'의 처음 8바이트는 0x00으로 채움
   - PS는 길이에 맞춰서 0x00으로 채움
   - TF = 0xBC (1바이트)
   - mHash = Hash(M)
   - H = Hash(M')
   - EM의 길이 = RSA의 key의 길이 = 2048bit
   - EM의 가장 왼쪽 비트(MSB, Most Significant Bit)가 1이면 강제로 0으로 바꿈

## 과제 진행 전제
64비트보다 큰 범위에서의 계산이 이루어지므로 GMP 라이브러리 설치 필요.

```bash
sudo apt update
sudo apt install libgmp-dev
```

## 과제 함수 프로토타입
1. **rsa_generate_key**: 길이가 RSAKEYSIZE(2048)인 e, d, n 생성하는 함수
   - mode가 0이면 표준 모드로, e = 65537
   - mode가 0이 아니면 무작위로 선택.
   - 기본 제공되는 함수
   
   ```c
   void rsa_generate_key(void *e, void *d, void *n, int mode);
   ```

2. **rsa_cipher**: $$m ← m^k mod n$$  계산하는 함수
   - 성공하면 0, 그렇지 않으면 오류 코드 반환
   - 기본 제공되는 함수
   
   ```c
   static int rsa_cipher(void *m, const void *k, const void *n);
   ```

3. **SHA-2 해시 함수** (sha224, sha256, sha384, sha512, sha512_224, sha512_256): 길이가 len 바이트인 메시지 m의 SHA-2 hash 값을 digest에 저장하는 함수
   - 기본 제공되는 함수
   
   ```c
   void sha224(const unsigned char *m, unsigned int len, unsigned char *digest);
   void sha256(const unsigned char *m, unsigned int len, unsigned char *digest);
   void sha384(const unsigned char *m, unsigned int len, unsigned char *digest);
   void sha512(const unsigned char *m, unsigned int len, unsigned char *digest);
   void sha512_224(const unsigned char *m, unsigned int len, unsigned char *digest);
   void sha512_256(const unsigned char *m, unsigned int len, unsigned char *digest);
   ```

4. **rsaes_oaep_encrypt**: 길이가 len 바이트인 메시지 m을 공개키 (e, n)으로 암호화한 결과를 c에 저장하는 함수
   - label: 데이터를 식별하기 위한 라벨 문자열. NULL 허용.
   - sha2_ndx는 사용할 SHA-2 해시함수의 색인값. SHA(224, 256, 384, 512, 512_224, 512_256) 중 선택.
   - c의 크기 = RSA의 키의 길이(RSAKEYSIZE) = 2048bit
   - 성공하면 0, 그렇지 않으면 오류 코드 반환
   
   ```c
   int rsaes_oaep_encrypt(const void *m, size_t len, const void *label, const void *e, const void *n, void *c, int sha2_ndx);
   ```

5. **rsaes_oaep_decrypt**: 암호문 c를 개인키 (d, n)을 사용하여 원본 메시지 m과 길이 len을 회복하는 함수
   - label과 sha2_ndx는 암호화할 때 사용한 것과 일치해야 함.
   - 성공하면 0, 그렇지 않으면 오류 코드 반환
   
   ```c
   int rsaes_oaep_decrypt(void *m, size_t *len, const void *label, const void *d, const void *n, const void *c, int sha2_ndx);
   ```

6. **rsassa_pss_sign**: 길이가 len 바이트인 메시지 m을 개인키 (d, n)으로 서명한 결과를 s에 저장하는 함수
   - s의 크기 = RSAKEYSIZE = 2048bit
   - 성공하면 0, 그렇지 않으면 오류 코드 반환
   
   ```c
   int rsassa_pss_sign(const void *m, size_t len, const void *d, const void *n, void *s);
   ```

7. **rsassa_pss_verify**: 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e, n)으로 검증하는 함수
   - 성공하면 0, 그렇지 않으면 오류 코드 반환
   
   ```c
   int rsassa_pss_verify(const void *m, size_t len, const void *e, const void *n, const void *s);
   ```

## 과제에서 사용될 오류 코드
- **PKCS_MSG_OUT_OF_RANGE**: RSA 데이터 값 ≥ modulus n
- **PKCS_MSG_TOO_LONG**: 입력 메시지가 너무 길어 한도 초과
- **PKCS_LABEL_TOO_LONG**: label의 길이가 너무 길어 한도 초과 (RSAES-OAEP)
- **PKCS_INITIAL_NONZERO**: EM의 첫 번째 바이트가 0이 아님. (RSAES-OAEP)
- **PKCS_HASH_MISMATCH**: hash 값이 일치하지 않음.
- **PKCS_INVALID_PS**: Padding String 뒤에 오는 값이 0x01이 아님. (RSAES-OAEP)
- **PKCS_HASH_TOO_LONG**: hash 값의 길이가 너무 커서 수용할 수 없음. (RSASSA-PSS)
- **PKCS_INVALID_LAST**: EM의 마지막 비트(LSB, Least Significant Bit)가 0이 아님. (RSASSA-PSS)
- **PKCS_INVALID_INT**: EM의 처음(MSB) 비트가 0이 아님. (RSASSA-PSS)
- **PKCS_INVALID_PD2**: Data Block의 앞 부분이 0x0000..00||0x01과 일치하지 않음. (RSASSA-PSS)
