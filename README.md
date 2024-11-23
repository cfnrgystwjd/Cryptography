# Cryptography  
cryptography team project_ team#8_project#6  

## 과제 목표  
NIST FIPS 186-4에 명시된 **ECDSA (Elliptic Curve Digital Signature Algorithm)** 전자서명 기법을 타원곡선 **P-256** 상에서 구현  

---

## 과제 배경 지식  
- **ECDSA의 주요 파라미터**
  - **타원곡선 (Elliptic Curve) E**  
    유한체 위에서 정의된 타원곡선  
  - **q**  
    충분히 큰 소수 (160비트 이상)  
  - **기저점 (Base Point, G)**  
    차수 \( q \)를 가지는 곡선 위의 한 점  

---

### 공개키와 개인키  
1. **개인키 (d)**  
   - 범위: \( [1, q-1] \)  
   - 조건: \( d \neq 0 \)  
2. **공개키 (Q)**  
   - \( Q = dG \)  

---

### 서명 생성 (Signature Generation)  
1. 메시지 \( m \)에 SHA-2 해시 적용: \( e = H(m) \)  
   - \( e \)의 길이가 \( n \)보다 길면 잘라서 사용 (\( e \leq n \))  
2. \( k \in (0, n) \)에서 무작위로 선택  
3. \( (x_1, y_1) = kG \) 계산  
4. \( r = x_1 \mod n \), \( r \neq 0 \)일 경우 진행  
5. \( s = k^{-1}(e + rd) \mod n \), \( s \neq 0 \)일 경우 진행  
6. 서명: \( (r, s) \)  

---

### 서명 검증 (Signature Verification)  
1. \( r, s \in [1, n-1] \) 확인  
2. \( e = H(m) \), 필요 시 길이 자르기  
3. \( u_1 = es^{-1} \mod n \), \( u_2 = rs^{-1} \mod n \)  
4. \( (x_1, y_1) = u_1G + u_2Q \)  
   - \( (x_1, y_1) = O \)이면 서명 오류  
5. \( r \equiv x_1 \ (\text{mod} \ n) \)일 경우 서명 일치  

---

## 과제 진행 전제  
64비트 이상의 계산이 필요하므로 GMP 라이브러리 설치가 요구됩니다.  

```bash
sudo apt update
sudo apt install libgmp-dev


## 과제 함수 프로토타입
1. **rsa_generate_key**: 길이가 RSAKEYSIZE(2048)인 e, d, n 생성하는 함수
   - mode가 0이면 표준 모드로, e = 65537
   - mode가 0이 아니면 무작위로 선택.
   - 기본 제공되는 함수
   
   ```c
   void rsa_generate_key(void *e, void *d, void *n, int mode);
   ```

2. **rsa_cipher**: $$m ← m^k$$ mod $$n$$  계산하는 함수
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
