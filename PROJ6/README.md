# Cryptography  
**Team Project: Team#8_Project#6**  

## 과제 목표  
NIST FIPS 186-4에 명시된 **ECDSA (Elliptic Curve Digital Signature Algorithm)** 전자서명 기법을 타원곡선 **P-256** 상에서 구현  

## 과제 배경 지식  

### 타원곡선 P-256 정의  
- 타원곡선 방정식:  
  $$y^2 = x^3 - 3x + b \ (\text{mod} \ p)$$  
- **파라미터:**  
  - $$p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
  - **기저점 (Base Point, G):**  
    - G_x = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296 
    - G_y = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5  
  - **차수 (Order, n):**  
    $$n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 
  - -$$n$$G = $$O:  
    $$O는 무한대 점 (항등원)

### ECDSA  
#### 주요 파라미터  
1. **E**: 타원곡선. 유한체 위에서 정의.  
2. **q**: 충분히 큰 소수 (160비트 이상) 
3. **G**: 곡선 위 차수 q를 가지는 한 점.  

#### 공개키와 개인키  
- **개인키 (d):**  
  - 범위: [1, q-1]
  - d != 0
- **공개키 (Q):**  
  - $$Q = $$d$$G, 곡선 상의 점.  

#### 서명 생성 (Signature Generation)  
1. 메시지 m에 대해 **SHA-2 해시** 적용. \( e = H(m) \)  
2. e 길이가 n보다 길면 잘라서 사용 (e의 길이 <= n의 길이).  
3. \( k \)를 \( (0, n) \)에서 무작위로 선택.  
4. \( (x_1, y_1) = kG \) 계산.  
5. \( r = x_1 \mod n \), \( r \neq 0 \)이면 진행.  
6. \( s = k^{-1}(e + rd) \mod n \), \( s \neq 0 \)이면 진행.  
7. 서명: \( (r, s) \).  

#### 서명 검증 (Signature Verification)  
1. \( r, s \in [1, n-1] \) 확인.  
2. \( e = H(m) \), 필요시 길이 자르기.  
3. \( u_1 = es^{-1} \mod n \), \( u_2 = rs^{-1} \mod n \).  
4. \( (x_1, y_1) = u_1G + u_2Q \).  
   - \( (x_1, y_1) = O \)이면 서명 오류.  
5. \( r \equiv x_1 \ (\text{mod} \ n) \)일 경우 서명 일치.  

## GMP 라이브러리 설치  
GMP를 사용하여 64비트 이상 정밀도의 수학 연산을 지원.  

```bash
sudo apt update
sudo apt install libgmp-dev
```  

## 과제 함수 프로토타입  

### 1. **초기화 및 정리**  
- **ecdsa_p256_init:**  
  시스템 파라미터 \( p, n, G \)를 초기화.  
  ```c
  void ecdsa_p256_init(void);
  ```  

- **ecdsa_p256_clear:**  
  파라미터 할당 해제.  
  ```c
  void ecdsa_p256_clear(void);
  ```  

### 2. **키 생성**  
- **ecdsa_p256_key:**  
  개인키 \( d \)와 공개키 \( Q \) 무작위 생성.  
  ```c
  void ecdsa_p256_key(void *d, ecdsa_p256_t *Q);
  ```  

### 3. **전자서명**  
- **ecdsa_p256_sign:**  
  메시지 \( m \) (길이 \( len \))을 개인키 \( d \)로 서명. \( r, s \)에 결과 저장.  
  - \( sha2_ndx \): 사용할 SHA-2 해시 함수 색인값.  
  - 반환값: 성공 시 0, 실패 시 오류 코드.  

  ```c
  int ecdsa_p256_sign(const void *m, size_t len, const void *d, void *r,
                      void *s, int sha2_ndx);
  ```  

### 4. **서명 검증**  
- **ecdsa_p256_verify:**  
  메시지 \( m \) (길이 \( len \))의 서명 \( (r, s) \)가 공개키 \( Q \)로 올바른지 검증.  
  - 반환값: 성공 시 0, 실패 시 오류 코드.  

  ```c
  int ecdsa_p256_verify(const void *m, size_t len, const ecdsa_p256_t *Q,
                        const void *r, const void *s, int sha2_ndx);
  ```  

## 오류 코드  
- **ECDSA_MSG_TOO_LONG**: 입력 메시지 초과.  
- **ECDSA_SIG_INVALID**: 서명 형식 또는 값이 잘못됨.  
- **ECDSA_SIG_MISMATCH**: 서명 불일치.
