# TEAM PROJECT - CRYPTOGRAPHY

## Team#8 Project#5: RSA PKCS#1 v2.2 구현

### 개요
이 과제는 IETF RFC 8017에서 정의된 RSA 공개키 암호체계(PKCS#1 버전 2.2)를 구현하는 프로젝트입니다. 주요 구현 대상은 아래 두 가지입니다:
- **RSAES-OAEP**: 최적 비대칭 암호 패딩(Optimal Asymmetric Encryption Padding)을 기반으로 한 암복호화 알고리즘.
- **RSASSA-PSS**: 확률적 서명 스킴(Probabilistic Signature Scheme)을 기반으로 한 전자서명 알고리즘.

### 주요 목표
1. **RSAES-OAEP**:
   - 메시지를 암호화 전 인코딩된 메시지(EM)로 변환 후 공개키를 사용하여 암호화.
   - SHA-2 계열의 해시 함수를 지원.
   - RSA 키 길이: 2048비트.

2. **RSASSA-PSS**:
   - 개인키를 사용하여 전자서명 생성 및 검증.
   - SHA-2 계열의 해시 함수를 지원.
   - RSA 키 길이: 2048비트.

### 필수 라이브러리
- GMP 라이브러리: 64비트 이상의 정밀도를 지원하는 수학 연산에 필요.

---

## Team#8 Project#6: ECDSA P-256 구현

### 개요
이 과제는 NIST FIPS 186-4에서 정의된 타원곡선 디지털 서명 알고리즘(ECDSA)을 P-256 타원곡선 상에서 구현하는 프로젝트입니다.

### 주요 목표
1. **타원곡선 초기화**:
   - 곡선 방정식: \(y^2 = x^3 - 3x + b \mod p\).
   - 표준 파라미터 \(p\), \(n\), 기저점 \(G\)를 사용.

2. **ECDSA 서명 생성**:
   - SHA-2 해시 함수를 사용하여 메시지를 해싱.
   - 개인키를 사용해 서명 \((r, s)\) 생성.

3. **ECDSA 서명 검증**:
   - 공개키를 사용하여 서명의 유효성을 확인.

### 필수 라이브러리
- GMP 라이브러리: 64비트 이상의 정밀도를 지원하는 수학 연산에 필요.

---

이 두 프로젝트는 Team#8의 암호학 구현 과제로, 암호화와 전자서명 분야에서의 표준을 준수하며 실무적인 응용을 목표로 합니다.
