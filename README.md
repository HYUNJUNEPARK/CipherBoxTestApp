<img src="" height="400"/>


---
1. <a href = "#content1">Base64</a></br>
* <a href = "#ref">참고링크</a>
---
**ECC(Elliptic Curve Cryptography, 타원곡선 암호 기술)** : EC(타원곡선)를 사용한 암호기술의 총체적인 이름</br>
-ECDSA : 디지털서명 용도</br>
-ECDH : 키교환 용도</br>
-Dual-EC-DRBG : 난수 생성용도</br>
<br></br>

**SHA-256(Secure Hash Algorithm)** : 어떤 길이의 값을 입력하더라도 256비트(32바이트) 고정된 결과값 반환</br>
-단방향 암호화(평문으로 복호화할 수 없는 암호화)로 속도가 빠르며 비밀번호 일치여부 확인에 많이 사용됨</br>
<br></br>

**AES 테스트 앱 암복호화 과정**</br>
EC 알고리즘 기반 키페어 생성(private/public key)</br>
-> 내 개인 키(private key)와 상대방 공개 키(public key) 로 공유키(Shared Secret Key) 생성</br>
-> 생성된 공유키(Shared Secret Key)(32 bytes)에 랜덤 바이트 배열(32 bytes)을 사용해 SHA-256 으로 해시 생성(32 byte)</br>
-> 해시를 키로 캐스팅하고 암호화/복호화에 사용</br>
<br></br>

**ECB**</br>
-가장 단순한 모드로 블록 단위로 순차적으로 암호화 하는 구조</br>
-한개의 블록만 해석되면 나머지 블록도 해석가능</br>
-원본 데이터를 16bytes 로 쪼개서 암호화 하는 구조</br>
-암호화 된 데이터의 어느 부분이라도 16바이트로 나누어 해석</br>
<br></br>

**CBC**</br>
-ECB 에 비해 기술적으로 더 복잡함(암호화 운영 모드 중 보안성이 제일 높은 암호화 방법)</br>
-16바이트로 암호화 한 데이터가 다음 16바이트 암호화에 적용되어 상호 연관 관계에 의해 원본 데이터 중간만 따로 해석할 수 없음</br>
-각 블록이 XOR연산을 통해 이전 암호문과 연산되고 첫번째 암호문에 대해서는 IV가 암호문 대신 상용됨</br>
<br></br>

><a id = "content1">**1. Base64**</a></br>

-8비트 이진 데이터를 문자 코드에 영향을 받지 않는 공통 아스키(ASCII(*1)) 영역의 "문자"들로만(*2) 이루어진 일련의 문자열로 바꾸는 인코딩 방식을 가리키는 개념</br>
-64진법으로 A-Z, a-z, 0-9 총 62개 문자숫자 + 2개의 기호 사용</br>
*1: 알바벳을 사용하는 대표적인 문자 인코딩</br>
*2: 문자가 아닌 데이터 ex. 백스페이스, 수직탭 등</br>

```kotlin
import android.util.Base64

val testString = "test text"

//encoding
val encoded: String = Base64.encodeToString(testString.toByteArray(), Base64.DEFAULT) //Output : U29tZSB0ZXh0

//decoding
val decoded_bytes = Base64.decode(encoded, Base64.DEFAULT)
val decoded_str = String(decoded_bytes) //Output : test text
```

<br></br>
<br></br>
---

><a id = "ref">**참고링크**</a></br>

Save and Retrieve KeyPair in AndroidKeystore</br> (updadteKeyPairToKeyStore()/keyStoreKeyPair 에서 참고)
https://stackoverflow.com/questions/42110123/save-and-retrieve-keypair-in-androidkeystore</br>

AES/CBC 암복호화 참고 코드</br>
http://www.fun25.co.kr/blog/java-aes128-cbc-encrypt-decrypt-example</br>

Android Unable to create EC KeyPair (Key Generator 에서 참고)</br>
https://stackoverflow.com/questions/43671748/android-unable-to-create-ec-keypair</br>

Derive Shared Secret From ECDH with existing foreign public key (Key Agreement 에서 참고)</br>
https://stackoverflow.com/questions/57238837/derive-shared-secret-from-ecdh-with-existing-foreign-public-key</br>

KeyGenParameterSpec 공식 문서</br>
https://developer.android.com/reference/kotlin/android/security/keystore/KeyGenParameterSpec</br>

Base64 encoding and decoding in Kotlin (Base64 샘플 코드에서 참고)</br>
https://www.techiedelight.com/base64-encoding-and-decoding-in-kotlin/</br>

AES 암호화 모듈 및 ECB/CBC Mode 차이점</br>
https://linuxforge.tistory.com/191</br>

How to store secret key in keystore and retrieve</br>
https://stackoverflow.com/questions/24231213/how-to-store-secretkey-in-keystore-and-retrieve-it</br>

코틀린 Singleton Pattern</br>
https://bacassf.tistory.com/59</br>

How to set a ripple effect on textview or imageview on Android?</br>
https://stackoverflow.com/questions/33477025/how-to-set-a-ripple-effect-on-textview-or-imageview-on-android</br>

SharedPreferences 간단하게 사용하기 (Kotlin)</br>
https://leveloper.tistory.com/133</br>

ViewModel 에서 context 필요로 할 때 해결방법</br>
https://youngest-programming.tistory.com/327</br>