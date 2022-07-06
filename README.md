1. <a href = "#content1">Base64</a></br>
2. <a href = "#content2">KeyStore</a></br>
3. <a href = "#content3">content3</a></br>
* <a href = "#ref">참고링크</a>
---
><a id = "content1">**1. Base64**</a></br>

-8비트 이진 데이터를 문자 코드에 영향을 받지 않는 공통 아스키(ASCII(*1)) 영역의 "문자"들로만(*2) 이루어진 일련의 문자열로 바꾸는 인코딩 방식을 가리키는 개념
-64진법으로 A-Z, a-z, 0-9 총 62개 문자숫자 + 2개의 기호 사용
*1: 알바벳을 사용하는 대표적인 문자 인코딩
*2: 문자가 아닌 데이터 ex. 백스페이스, 수직탭 등

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

><a id = "content2">**2. KeyStore**</a></br>




<br></br>
<br></br>


><a id = "content3">**3. content3**</a></br>




<br></br>
<br></br>
---

><a id = "ref">**참고링크**</a></br>

Android Unable to create EC KeyPair (Key Generator 에서 참고)</br>
https://stackoverflow.com/questions/43671748/android-unable-to-create-ec-keypair</br>

Derive Shared Secret From ECDH with existing foreign public key (Key Agreement 에서 참고)</br>
https://stackoverflow.com/questions/57238837/derive-shared-secret-from-ecdh-with-existing-foreign-public-key</br>

KeyGenParameterSpec 공식 문서</br>
https://developer.android.com/reference/kotlin/android/security/keystore/KeyGenParameterSpec</br>

Base64 encoding and decoding in Kotlin (Base64 샘플 코드에서 참고)</br>
https://www.techiedelight.com/base64-encoding-and-decoding-in-kotlin/</br>