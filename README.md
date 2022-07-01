
Key Generator 에서 참고
Android Unable to create EC KeyPair
https://stackoverflow.com/questions/43671748/android-unable-to-create-ec-keypair

Key Agreement 에서 참고
Derive Shared Secret From ECDH with existing foreign public key
https://stackoverflow.com/questions/57238837/derive-shared-secret-from-ecdh-with-existing-foreign-public-key

KeyGenParameterSpec 공식 문서
https://developer.android.com/reference/kotlin/android/security/keystore/KeyGenParameterSpec




//Base64
****** 개념이 조금 꼬임 - AndroidStudioProject - My Application 내 테스트 중인 코드 보고 다시 정리할 것


-8비트 이진 데이터를 문자 코드에 영향을 받지 않는 공통 아스키(ASCII(1)) 영역의 "문자"들로만(2) 이루어진 일련의 문자열로 바꾸는 인코딩 방식을 가리키는 개념
-64진법으로 A-Z, a-z, 0-9 총 62개 문자숫자 + 2개의 기호 사용
-Encoding : String -> Base64 [**using encode method (depending on library)** or **toByteArray()**]

-Decoding : Base64 -> String [**using decode method (depending on library)** or **String()**]

1: 알바벳을 사용하는 대표적인 문자 인코딩
2: 문자가 아닌 데이터 ex. 백스페이스, 수직탭 등

```kotlin
//android.util.Base64
//Encoding Example(String -> Base64)
val data: ByteArray = data.toByteArray()
val encodedString: String = Base64.getEncoder().encodeToString(oriString.toByteArray())



//Decoding Example(Base64 -> String)
val result: String = Base64.encodeToString(_result, Base64.DEFAULT) //publicKey 를 서버에 전송하는 경우 DEFAULT 옵션 사용
String(result)

```
Base64 encoding and decoding in Kotlin
https://www.techiedelight.com/base64-encoding-and-decoding-in-kotlin/


Kotlin Base64 Encoding and Decoding
https://www.bezkoder.com/kotlin-base64/


//KeyStore

//AES padding / ECB







***
공식 문서 예시 참고 에러 메시지와 시도했던 것들
Example: EC key for ECDH key agreement

Caused by: android.security.keystore.KeyPermanentlyInvalidatedException: Key permanently invalidated
1. sceenlock 설정 후 앱재설치(Such keys are permanently and irreversibly invalidated once the secure lock screen is disabled)
2. data class 에 키 담지 않고 사용(데이터 클래스에 담으면 유효성 없어지나 의심했음)
3. keyPairA/B 를 싱글톤 패턴 변수로 빼서 실행 시켜봄
private : android.security.keystore2.AndroidKeyStoreECPrivateKey@e6260955 // public : android.security.keystore2.AndroidKeyStoreECPublicKey@f9c961f8
android.security.keystore2.AndroidKeyStoreECPrivateKey@553e6aa6 // public : android.security.keystore2.AndroidKeyStoreECPublicKey@1fbdd7da
***
