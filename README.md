
Key Generator 에서 참고
Android Unable to create EC KeyPair
https://stackoverflow.com/questions/43671748/android-unable-to-create-ec-keypair

Key Agreement 에서 참고
Derive Shared Secret From ECDH with existing foreign public key
https://stackoverflow.com/questions/57238837/derive-shared-secret-from-ecdh-with-existing-foreign-public-key

KeyGenParameterSpec 공식 문서
https://developer.android.com/reference/kotlin/android/security/keystore/KeyGenParameterSpec

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
