package com.study.cipher

import android.annotation.SuppressLint
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.DataBindingUtil
import com.study.cipher.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    companion object {
        const val ECDH_CIPHER_SDK = "0"
        const val AES_CIPHER_SDK = "1"
    }

    private var sdk: String? = null
    private lateinit var binding: ActivityMainBinding
    private val ecdhSdkViewModel: EcdhSdkViewModel by viewModels()
    private val aesSdkViewModel: AesSdkViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            //TODO 사용할 SDK 정의
            sdk = ECDH_CIPHER_SDK
            //sdk = AES_CIPHER_SDK

            if (sdk == ECDH_CIPHER_SDK) {
                if ((Build.VERSION.SDK_INT >= Build.VERSION_CODES.S).not()) {
                    Toast.makeText(this, getString(R.string.toast_msg_api_31), Toast.LENGTH_SHORT).show()
                    return
                }
            }
            binding = DataBindingUtil.setContentView(this, R.layout.activity_main)
            binding.mainActivity = this

            initObserver()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun initObserver() {
        //ecdh-cipher-sdk
        if (sdk == ECDH_CIPHER_SDK) {
            ecdhSdkViewModel.publicKey.observe(this) { publicKey ->
                binding.publicKey = publicKey
            }

            ecdhSdkViewModel.espKeyList.observe(this) { keyIdList ->
                binding.keyIdListInESP = keyIdList.toString()
            }

            ecdhSdkViewModel.currentSharedSecretKeyId.observe(this) { currentKeyId ->
                binding.currentKeyId = currentKeyId
            }

            ecdhSdkViewModel.isECKeyPair.observe(this) { isECKeyPair ->
                binding.isEcKeyPair = isECKeyPair
            }

            ecdhSdkViewModel.isSharedSecretKey.observe(this) { isSharedSecretKey ->
                binding.isSharedSecretKey = isSharedSecretKey

            }
        }
    }

    @SuppressLint("NewApi")
    fun onGenerateECKeyPair() {
        try {
            //ecdh-cipher-sdk
            if (sdk == ECDH_CIPHER_SDK) {
                ecdhSdkViewModel.generateECKeyPair()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onAgreementKey() {
        try {
            //ecdh-cipher-sdk
            if (sdk == ECDH_CIPHER_SDK) {
                ecdhSdkViewModel.generateSharedSecretKey()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onReset() {
        try {
            //ecdh-cipher-sdk
            if (sdk == ECDH_CIPHER_SDK) {
                ecdhSdkViewModel.reset()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onSend() {
        try {
            val message = binding.messageEditText.text.toString()
            binding.originMessage = message

            //ecdh-cipher-sdk
            if (sdk == ECDH_CIPHER_SDK) {
                //encrypt
                val encryptedMsg = ecdhSdkViewModel.encrypt(message)
                if (isCipherError(encryptedMsg, CipherState.ENCRYPTION)) {
                    return
                }
                //decrypt
                val decryptedMsg = ecdhSdkViewModel.decrypt(encryptedMsg!!)
                if (isCipherError(decryptedMsg, CipherState.DECRYPTION)) {
                    return
                }
            }

            //aes-cipher-sdk
            if (sdk == AES_CIPHER_SDK) {
                //encrypt
                val encryptedMsg = aesSdkViewModel.encrypt(message)
                if (isCipherError(encryptedMsg, CipherState.ENCRYPTION)) {
                    return
                }
                //decrypt
                val decryptedMsg = aesSdkViewModel.decrypt(encryptedMsg!!)
                if (isCipherError(decryptedMsg, CipherState.DECRYPTION)) {
                    return
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * 암호화 복호화 과정에서 에러가 있었는지 확인하고 UI 를 그려준다.
     * @param message 암호화/복호화 결과 메시지
     * @param mode CipherState.ENCRYPTION, CipherState.DECRYPTION
     * @return 에러가 있다면 true, 없다면 false
     */
    private fun isCipherError(message: String?, mode: CipherState): Boolean {
        if (mode == CipherState.DECRYPTION) {
            if (message == null) {
                binding.decryptedMessage = resources.getString(R.string.error_message)
                binding.editMessage = null
                return true
            } else {
                binding.decryptedMessage = message
                binding.editMessage = null
                return false
            }
        }
        if (mode == CipherState.ENCRYPTION) {
            if (message == null) {
                binding.encryptedMessage = resources.getString(R.string.error_message)
                binding.editMessage = null
                return true
            } else {
                binding.encryptedMessage = message
                binding.editMessage = null
                return false
            }
        }
        return true
    }
}

enum class CipherState() {
    ENCRYPTION, DECRYPTION
}