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

    private lateinit var binding: ActivityMainBinding

    private var sdk: String? = null

    private val ecdhSdkViewModel: EcdhSdkViewModel by viewModels()
    private val aesSdkViewModel: AesSdkViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            //TODO 사용할 SDK 정의
            //sdk = ECDH_CIPHER_SDK
            sdk = AES_CIPHER_SDK

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
                binding.publicKeyTextView.text = publicKey
            }

            ecdhSdkViewModel.espKeyList.observe(this) { keyIdList ->
                binding.publicKeyIdTextView.text = keyIdList.toString()
            }

            ecdhSdkViewModel.currentSharedSecretKeyId.observe(this) { currentKeyId ->
                binding.keyIdTextView.text = currentKeyId
            }

            ecdhSdkViewModel.isECKeyPair.observe(this) { isECKeyPair ->
                binding.keyAgreementButton.isEnabled = isECKeyPair
            }

            ecdhSdkViewModel.isSharedSecretKey.observe(this) { isSharedSecretKey ->
                binding.sendButton.isEnabled = isSharedSecretKey
            }
        }

        //aes-cipher-sdk
        if (sdk == AES_CIPHER_SDK) {

        }
    }

    @SuppressLint("NewApi")
    fun onGenerateECKeyPair() {
        try {
            //ecdh-cipher-sdk
            if (sdk == ECDH_CIPHER_SDK) {
                ecdhSdkViewModel.generateECKeyPair()
            }

            //aes-cipher-sdk
            if (sdk == AES_CIPHER_SDK) {

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

            //aes-cipher-sdk
            if (sdk == AES_CIPHER_SDK) {

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

            //aes-cipher-sdk
            if (sdk == AES_CIPHER_SDK) {

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
                ecdhSdkViewModel.encrypt(message).let { encryptedMsg ->
                    if (encryptedMsg == null) {
                        binding.encryptionCBCTextView.text = resources.getString(R.string.error_message)
                        return
                    }
                    binding.encryptionCBCTextView.text = encryptedMsg

                    //decrypt
                    ecdhSdkViewModel.decrypt(encryptedMsg).let { decryptedMsg ->
                        if (decryptedMsg == null) {
                            binding.decryptionCBCTextView.text = resources.getString(R.string.error_message)
                            return
                        }
                        binding.decryptionCBCTextView.text = decryptedMsg
                    }
                }
                binding.messageEditText.text = null
            }

            //aes-cipher-sdk
            if (sdk == AES_CIPHER_SDK) {
                //encrypt
                aesSdkViewModel.encrypt(message).let { encryptedMsg ->
                    if (encryptedMsg == null) {
                        binding.encryptionCBCTextView.text = resources.getString(R.string.error_message)
                        return
                    }
                    binding.encryptedMessage = encryptedMsg
                }

                //decrypt
                val encryptedMessage = binding.encryptedMessage?.ifEmpty {
                    return
                }
                aesSdkViewModel.decrypt(encryptedMessage!!).let { decryptedMsg ->
                    if (decryptedMsg == null) {
                        binding.decryptionCBCTextView.text = resources.getString(R.string.error_message)
                        return
                    }
                    binding.decryptedMessage = decryptedMsg
                }

                //null
                binding.editMessage = null
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}