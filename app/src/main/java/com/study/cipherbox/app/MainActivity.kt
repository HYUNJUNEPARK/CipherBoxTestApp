package com.study.cipherbox.app

import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.DataBindingUtil
import com.study.cipherbox.R
import com.study.cipherbox.databinding.ActivityMainBinding
import com.study.cipherbox.sdk.CipherBox
import com.study.cipherbox.sdk.EncryptedSharedPreferencesManager
import com.study.cipherbox.sdk.util.ECKeyUtil

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var cipherBox: CipherBox
    private lateinit var keyId: String
    private lateinit var espm: EncryptedSharedPreferencesManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                binding = DataBindingUtil.setContentView(this, R.layout.activity_main)
                cipherBox = CipherBox.getInstance(this)!!
                binding.mainActivity = this
                espm = EncryptedSharedPreferencesManager.getInstance(this)!!

                isECKey()
                getKeyListOnESP()
                getPublicKey()
            } else {
                Toast.makeText(this, "API 31 이상 사용 가능", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun getPublicKey() {
        try {
            val _publicKey = cipherBox.getECPublicKey()
            val publicKey = ECKeyUtil.publicKeyToString(_publicKey)
            binding.publicKeyTextView.text = publicKey.toString()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun isECKey() {
        try {
            binding.keyAgreementButton.isEnabled = cipherBox.isECKeyPair()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun getKeyListOnESP() {
        try {
            espm.getKeyIdList().let {
                    keyIdList ->
                val keyIds = StringBuffer("")
                for (keyId in keyIdList!!) {
                    keyIds.append("$keyId\n")
                }
                binding.publicKeyIdTextView.text = keyIds.toString()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onGenerateECKeyPair() {
        try {
            getPublicKey()
            cipherBox.generateECKeyPair()
            binding.keyAgreementButton.isEnabled = true
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onAgreementKey() {
        try {
            keyId = cipherBox.generateRandom(32)

            cipherBox.generateSharedSecretKey(
                publicKey = cipherBox.getECPublicKey(),
                nonce = keyId
            )

            binding.keyIdTextView.text = keyId
            binding.sendButton.isEnabled = true
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onReset() {
        try {
            cipherBox.reset()
            binding.keyAgreementButton.isEnabled = false
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onSend() {
        try {
            val message = binding.messageEditText.text.toString()
            val encryptedMsg = cipherBox.encrypt(message, keyId)
            val decryptedMsg = cipherBox.decrypt(encryptedMsg, keyId)

            binding.userMessageTextView.text = message
            binding.encryptionCBCTextView.text = encryptedMsg
            binding.decryptionCBCTextView.text = decryptedMsg

            binding.messageEditText.text = null
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}