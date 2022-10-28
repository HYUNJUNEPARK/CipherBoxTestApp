package com.study.cipherbox.app

import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.DataBindingUtil
import com.study.cipherbox.R
import com.study.cipherbox.databinding.ActivityMainBinding
import com.study.cipherbox.sdk.CipherBox
import com.study.cipherbox.sdk.EncryptedSharedPreferencesManager
import com.study.cipherbox.sdk.ECKeyUtil
import com.study.cipherbox.vm.KeyViewModel

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var cipherBox: CipherBox
    private lateinit var keyId: String
    private lateinit var espm: EncryptedSharedPreferencesManager

    private val viewModel: KeyViewModel by viewModels()

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

                viewModel.getPublicKey()
                viewModel.publicKey.observe(this) { publicKey ->
                    binding.publicKeyTextView.text = publicKey
                }
            } else {
                Toast.makeText(this, "API 31 이상 사용 가능", Toast.LENGTH_SHORT).show()
            }
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
            viewModel.reset()
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