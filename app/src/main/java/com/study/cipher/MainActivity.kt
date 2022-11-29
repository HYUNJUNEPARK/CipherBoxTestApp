package com.study.cipher

import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.viewModels
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.DataBindingUtil
import com.study.cipher.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val viewModel: EcdhSdkViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            if ((Build.VERSION.SDK_INT >= Build.VERSION_CODES.S).not()) {
                Toast.makeText(this, getString(R.string.toast_msg_api_31), Toast.LENGTH_SHORT).show()
                return
            }

            binding = DataBindingUtil.setContentView(this, R.layout.activity_main)
            binding.mainActivity = this

            initObserver()

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun initObserver() {
        viewModel.publicKey.observe(this) { publicKey ->
            binding.publicKeyTextView.text = publicKey
        }

        viewModel.espKeyList.observe(this) { keyIdList ->
            binding.publicKeyIdTextView.text = keyIdList.toString()
        }

        viewModel.currentSharedSecretKeyId.observe(this) { currentKeyId ->
            binding.keyIdTextView.text = currentKeyId
        }

        viewModel.isECKeyPair.observe(this) { isECKeyPair ->
            binding.keyAgreementButton.isEnabled = isECKeyPair
        }

        viewModel.isSharedSecretKey.observe(this) { isSharedSecretKey ->
            binding.sendButton.isEnabled = isSharedSecretKey
        }
    }

    @RequiresApi(Build.VERSION_CODES.S)
    fun onGenerateECKeyPair() {
        try {
            viewModel.generateECKeyPair()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onAgreementKey() {
        try {
            viewModel.generateSharedSecretKey()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onReset() {
        try {
            viewModel.reset()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun onSend() {
        try {
            val message = binding.messageEditText.text.toString()
            binding.userMessageTextView.text = message

            viewModel.encrypt(message).let { encryptedMsg ->
                if (encryptedMsg == null) {
                    //Error Log
                    binding.encryptionCBCTextView.text = resources.getString(R.string.error_message)
                    return
                }
                binding.encryptionCBCTextView.text = encryptedMsg
                viewModel.decrypt(encryptedMsg).let { decryptedMsg ->
                    if (decryptedMsg == null) {
                        //Error Log
                        binding.decryptionCBCTextView.text = resources.getString(R.string.error_message)
                        return
                    }
                    binding.decryptionCBCTextView.text = decryptedMsg
                }
            }
            binding.messageEditText.text = null
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}