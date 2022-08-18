package com.june.strongboxkey.app

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.june.strongboxkey.R
import com.june.strongboxkey.databinding.ActivityMainBinding
import com.june.strongboxkey.strongbox.StrongBox
import java.security.PublicKey

class MainActivity : AppCompatActivity() {
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }

    private val strongBox = StrongBox.getInstance(this)
    private var publicKey: PublicKey? = null
    private lateinit var spm: SharedPreferenceManager
    private var keyId: String? = null
    private var random: String? = null
    private val TAG = "testLog"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)

        spm = SharedPreferenceManager.getInstance(this)!!
        initKeyState()
    }

    fun keyGenButtonClicked(v: View) {
        strongBox.generateECKeyPair()
        publicKey = strongBox.getECPublicKey()
        random = strongBox.generateRandom(32)

        if (publicKey != null && random != null) {
            binding.ecKeyPairStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
            binding.randomTextView.text = random
            spm.putString("random", random)
        } else {
            Toast.makeText(this, "키 쌍 생성 or 랜덤 생성에 문제가 발생했습니다.", Toast.LENGTH_SHORT).show()
        }
    }

    private fun initKeyState() {
        try {
            publicKey = strongBox.getECPublicKey()
            binding.ecKeyPairStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
        } catch (e: Exception) {
            binding.ecKeyPairStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
        }
        val isRandom = (spm.getString("random", "null") != "null")
        if (isRandom) {
            random = spm.getString("random", "null")
            binding.randomTextView.text = random
        } else {
            binding.randomTextView.text = null
        }
    }

    fun sharedSecretKeyGenButtonClicked(v: View) {
        if (publicKey == null || random == null) return

        strongBox.generateSharedSecretKey(publicKey!!, random!!).let { keyAlias ->
            keyId = keyAlias
            binding.sharedSecretKeyAliasTextView.text = keyAlias
        }


//        if (publicKey == null || random == null) {
//            Toast.makeText(this, "퍼블릭키 또는 랜덤 없음", Toast.LENGTH_SHORT).show()
//            return
//        }
//
//        strongBox.generateSharedSecretKey(publicKey!!, random!!).let { result ->
//            keyId = result
//        }
//        Log.d("testLog", "ssk Key Id : $keyId")
//        if (keyId != null) {
//            binding.sharedSecretKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
//        }
    }


    fun ecKeyPairDeleteButtonClicked(v: View) {
        strongBox.deleteECKeyPair().let { result ->
            if (result) {
                //키페어가 삭제 되면 해당 랜덤도 같이 삭제
                spm.putString("random", "null")
                initKeyState()
            } else {
                Toast.makeText(this, "키 쌍 삭제 싪패", Toast.LENGTH_SHORT).show()
            }
        }
    }


    fun testButtonClicked(v: View) {
        if (keyId == null) return 
        
        if (strongBox.isSharedSecretKey(keyId!!)) {
            Toast.makeText(this, "ssk 있음", Toast.LENGTH_SHORT).show()
        }

    }

    fun sharedSecretKeyDeleteButtonClicked(v: View) {
        if (keyId == null) return

        strongBox.deleteSharedSecretKey(keyId!!).let { result ->
            if (result) {
                Toast.makeText(this, "ssk 키 삭제", Toast.LENGTH_SHORT).show()
            }
            else {
                Toast.makeText(this, "ssk 키 삭제 실패", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun messageSendButtonClicked(v: View) {
        if (keyId == null) return

        val userInput = binding.messageEditText.text.toString()
        binding.userMessageTextView.text = userInput
        val encryption = strongBox.encrypt(userInput, keyId!!)
        binding.encryptionCBCTextView.text = encryption
        val decryption = strongBox.decrypt(encryption, keyId!!)
        binding.decryptionCBCTextView.text = decryption

        binding.messageEditText.text = null
    }

    fun getAllKeyIds(v: View) {
        strongBox.getAllSecretKeyIds()
    }

}