package com.study.cipherbox.app

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.study.cipherbox.databinding.ActivityMainBinding
import com.study.cipherbox.sdk.CipherBox

class MainActivity : AppCompatActivity() {
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }
    private var defaultKeypair: KeyPairModel? = null //sender
    private var usimKeypair: KeyPairModel? = null //recipient
    private var sharedSecretKey: ByteArray? = null

    private lateinit var cipherBox: CipherBox

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)

        try {
            cipherBox = CipherBox.getInstance()!!
            binding.mainActivity = this
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }



    fun generateKeypair(v: View) {
        try {
            defaultKeypair = cipherBox.generateECKeypair()
            usimKeypair = cipherBox.generateECKeypair()
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, "예기치 못한 에러가 발생했습니다.", Toast.LENGTH_SHORT).show()
            return
        }
        showKeypairState()
    }

    fun agreementKeypair(v: View) {
        if (defaultKeypair == null || usimKeypair == null) {
            return
        }

        try {
            sharedSecretKey = cipherBox.agreementKey(
                privateKey = defaultKeypair!!.privateKey,
                publicKey = usimKeypair!!.publicKey
            )
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, "예기치 못한 에러가 발생했습니다.", Toast.LENGTH_SHORT).show()
            return
        }
        binding.messageSendButton.isEnabled = true
    }

    fun sendMessage(v: View) {
        if (defaultKeypair == null || usimKeypair == null || sharedSecretKey == null) {
            Toast.makeText(this@MainActivity, "암복호화 키 필요", Toast.LENGTH_SHORT).show()
            return
        }
        val message = binding.messageEditText.text.toString()
        val encryptedMessage = cipherBox.encrypt_ex_ver(
            message = message,
            key = sharedSecretKey!!
        )
        val decryptedMessage = cipherBox.decrypt_ex_ver(
            message = encryptedMessage,
            key = sharedSecretKey!!
        )
        binding.userMessageTextView.text = message
        binding.encryptionCBCTextView.text = encryptedMessage
        binding.decryptionCBCTextView.text = decryptedMessage

        binding.messageEditText.text = null
    }

    fun reset(v: View) {
        defaultKeypair = null
        usimKeypair = null
        sharedSecretKey =  null

        showKeypairState()
        binding.messageSendButton.isEnabled = false
    }

    private fun showKeypairState() {
        if (defaultKeypair?.privateKey != null) {
            binding.privateKeyAText.visibility = View.VISIBLE
        } else {
            binding.privateKeyAText.visibility = View.INVISIBLE
        }
        if (defaultKeypair?.publicKey != null) {
            binding.publicKeyAText.visibility = View.VISIBLE
        } else {
            binding.publicKeyAText.visibility = View.INVISIBLE
        }
        if (usimKeypair?.privateKey != null) {
            binding.privateKeyBText.visibility = View.VISIBLE
        } else {
            binding.privateKeyBText.visibility = View.INVISIBLE
        }
        if (usimKeypair?.publicKey != null) {
            binding.publicKeyBText.visibility = View.VISIBLE
        } else {
            binding.publicKeyBText.visibility = View.INVISIBLE
        }
    }



//    private lateinit var binding: ActivityMainBinding
//
//    private val strongBox = StrongBox.getInstance(this)
//    private var publicKey: PublicKey? = null
//    private lateinit var spm: SharedPreferenceManager
//    private var keyId: String? = null
//    private var random: String? = null
//
//    override fun onCreate(savedInstanceState: Bundle?) {
//        super.onCreate(savedInstanceState)
//        binding = DataBindingUtil.setContentView(this, R.layout.activity_main)
//
//        spm = SharedPreferenceManager.getInstance(this)!!
//        initKeyState()
//    }
//
//    fun keyGenButtonClicked(v: View) {
//        strongBox.generateECKeyPair()
//        publicKey = strongBox.getECPublicKey()
//        random = strongBox.generateRandom(32)
//
//        if (publicKey != null && random != null) {
//            binding.ecKeyPairStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
//            binding.randomTextView.text = random
//            spm.putString("random", random)
//        } else {
//            Toast.makeText(this, "키 쌍 생성 or 랜덤 생성에 문제가 발생했습니다.", Toast.LENGTH_SHORT).show()
//        }
//    }
//
//    private fun initKeyState() {
//        try {
//            publicKey = strongBox.getECPublicKey()
//            binding.ecKeyPairStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
//        } catch (e: Exception) {
//            binding.ecKeyPairStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
//        }
//        val isRandom = (spm.getString("random", "null") != "null")
//        if (isRandom) {
//            random = spm.getString("random", "null")
//            binding.randomTextView.text = random
//        } else {
//            binding.randomTextView.text = null
//        }
//    }
//
//    fun sharedSecretKeyGenButtonClicked(v: View) {
//        if (publicKey == null || random == null) return
//
//        strongBox.generateSharedSecretKey(publicKey!!, random!!).let { keyAlias ->
//            keyId = keyAlias
//            binding.sharedSecretKeyAliasTextView.text = keyAlias
//        }
//
//
////        if (publicKey == null || random == null) {
////            Toast.makeText(this, "퍼블릭키 또는 랜덤 없음", Toast.LENGTH_SHORT).show()
////            return
////        }
////
////        strongBox.generateSharedSecretKey(publicKey!!, random!!).let { result ->
////            keyId = result
////        }
////        Log.d("testLog", "ssk Key Id : $keyId")
////        if (keyId != null) {
////            binding.sharedSecretKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
////        }
//    }
//
//
//    fun ecKeyPairDeleteButtonClicked(v: View) {
//        strongBox.deleteECKeyPair().let { result ->
//            if (result) {
//                //키페어가 삭제 되면 해당 랜덤도 같이 삭제
//                spm.putString("random", "null")
//                initKeyState()
//            } else {
//                Toast.makeText(this, "키 쌍 삭제 싪패", Toast.LENGTH_SHORT).show()
//            }
//        }
//    }
//
//
//    fun testButtonClicked(v: View) {
//        if (keyId == null) return
//
//        if (strongBox.isSharedSecretKey(keyId!!)) {
//            Toast.makeText(this, "ssk 있음", Toast.LENGTH_SHORT).show()
//        }
//
//    }
//
//    fun sharedSecretKeyDeleteButtonClicked(v: View) {
//        if (keyId == null) return
//
//        strongBox.deleteSharedSecretKey(keyId!!).let { result ->
//            if (result) {
//                Toast.makeText(this, "ssk 키 삭제", Toast.LENGTH_SHORT).show()
//            }
//            else {
//                Toast.makeText(this, "ssk 키 삭제 실패", Toast.LENGTH_SHORT).show()
//            }
//        }
//    }
//
//    fun messageSendButtonClicked(v: View) {
//        if (keyId == null) return
//
//        val userInput = binding.messageEditText.text.toString()
//        binding.userMessageTextView.text = userInput
//        val encryption = strongBox.encrypt(userInput, keyId!!)
//        binding.encryptionCBCTextView.text = encryption
//        val decryption = strongBox.decrypt(encryption, keyId!!)
//        binding.decryptionCBCTextView.text = decryption
//
//        binding.messageEditText.text = null
//    }
//
//    fun getAllKeyIds(v: View) {
//        strongBox.getAllSecretKeyIds()
//    }

}