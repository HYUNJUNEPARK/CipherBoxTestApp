package com.study.cipher.aesCipher

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import androidx.databinding.DataBindingUtil
import com.study.cipher.AesCipher
import com.study.cipher.R
import com.study.cipher.databinding.ActivityAesCipherBinding

class AesCipherActivity : AppCompatActivity() {
    private lateinit var binding: ActivityAesCipherBinding
    private lateinit var aesCipher: AesCipher

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = DataBindingUtil.setContentView(this, R.layout.activity_aes_cipher)
        binding.aesCipherActivity = this

        aesCipher = AesCipher.getInstance()


        aesCipher.encrypt("asjdkfl;jaksl;fjkals;djfklasdjfklsdjfklasjfk;").let {
            Log.d("testLog", "encrypt: $it")
            aesCipher.decrypt(it!!).let {
                Log.d("testLog", "decrypt: $it")
            }
        }

    }
}