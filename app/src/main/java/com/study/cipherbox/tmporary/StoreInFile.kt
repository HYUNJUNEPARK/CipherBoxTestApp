package com.june.strongboxkey.tmporary

import android.content.Context
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.Key
import java.security.KeyStore

class StoreInFile(private val context: Context) {
//https://stackoverflow.com/questions/24231213/how-to-store-secretkey-in-keystore-and-retrieve-it
    private val KEYSTORE_FILE_FOR_SHARED_KEY = "keystore_shared_key"
    private val storePassword = "storePassword".toCharArray()
    private val keyPassword = "keyPassword".toCharArray()

    private val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        var fis: FileInputStream? = null
        try {
            fis = context.openFileInput(KEYSTORE_FILE_FOR_SHARED_KEY)
        }
        catch (e: Exception){
            load(null)
        }
        load(fis, storePassword)
    }

    fun storeKeystoreInFile(keyAlias: String, key: Key) {
        keyStore.setKeyEntry(keyAlias, key, keyPassword, null)
        val ksOut: FileOutputStream = context.openFileOutput(KEYSTORE_FILE_FOR_SHARED_KEY, Context.MODE_PRIVATE)
        keyStore.store(ksOut, storePassword)
        ksOut.close()
    }

    fun getKey(keyAlias: String): Key {
        var fis: FileInputStream? = null
        try {
            fis = context.openFileInput(KEYSTORE_FILE_FOR_SHARED_KEY)
        }
        catch (e: Exception){
            e.printStackTrace()
        }
        keyStore.load(fis, storePassword)
        fis?.close()
        return keyStore.getKey(keyAlias, keyPassword)
    }

    fun isKeyStoreFile(keyAlias: String): Boolean {
        val fis: FileInputStream?
        try {
            fis = context.openFileInput(KEYSTORE_FILE_FOR_SHARED_KEY)

        }
        catch (e: Exception){
            e.printStackTrace()
            return false
        }
        keyStore.load(fis, storePassword)
        fis.close()
        keyStore.getKey(keyAlias, storePassword).let { key ->
            return key != null
        }
    }

    fun readAllKeysInFile(): String {
        val fis: FileInputStream?
        val sb = StringBuffer()
        //throw IOException

        try {
            fis = context.openFileInput(KEYSTORE_FILE_FOR_SHARED_KEY)
            keyStore.load(fis, storePassword)
            fis?.close()
            for (key in keyStore.aliases()) {
                sb.append(key + "\n")
            }
            return sb.toString()
        }
        catch (e: Exception){
            e.printStackTrace()
            throw e
            /*
            NullPointerException	If b is null.
IndexOutOfBoundsException	If off is negative, len is negative, or len is greater than b.length - off
IOException	if an I/O error occurs.
            */
        }
    }
}

/* 예외처리

자바
체크예외
-복구가 가능한 예외들이기 때문에 반드시 예외를 처리하는 코드를 함께 작성
-catch문으로 예외를 잡든, throws로 예외를 자신을 호출한 클래스로 던지는 방법으로 해결해야 하는데, 이를 해결하지 않으면 컴파일 에러 가 발생

언체크예외
-RuntimeException을 상속
-프로그램이 동작하는 상황에서 발생하는 예외
->코틀린에서는 구분 안함


예외 복구 : 예외 상황을 파악하고, 문제를 해결해서 정상적인 상태로 돌려놓는 것


*/