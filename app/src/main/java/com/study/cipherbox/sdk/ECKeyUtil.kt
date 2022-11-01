package com.study.cipherbox.sdk

import android.os.Build
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.*

object ECKeyUtil {
    fun stringToPublicKey(publicKey: String): PublicKey? {
        try {
            val _publicKey = Base64.decode(publicKey, Base64.NO_WRAP)
            val publicKeySpec = X509EncodedKeySpec(_publicKey)

            val publicKey = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(publicKeySpec)
            return publicKey
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    //Temp Method
    @RequiresApi(Build.VERSION_CODES.O)
    fun _stringToPublicKey(publicKey: String): PublicKey? {
        try {
            val _publicKey = publicKey
            val encoded: ByteArray = java.util.Base64.getDecoder().decode(_publicKey)
            // val _encoded: ByteArray = Base64.decode(_publicKey, Base64.NO_WRAP)

            val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            val templateForECPublicKey = byteArrayOf(
                0x30, 0x59,
                0x30, 0x13,
                0x06, 0x07, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01,
                0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07,
                0x03, 0x42, 0x00
            )
            val keySpec = X509EncodedKeySpec(templateForECPublicKey + encoded)
            return keyFactory.generatePublic(keySpec) as ECPublicKey
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun publicKeyToString(publicKey: PublicKey): String? {
        try {
            //publicKey -> byte
            val _publicKey: ByteArray = publicKey.encoded
            //byte -> string
            return Base64.encodeToString(_publicKey, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    //공개키로 affineX, affineY 생성
    fun extractAffineXY(userId: String, publicKey: PublicKey): HashMap<String, String> {
        (publicKey as ECPublicKey).let { ecPublicKey ->
            return hashMapOf(
                "userId" to userId,
                "affineX" to ecPublicKey.w.affineX.toString(),
                "affineY" to ecPublicKey.w.affineY.toString()
            )
        }
    }

    //affineX, affineY 로 공개키 생성
    //ecParameterSpec 를 사용하지 않아도 됨
    //_deriveECPublicKeyFromECPoint 개선 메서드
    private fun deriveECPublicKeyFromECPoint(affineX: String, affineY: String): ECPublicKey? {
        val affineX = BigInteger(affineX, 16)
        val affineY = BigInteger(affineY, 16)
        val point = ECPoint(affineX, affineY)
        try {
            val algorithmParameters: AlgorithmParameters = AlgorithmParameters.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            algorithmParameters.init(ECGenParameterSpec("secp256r1"))
            val parameterSpec: ECParameterSpec =
                algorithmParameters.getParameterSpec(ECParameterSpec::class.java)
            val publicKeySpec: KeySpec = ECPublicKeySpec(point, parameterSpec)
            return KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(publicKeySpec) as ECPublicKey
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: InvalidParameterSpecException) {
            e.printStackTrace()
        } catch (e: InvalidKeySpecException) {
            e.printStackTrace()
        }
        return null
    }

    fun _deriveECPublicKeyFromECPoint(affineX: String, affineY: String): PublicKey {
        val affineX = BigInteger(affineX)
        val affineY = BigInteger(affineY)
        val ecPoint = ECPoint(affineX, affineY)
        val keySpec = ECPublicKeySpec(
            ecPoint,
            ecParameterSpec
        )
        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
        return keyFactory.generatePublic(keySpec)
    }

    //Reference : Elliptic Curve Domain Parameters (https://www.secg.org/sec2-v2.pdf Page9 of 33-34)
    private val ecParameterSpec= with(this) {
        val p = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        val a = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
        val b = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
        val gX = BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
        val gY = BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
        val n = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        val h = 1
        val ecField = ECFieldFp(p)
        val curve = EllipticCurve(ecField, a, b)
        val g = ECPoint(gX, gY)
        ECParameterSpec(curve, g, n, h)
    }
}