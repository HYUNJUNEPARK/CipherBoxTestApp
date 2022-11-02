package com.study.cipherbox.sdk.aos

import android.os.Build
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import com.study.cipherbox.sdk.JavaUtil
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.*

object ECKeyUtil {
    //TODO TEST RETURN publicKey
    fun stringToPublicKey(publicKey: String): ByteArray? {
//        try {
//            val _publicKey = Base64.decode(publicKey, Base64.NO_WRAP)
//            val publicKeySpec = X509EncodedKeySpec(_publicKey)
//
//            val publicKey = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(publicKeySpec)
//            return publicKey
//        } catch (e: Exception) {
//            e.printStackTrace()
//        }
//        return null


        try {
//            val _publicKey = Base64.decode(publicKey, Base64.NO_WRAP)
//            val publicKeySpec = X509EncodedKeySpec(_publicKey)
//
//            val publicKey = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(publicKeySpec)
//            return publicKey

            return Base64.decode(publicKey, Base64.NO_WRAP)



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

    //TODO 변경해야할 메서드
    fun _publicKeyToString(publicKey: PublicKey): String? {
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


    fun publicKeyToString(publicKey: PublicKey): String? {
        try {
            //publicKey -> affineX, affineY -> uncompressed form(string -> byteArray) -> Base64Encoding(byteArray -> string)
            val ecPublicKey = publicKey as ECPublicKey

            //TODO Decimal -> Hex
            val affineX = ecPublicKey.w.affineX
            val affineY = ecPublicKey.w.affineY
            val uncompressedForm_str = "04$affineX$affineY"
            val uncompressedForm_bytes = JavaUtil.hexStringToByteArray(uncompressedForm_str)
            return Base64.encodeToString(uncompressedForm_bytes, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    //공개키로 affineX, affineY 생성
    fun getAffineXY(userId: String, publicKey: String): HashMap<String, String>? {
        try {
            //String -> ByteArray
            val uncompressedForm_bytes = Base64.decode(publicKey, Base64.NO_WRAP)
            // bytes[0]: 0x04
            // bytes[1 .. 31]: affineX
            // bytes[32 .. 64]: affineY

            //TODO NEED Detail option
            val affineX = JavaUtil.byteArrayToString(uncompressedForm_bytes, 1, 32)
            val affineY = JavaUtil.byteArrayToString(uncompressedForm_bytes, 32, 32)

            return hashMapOf(
                "userId" to userId,
                "affineX" to affineX,
                "affineY" to affineY
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun deriveECPublicKeyFromECPoint(keyArray: ByteArray): PublicKey? {
        try {
            val affineX = JavaUtil.byteArrayToString(keyArray, 1, 32)
            val affineY = JavaUtil.byteArrayToString(keyArray, 32, 32)
            return __deriveECPublicKeyFromECPoint(affineX, affineY)
        } catch (e: Exception) {
            e.printStackTrace()
        }

        return null
    }

    fun _____deriveECPublicKeyFromECPoint(affineX: String, affineY: String): String? {
        try {
            val uncompressedForm_str = "04$affineX$affineY"
            val uncompressedForm_bytes = JavaUtil.hexStringToByteArray(uncompressedForm_str)

            //byteArray->String(Base64 encoding)
            return Base64.encodeToString(uncompressedForm_bytes, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }





    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    //affineX, affineY 로 공개키 생성
    //ecParameterSpec 를 사용하지 않아도 됨
    //_deriveECPublicKeyFromECPoint 개선 메서드
    private fun _deriveECPublicKeyFromECPoint(affineX: String, affineY: String): ECPublicKey? {
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

    fun __deriveECPublicKeyFromECPoint(affineX: String, affineY: String): PublicKey {
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