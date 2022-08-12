package com.june.strongboxkey.strongbox

import android.util.Log
import android.view.View
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.*

class AppUtil {
    //TODO 앱에서 구현해야하는 함수

//    fun generatePublicKeyByECPoint(affineX: BigInteger, affineY: BigInteger): PublicKey {
//        val ecPoint = ECPoint(affineX, affineY)
//        val keySpec = ECPublicKeySpec(ecPoint, ecParameterSpec())
//        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
//        return keyFactory.generatePublic(keySpec)
//    }



//    private fun updatePublicKeyAffineXYToServer(userId: String, publicKey: PublicKey) {
//        val ecPublicKey = publicKey as ECPublicKey
//        val user = hashMapOf(
//            FIRE_STORE_FIELD_USER_ID to userId,
//            FIRE_STORE_FIELD_AFFINE_X to ecPublicKey.w.affineX.toString(),
//            FIRE_STORE_FIELD_AFFINE_Y to ecPublicKey.w.affineY.toString()
//        )
//        db!!.collection(FIRE_STORE_DOCUMENT_PUBLIC_KEY)
//            .add(user)
//            .addOnSuccessListener {
//                showToast("퍼블릭키 업로드 성공")
//            }
//            .addOnFailureListener { e ->
//                binding.progressBarLayout.visibility = View.GONE
//                Log.e(TAG, "Error adding document", e)
//                showToast("퍼블릭키 업로드 실패")
//                finish()
//            }
//    }


    //TODO public key by XY
    fun createPublicKeyByECPoint(affineX: BigInteger, affineY: BigInteger): PublicKey {
        val ecPoint = ECPoint(affineX, affineY)
        val keySpec = ECPublicKeySpec(ecPoint, ecParameterSpec())
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(keySpec)
    }

    //
    //reference : Elliptic Curve Domain Parameters (https://www.secg.org/sec2-v2.pdf Page9 of 33-34)
    private fun ecParameterSpec(): ECParameterSpec {
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
        return ECParameterSpec(curve, g, n, h)
    }
}