package com.study.cipherbox.strongbox

import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.*

class ECKeyUtil {
    /**
     * 서버에 업로드할 Public Key 를 x, y 좌표로 분해하는 메서드입니다.
     *
     * @param publicKey 서버에 업로드할 Public Key 를 파라미터로 전달합니다.
     * @return x,y 좌표를 해시맵에 담아 반환합니다.
     */
    fun disassemble(publicKey: PublicKey): HashMap<String, String> {
        val ecPublicKey = publicKey as ECPublicKey
        return hashMapOf(
            "affineX" to ecPublicKey.w.affineX.toString(),
            "affineY" to ecPublicKey.w.affineY.toString()
        )
    }

    /**
     * 서버에서 받은 x, y 좌표를 Public Key 로 합성하는 메서드입니다.
     *
     * @param affineX 합성하려는 Public Key 의 x 좌표입니다.
     * @param affineY 합성하려는 Public Key 의 y 좌표입니다.
     * @return 합성한 Public Key 를 반환합니다.
     */
    fun assemble(affineX: String, affineY: String): PublicKey {
        val affineX = BigInteger(affineX)
        val affineY = BigInteger(affineY)
        val ecPoint = ECPoint(affineX, affineY)
        val keySpec = ECPublicKeySpec(ecPoint, ecParameterSpec())
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(keySpec)
    }

    //Reference : Elliptic Curve Domain Parameters (https://www.secg.org/sec2-v2.pdf Page9 of 33-34)
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