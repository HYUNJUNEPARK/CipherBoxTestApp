package com.study.cipherbox.sdk.util;

import androidx.annotation.NonNull;

//affineX, affineY BigInteger 10진법 -> 16진법 변환 시 사용

/*
Example
if (_affineX[0].equals(0)) {
    val affineX = JavaUtil.byteArrayToString(_affineX, 1)
    val affineY = JavaUtil.byteArrayToString(_affineY, 1)
} else {
    val affineX = JavaUtil.byteArrayToString(_affineX, 0)
    val affineY = JavaUtil.byteArrayToString(_affineY, 0)
}
*/
public class JavaLibUtil {
    private static final char[] hexCode = "0123456789ABCDEF".toCharArray();

    public static String byteArrayToString(@NonNull byte[] bytes) {
        return byteArrayToString(bytes, 0, bytes.length);
    }
    public static String byteArrayToString(@NonNull byte[] bytes, int offset) throws ArrayIndexOutOfBoundsException {
        return byteArrayToString(bytes, offset, bytes.length - offset);
    }

    public static String byteArrayToString(@NonNull byte[] bytes, int offset, int length) throws ArrayIndexOutOfBoundsException {
        if (length < 0) {
            throw new IllegalArgumentException(String.format("The length must be positive.(length: %d)", length));
        }
        String result;
        if (length == 0) {
            result = "";
        } else {
            char[] chars = new char[length * 2];
            int charsOffset = 0;
            while (length-- > 0) {
                try {
                    byte b = bytes[offset++];
                    chars[charsOffset++] = hexCode[(b >> 4) & 0xF];
                    chars[charsOffset++] = hexCode[b & 0xF];
                } catch (ArrayIndexOutOfBoundsException e) {
                    throw new IllegalArgumentException(String.format("Index out of array bounds(Array size: %d, Index: %d)", bytes.length, offset));
                }
            }
            result = new String(chars);
        }
        return result;
    }

    public static byte[] hexStringToByteArray(@NonNull String hexString) throws IllegalArgumentException {
        hexString = hexString.replaceAll("\\s", "");

        int length = hexString.length();
        byte[] bytes = new byte[(length + 1) >> 1];
        if (length != 0) {
            char[] chars = hexString.toCharArray();

            int bytesOffset = 0;
            int charsOffset = 0;
            if ((length & 0x01) == 0x01) {
                bytes[bytesOffset++] = (byte) hexToInt(chars[charsOffset++]);
            }
            while (charsOffset < length) {
                int high = hexToInt(chars[charsOffset++]);
                int low = hexToInt(chars[charsOffset++]);
                bytes[bytesOffset++] = (byte) (high << 4 | low);
            }
        }
        return bytes;
    }

    private static int hexToInt(char ch) {
        if ('0' <= ch && ch <= '9') {
            return ch - '0';
        }
        if ('A' <= ch && ch <= 'F') {
            return ch - 'A' + 10;
        }
        if ('a' <= ch && ch <= 'f') {
            return ch - 'a' + 10;
        }
        throw new IllegalArgumentException(String.format("Non-hexadecimal digit found: %c", ch));
    }
}
