package com.momen.securitypractice

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object Encryptor {
    private const val AES_ALG = "AES"
    private const val AES_TRANSFORMATION = "AES/CBC/PKCS5Padding"

    fun generateAESKey(): ByteArray {
        val keyGen: KeyGenerator = KeyGenerator.getInstance("AES")

        keyGen.init(192)
        val secretKey = keyGen.generateKey()
        return secretKey.encoded
    }

    @Throws(Exception::class)
    fun encryptAES(key: ByteArray, data: ByteArray): Pair<ByteArray, ByteArray> {
        val iv = ByteArray(16).apply {
            SecureRandom().nextBytes(this)
        }
        val sKeySpec: SecretKeySpec = SecretKeySpec(key, AES_ALG)
        val cipher: Cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, IvParameterSpec(iv))
        val encrypted: ByteArray = cipher.doFinal(data)
        return encrypted to iv
    }

    @Throws(Exception::class)
    fun decryptAES(raw: ByteArray, encrypted: ByteArray, iv: ByteArray): ByteArray {
        val sKeySpec: SecretKeySpec = SecretKeySpec(raw, AES_ALG)
        val cipher: Cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, sKeySpec, IvParameterSpec(iv))
        val decrypted: ByteArray = cipher.doFinal(encrypted)
        return decrypted
    }
}