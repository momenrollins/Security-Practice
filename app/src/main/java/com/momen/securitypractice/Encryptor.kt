package com.momen.securitypractice

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object Encryptor {

    /**
     * ---------- AES ----------
     */

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

    /**
     * ---------- RSA ----------
     */

    private lateinit var keyPair: KeyPair
    private const val RSA_ALG = "RSA"
    private const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"

    private fun generateRSAKeys() {
        if (::keyPair.isInitialized) {
            return
        }
        try {
            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(RSA_ALG)
            kpg.initialize(1024)
            keyPair = kpg.generateKeyPair()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun getRSAPublicKey(): ByteArray {
        generateRSAKeys()
        return keyPair.public.encoded
    }

    fun getRSAPrivateKey(): ByteArray {
        generateRSAKeys()
        return keyPair.private.encoded
    }

    @Throws(Exception::class)
    fun encryptRSA(publicKey: ByteArray, data: ByteArray): ByteArray {
        val key: PublicKey =
            KeyFactory.getInstance(RSA_ALG).generatePublic(X509EncodedKeySpec(publicKey))
        val cipher: Cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encrypted: ByteArray = cipher.doFinal(data)
        return encrypted
    }

    @Throws(Exception::class)
    fun decryptRSA(privateKey: ByteArray, encrypted: ByteArray): ByteArray {
        val key: PrivateKey =
            KeyFactory.getInstance(RSA_ALG).generatePrivate(PKCS8EncodedKeySpec(privateKey))
        val cipher: Cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key)
        val decrypted: ByteArray = cipher.doFinal(encrypted)
        return decrypted
    }

    /**
     * ---------- SHA-256 ----------
     */

    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

}