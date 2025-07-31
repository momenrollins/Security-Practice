package com.momen.securitypractice

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.momen.securitypractice.databinding.FragmentSecondBinding

class SecondFragment : Fragment() {

    private var _binding: FragmentSecondBinding? = null

    private val binding get() = _binding!!
    var displayedText = ""
    val iv: ByteArray = ByteArray(16)

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        _binding = FragmentSecondBinding.inflate(inflater, container, false)
        return binding.root

    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.btnResultBase64.setOnClickListener { setViewData(DisplayType.BASE64) }
        binding.btnResultHex.setOnClickListener { setViewData(DisplayType.HEX) }
    }

    fun setViewData(type: DisplayType) {
        val textToEncrypt = binding.etTextToEncrypt.text.toString()
        if (textToEncrypt.isEmpty()) return

        displayedText = ""
        val publicRSAKey = Encryptor.getRSAPublicKey()
        displayedText += "Public RSA Key: " + format(publicRSAKey, type)
        val privateRSAKey = Encryptor.getRSAPrivateKey()
        displayedText += "\n●●●●●●●●●●●●●●●●●●●●\nPrivate RSA Key: " + format(privateRSAKey, type)

        val aesKey = Encryptor.generateAESKey()
        displayedText += "\n●●●●●●●●●●●●●●●●●●●●\nAES Key: " + format(aesKey, type)
        val encryptedAESKey = Encryptor.encryptRSA(publicRSAKey, aesKey)
        displayedText += "\n●●●●●●●●●●●●●●●●●●●●\nEncrypted AES Key: " + format(encryptedAESKey, type)

        val encryptedText = Encryptor.encryptAES(aesKey, textToEncrypt.toByteArray(), iv)
        displayedText += "\n●●●●●●●●●●●●●●●●●●●●\nEncrypted Text: " + format(encryptedText, type)
        val decryptedAESKey = Encryptor.decryptRSA(privateRSAKey, encryptedAESKey)
        displayedText += "\n●●●●●●●●●●●●●●●●●●●●\nDecrypted AES Key: " + format(decryptedAESKey, type)
        val decryptedText = Encryptor.decryptAES(decryptedAESKey, encryptedText, iv)
        displayedText += "\n●●●●●●●●●●●●●●●●●●●●\nDecrypted Text ➡️ " + String(decryptedText)

        binding.tvResult.text = displayedText
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    enum class DisplayType { BASE64, HEX }

    fun format(data: ByteArray, type: DisplayType): String {
        return when (type) {
            DisplayType.BASE64 -> data.toBase64String()
            DisplayType.HEX -> data.toHexString()
        }
    }


}