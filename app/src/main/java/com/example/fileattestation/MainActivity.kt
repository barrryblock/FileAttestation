package com.example.fileattestation

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Base64
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.android.volley.Request
import com.android.volley.RequestQueue
import com.android.volley.Response
import com.android.volley.toolbox.JsonObjectRequest
import com.android.volley.toolbox.Volley
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import javax.crypto.KeyGenerator
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.security.spec.RSAKeyGenParameterSpec

class MainActivity : AppCompatActivity() {

    private lateinit var buttonUpload: Button
    private lateinit var buttonViewFiles: Button
    private lateinit var queue: RequestQueue


    companion object {
        const val FILE_SELECT_CODE = 0
        const val KEY_ALIAS = "myKeyAlias"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        buttonUpload = findViewById(R.id.buttonUpload)
        buttonViewFiles = findViewById(R.id.buttonViewFiles)
        queue = Volley.newRequestQueue(this)

        val selectFileButton: Button = findViewById(R.id.selectFileButton)
        selectFileButton.setOnClickListener {
            showFileChooser()
        }
        buttonViewFiles.setOnClickListener {
            val intent = Intent(this, FileListActivity::class.java)
            startActivity(intent)
        }

        createKey()
    }

    private fun showFileChooser() {
        val intent = Intent(Intent.ACTION_GET_CONTENT)
        intent.type = "*/*"
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        try {
            startActivityForResult(Intent.createChooser(intent, "Select a File"), FILE_SELECT_CODE)
        } catch (ex: android.content.ActivityNotFoundException) {
            Toast.makeText(this, "Please install a File Manager.", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == FILE_SELECT_CODE && resultCode == RESULT_OK) {
            val uri: Uri? = data?.data
            uri?.let {
                try {
                    val fileContent = readFileContent(it)
                    val signedData = signData(fileContent)
                    sendSignedDataToServer(fileContent, signedData)
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }
    }

    private fun readFileContent(uri: Uri): ByteArray {
        val inputStream: InputStream? = contentResolver.openInputStream(uri)
        val byteArrayOutputStream = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        var length: Int
        if (inputStream != null) {
            while (inputStream.read(buffer).also { length = it } != -1) {
                byteArrayOutputStream.write(buffer, 0, length)
            }
        }
        return byteArrayOutputStream.toByteArray()
    }

    private fun createKey() {
        try {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .build()
            )
            keyGenerator.generateKey()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun signData(data: ByteArray): ByteArray {
        val signature: Signature = Signature.getInstance("SHA256withRSA")
        val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val privateKey: PrivateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    private fun sendSignedDataToServer(fileContent: ByteArray, signedData: ByteArray) {
        val queue: RequestQueue = Volley.newRequestQueue(this)
        val url = "https://10.0.2.2:5000/verify"

        val params = HashMap<String, String>()
        params["file_content"] = Base64.encodeToString(fileContent, Base64.DEFAULT)
        params["signed_data"] = Base64.encodeToString(signedData, Base64.DEFAULT)

        val jsonRequest = JSONObject(params as Map<*, *>)

        val jsonObjectRequest = JsonObjectRequest(
            Request.Method.POST, url, jsonRequest,
            { response ->
                // Handle response
                Toast.makeText(this, response.toString(), Toast.LENGTH_SHORT).show()
            },
            { error ->
                // Handle error
                Toast.makeText(this, error.toString(), Toast.LENGTH_SHORT).show()
            })

        queue.add(jsonObjectRequest)
    }
}