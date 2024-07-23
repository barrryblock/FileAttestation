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
import java.io.IOException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import javax.crypto.KeyGenerator
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.security.spec.RSAKeyGenParameterSpec
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.IntegrityTokenResponse
import com.google.android.gms.tasks.OnCompleteListener
import com.google.android.gms.tasks.Task
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType


class MainActivity : AppCompatActivity() {

    private lateinit var buttonUpload: Button
    private lateinit var buttonViewFiles: Button
    private lateinit var queue: RequestQueue
    private val API_KEY = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDixqf01yxtEpg/\\nMIF+ebSvwH1w/E+SP5h3iUCXtoviPwBtE19CNUb9HVN3ibH4pezGxjb9k2tSqhCp\\nz6UgE/9BtDcGvpfgqkQAJWEjlKHtS66HrO01ufkLBCltYU6AkQhEWdOt0Q1QNPNS\\n7H9jMnB1WpFGadzLuKvKsAk2WO45shCdImMdFU1Z4uX+VBwsVuyjcsmkdvFXatWA\\nXPsIrcXaq9fyvkeJhknPpAZ3TfAwr+seurxD1Dn4ZRUIcB5jcAtUwf8Q9/rKnd8t\\nWBo320xUkBHjr7NP8vr+CGJT+G37/eQKI6ukxTWG3BLizert4LrWCFgy5VEgqPsy\\n4oRVsdlxAgMBAAECggEAS+uO6iipTmDFyI3gJGvxYk9yj4NgzkjtLcOs9L2f6iAG\\nb/3my78TY4TQXzohc2l1MfzFBzK14OhfiMIj+W/IaoI/U8o2BXhrKJNbCHLnnQ5T\\nwUdS6MQ4jIgZqG1Fv0QOvPdHpy7QIrR/a5kScq69uIQYE7c4PJm4JbS2eNPf+T8y\\n/Dp3muc0v42Vx7zm2DVqKgierPB5iGwpwlSw5Ah+Nk7McQEg7j2w+NsjAD6lZ2XD\\nZMj1NQEvn0i8wKvKuUeC5RBM27XyrCzE442wtz9a7V0NqbPAnLa0q3mGnap6t3Yt\\nGdYYUasF4bo1UVYRhUfdJ1cLuzZ2GiTgCPCCS0bvCwKBgQDynM6ttnL0zy4MoT9C\\nV7odU0lLAGUtu3fIboVK4uSHEowfQvO2DohjqwmJRbrDWD95aD/6scXtL3TxmXlI\\nPMe1Bhr2MyEN6Aqh4kiDUFSyh9viSte9cmTV8cZ24J4racOeLvlxMFuJQkI/YUSm\\nL2vuYS8ibi9gJdAV6SQbVGb3uwKBgQDvSiOIoHTtPZhYpqhAMp4xpqWxATlsdnJJ\\noFNvebz3vPOmFx8e4TCPAaOn5k2t52DITkNtTKaGI5B9fk0ZQ5jbjFUpaIPZ4eYr\\nHd1BurPgSHE/K7Vs791FptrrjCtMTA7ZmF0jtf0DzDvLPR9oO9RTHo5ZCxheRCa2\\nd4Q7MAgSwwKBgQCFTHKiLyRqLYr3lYDUSq8Pfbs/YjA1OFNP5KmHw7IcJKyoYHjX\\nBpUZbdgHfDBpNAtsAUNl0lcVQoXWWKSyc/KmG3yk2OLIaT2uRE3jGDfw/4RoiQaQ\\nKFIO2pBYsIE3CR1ZxCV5c0BX4ffUKvU0+ckraGolWLTe9uelojscaPtKEQKBgQDN\\n4JnF+VfgrjgfPfRQl7xnt5ujOQxw90/JbPmcVb9x3s46vnX2GYWv5Jcr5Ag9cW9h\\np4R3y5USoBK3Bi3LaM9hRdIXuGaI1cU0n5M39CzC8VEOKssDmTRlsvNz6btu/5lf\\nOaoZCYFQ/S0M5d/ZzHAXu5h5oAQtRrGQGDBaxC6OBQKBgEg8rxsYALCoZe653AuM\\ndQbUyVLhGu1KLTU6y/QG9DyMoSJGvTPNIiXS3Kj0QzVCYxYYksqBDRCEwfMMemQN\\nkE6FLS11RdBI3v+fOSbFV82tdu5sbbfHj1jY20/D7OGf2g+srnH/MGtff2EcjWjh\\n5yXvushu5fWoMXWIBAB+Axiv\\n-----END PRIVATE KEY-----\\n"

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

        performDeviceAttestation()
        createKey()
    }

    private fun performDeviceAttestation() {
        val integrityManager: IntegrityManager = IntegrityManagerFactory.create(this)

        val nonce = generateNonce()
        val request = IntegrityTokenRequest.builder()
            .setNonce(Base64.encodeToString(nonce, Base64.DEFAULT))
            .build()

        integrityManager.requestIntegrityToken(request)
            .addOnCompleteListener { task ->
                if (task.isSuccessful) {
                    val tokenResponse = task.result
                    val integrityToken = tokenResponse.token()

                    // Send the integrity token to your server for verification
//                    sendTokenToServer(integrityToken)
                } else {
                    task.exception?.printStackTrace()
                    // Handle failure case
                }
            }
    }



//    private fun sendTokenToServer(integrityToken: String) {
//        val client = OkHttpClient()
//        val json = """
//        {
//            "token": "$integrityToken"
//        }
//    """.trimIndent()
//        val body = RequestBody.create("application/json; charset=utf-8".toMediaType(), json)
//        val request = Request.Builder()
//            .url("https://fileveri-flask.azurewebsites.net/verify")
//            .post(body)
//            .build()
//
//        client.newCall(request).enqueue(object : Callback {
//            override fun onFailure(call: Call, e: IOException) {
//                e.printStackTrace()
//            }
//
//            override fun onResponse(call: Call, response: Response) {
//                response.use {
//                    if (!response.isSuccessful) throw IOException("Unexpected code $response")
//
//                    val responseData = response.body()?.string()
//                    println(responseData)
//                }
//            }
//        })
//    }
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


    private fun generateNonce(): ByteArray {
        val nonceData = "Sample nonce".toByteArray()
        // You should generate a cryptographically secure nonce for production use
        return nonceData
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