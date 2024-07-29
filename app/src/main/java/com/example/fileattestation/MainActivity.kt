package com.example.fileattestation

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Button
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.android.volley.DefaultRetryPolicy
import com.android.volley.RequestQueue
import com.android.volley.RetryPolicy
import com.android.volley.toolbox.JsonObjectRequest
import com.android.volley.toolbox.StringRequest
import com.android.volley.toolbox.Volley
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStreamWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.util.Calendar
import java.util.GregorianCalendar
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.security.auth.x500.X500Principal

interface ChallengeCallback {
    fun onSuccess(challenge: String)
    fun onFailure(errorMessage: String)
}

class MainActivity : AppCompatActivity(), ChallengeCallback {

    private lateinit var buttonUpload: Button
    private lateinit var buttonViewFiles: Button
    private lateinit var queue: RequestQueue
    private lateinit var keyPair: KeyPair
    private var challengeString: String? = null
    //private val API_KEY = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDixqf01yxtEpg/\\nMIF+ebSvwH1w/E+SP5h3iUCXtoviPwBtE19CNUb9HVN3ibH4pezGxjb9k2tSqhCp\\nz6UgE/9BtDcGvpfgqkQAJWEjlKHtS66HrO01ufkLBCltYU6AkQhEWdOt0Q1QNPNS\\n7H9jMnB1WpFGadzLuKvKsAk2WO45shCdImMdFU1Z4uX+VBwsVuyjcsmkdvFXatWA\\nXPsIrcXaq9fyvkeJhknPpAZ3TfAwr+seurxD1Dn4ZRUIcB5jcAtUwf8Q9/rKnd8t\\nWBo320xUkBHjr7NP8vr+CGJT+G37/eQKI6ukxTWG3BLizert4LrWCFgy5VEgqPsy\\n4oRVsdlxAgMBAAECggEAS+uO6iipTmDFyI3gJGvxYk9yj4NgzkjtLcOs9L2f6iAG\\nb/3my78TY4TQXzohc2l1MfzFBzK14OhfiMIj+W/IaoI/U8o2BXhrKJNbCHLnnQ5T\\nwUdS6MQ4jIgZqG1Fv0QOvPdHpy7QIrR/a5kScq69uIQYE7c4PJm4JbS2eNPf+T8y\\n/Dp3muc0v42Vx7zm2DVqKgierPB5iGwpwlSw5Ah+Nk7McQEg7j2w+NsjAD6lZ2XD\\nZMj1NQEvn0i8wKvKuUeC5RBM27XyrCzE442wtz9a7V0NqbPAnLa0q3mGnap6t3Yt\\nGdYYUasF4bo1UVYRhUfdJ1cLuzZ2GiTgCPCCS0bvCwKBgQDynM6ttnL0zy4MoT9C\\nV7odU0lLAGUtu3fIboVK4uSHEowfQvO2DohjqwmJRbrDWD95aD/6scXtL3TxmXlI\\nPMe1Bhr2MyEN6Aqh4kiDUFSyh9viSte9cmTV8cZ24J4racOeLvlxMFuJQkI/YUSm\\nL2vuYS8ibi9gJdAV6SQbVGb3uwKBgQDvSiOIoHTtPZhYpqhAMp4xpqWxATlsdnJJ\\noFNvebz3vPOmFx8e4TCPAaOn5k2t52DITkNtTKaGI5B9fk0ZQ5jbjFUpaIPZ4eYr\\nHd1BurPgSHE/K7Vs791FptrrjCtMTA7ZmF0jtf0DzDvLPR9oO9RTHo5ZCxheRCa2\\nd4Q7MAgSwwKBgQCFTHKiLyRqLYr3lYDUSq8Pfbs/YjA1OFNP5KmHw7IcJKyoYHjX\\nBpUZbdgHfDBpNAtsAUNl0lcVQoXWWKSyc/KmG3yk2OLIaT2uRE3jGDfw/4RoiQaQ\\nKFIO2pBYsIE3CR1ZxCV5c0BX4ffUKvU0+ckraGolWLTe9uelojscaPtKEQKBgQDN\\n4JnF+VfgrjgfPfRQl7xnt5ujOQxw90/JbPmcVb9x3s46vnX2GYWv5Jcr5Ag9cW9h\\np4R3y5USoBK3Bi3LaM9hRdIXuGaI1cU0n5M39CzC8VEOKssDmTRlsvNz6btu/5lf\\nOaoZCYFQ/S0M5d/ZzHAXu5h5oAQtRrGQGDBaxC6OBQKBgEg8rxsYALCoZe653AuM\\ndQbUyVLhGu1KLTU6y/QG9DyMoSJGvTPNIiXS3Kj0QzVCYxYYksqBDRCEwfMMemQN\\nkE6FLS11RdBI3v+fOSbFV82tdu5sbbfHj1jY20/D7OGf2g+srnH/MGtff2EcjWjh\\n5yXvushu5fWoMXWIBAB+Axiv\\n-----END PRIVATE KEY-----\\n"
    private lateinit var filePickerLauncher: ActivityResultLauncher<Intent>
    private var fileContent: ByteArray? = null
    private var signedData: ByteArray? = null
    companion object {
        //const val FILE_SELECT_CODE = 0
        const val KEY_ALIAS = "com.android.security.publickeycryptography.key"
    }
    private fun showFileChooser() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        filePickerLauncher.launch(intent)
    }
    private fun readFileContent(uri: Uri): ByteArray {
        contentResolver.openInputStream(uri)?.use { inputStream ->
            val byteArrayOutputStream = ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            var length: Int
            while (inputStream.read(buffer).also { length = it } != -1) {
                byteArrayOutputStream.write(buffer, 0, length)
            }
            return byteArrayOutputStream.toByteArray()
        } ?: throw IOException("Unable to open InputStream for URI: $uri")
    }
    private fun generateKeyPair(): KeyPair {
        //We create the start and expiry date for the key
        val startDate = GregorianCalendar()
        val endDate = GregorianCalendar()
        endDate.add(Calendar.YEAR, 1)

        //We are creating a RSA key pair and store it in the Android Keystore
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")

        //We are creating the key pair with sign and verify purposes
        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).run {
            //setCertificateSerialNumber(BigInteger.valueOf(777))       //Serial number used for the self-signed certificate of the generated key pair, default is 1
            //setCertificateSubject(X500Principal("CN=$KEY_ALIAS"))     //Subject used for the self-signed certificate of the generated key pair, default is CN=fake
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)                         //Set of digests algorithms with which the key can be used
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1) //Set of padding schemes with which the key can be used when signing/verifying
            setCertificateNotBefore(startDate.time)                         //Start of the validity period for the self-signed certificate of the generated, default Jan 1 1970
            setCertificateNotAfter(endDate.time)                            //End of the validity period for the self-signed certificate of the generated key, default Jan 1 2048
            setUserAuthenticationRequired(false)                             //Sets whether this key is authorized to be used only if the user has been authenticated, default false
            setKeySize(2048)
            setIsStrongBoxBacked(true)
            build()
        }

        //Initialization of key generator with the parameters we have specified above
        keyPairGenerator.initialize(parameterSpec)

        //Generates the key pair
        return keyPairGenerator.genKeyPair()
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val keyPair = generateKeyPair()
        getChallenge(this, this)
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
        buttonUpload.setOnClickListener {
            if (fileContent != null && signedData != null) {
                //sendSignedDataToServer(fileContent!!, keyPair.public , signedData!!)
                println(formatBase64String(keyPair.public.encoded.toString()))
                sendSignedDataToServer(this, fileContent!!, keyPair.public,challengeString)
            } else {
                Toast.makeText(this, "No file selected", Toast.LENGTH_SHORT).show()
            }
        }
        filePickerLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result: ActivityResult ->
            if (result.resultCode == Activity.RESULT_OK) {
                result.data?.data?.let { uri ->
                    try {
                        fileContent = readFileContent(uri)
                        signedData = signData(fileContent!!)
                        Toast.makeText(this, "File ready to upload", Toast.LENGTH_SHORT).show()
                        println("File content size: ${fileContent?.size}")
                        println("Signed data size: ${signedData?.size}")
                    } catch (e: Exception) {
                        e.printStackTrace()
                        Toast.makeText(this, "Error processing file", Toast.LENGTH_SHORT).show()
                    }
                } ?: run {
                    Toast.makeText(this, "No file selected", Toast.LENGTH_SHORT).show()
                }
            } else {
                Toast.makeText(this, "File selection canceled", Toast.LENGTH_SHORT).show()
            }
        }
        //performDeviceAttestation()

    }
    private fun getChallenge(context: Context, callback:ChallengeCallback) {
        val url = "https://fileveri-flask.azurewebsites.net/api/challenge"
        val deviceId = "wenXku4fBwXU"
        val deviceToken = "eQGFH02opt4DQPiu"

        val jsonObjectRequest = object : JsonObjectRequest(
            Method.GET, url, null,
            { response ->
                try {
                    val challenge = response.getString("challenge")
                    callback.onSuccess(challenge)
                } catch (e: JSONException) {
                    e.printStackTrace()
                    callback.onFailure("Error parsing JSON data.")
                }
            },
            { error ->
                error.printStackTrace()
                callback.onFailure("Failed to fetch challenge.")
            }
        ) {
            override fun getHeaders(): Map<String, String> {
                val headers = HashMap<String, String>()
                headers["deviceid"] = deviceId
                headers["deviceToken"] = deviceToken
                return headers
            }
        }

        val requestQueue = Volley.newRequestQueue(context)
        requestQueue.add(jsonObjectRequest)
    }
    private fun signData(data: ByteArray): ByteArray? {
        return try {
            val signature: Signature = Signature.getInstance("SHA256withRSA")
            val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
            if (privateKey == null) {
                Toast.makeText(this, "Private key not found", Toast.LENGTH_SHORT).show()
                return null
            }
            signature.initSign(privateKey)
            signature.update(data)
            signature.sign()
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, "Error signing data", Toast.LENGTH_SHORT).show()
            null
        }
    }
    private fun encryptFileContent(fileContent: ByteArray, secretKey: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12) // GCM standard IV length
        SecureRandom().nextBytes(iv)
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
        val encryptedContent = cipher.doFinal(fileContent)
        return iv + encryptedContent // Concatenate IV and encrypted content
    }
    private fun generateSecretKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256) // AES-256
        return keyGenerator.generateKey()
    }
    private fun sendSignedDataToServer(context: Context,
                                       fileContent: ByteArray,
                                       publicKey: PublicKey,
                                       challengeString: String?
                                       ) {
        val secretKey = generateSecretKey()

        // Prepare data to be sent
        //val params = HashMap<String, String>()
//        params["encrypted_file_content"] = Base64.encodeToString(encryptFileContent(fileContent, secretKey), Base64.DEFAULT)
//        params["signed_encrypted_content"] = Base64.encodeToString(signData(encryptFileContent(fileContent, secretKey)), Base64.DEFAULT)
//        params["signed_challenge"] = Base64.encodeToString(challengeString?.let { signData(it.toByteArray(Charsets.UTF_8)) }, Base64.DEFAULT)
//        params["public_key"] = Base64.encodeToString(publicKey.encoded, Base64.DEFAULT)
//        params["challenge"] = Base64.encodeToString(challengeString?.toByteArray(Charsets.UTF_8) , Base64.DEFAULT)
//        val fileParams = HashMap<String, ByteArray>()
//        fileParams["encrypted_file_content"] = encryptFileContent(fileContent, secretKey)

        //println(Base64.encodeToString(publicKey.encoded, Base64.DEFAULT))

        // Send request using Volley
        //val queue: RequestQueue = Volley.newRequestQueue(context)
        val url = "https://fileveri-flask.azurewebsites.net/upload"
        val deviceId = "wenXku4fBwXU"
        val deviceToken = "eQGFH02opt4DQPiu"
        val encodedPublicKey = Base64.encodeToString(publicKey.encoded, Base64.DEFAULT).replace("\n", "")
        val publicKeyString = "-----BEGIN PUBLIC KEY-----\n${formatBase64String(encodedPublicKey)}-----END PUBLIC KEY-----"



        val jsonObjectRequest = object : StringRequest(
            Method.POST, url,
            { response ->
                Toast.makeText(context, response.toString(), Toast.LENGTH_SHORT).show()
            },
            { error ->
                // Handle error
                val responseBody = error.networkResponse?.data?.let { String(it, Charsets.UTF_8) }
                Toast.makeText(context, "Error: $responseBody", Toast.LENGTH_SHORT).show()
                println("UploadError: ${error.toString()}")
                println("UploadError: $responseBody")
            }){
            override fun getHeaders(): Map<String, String> {
                val headers = HashMap<String, String>()
                headers["deviceid"] = deviceId
                headers["deviceToken"] = deviceToken
                return headers
            }
            override fun getParams(): Map<String, String> {
                val params = HashMap<String, String>()
                //params["encrypted_file_content"] = Base64.encodeToString(fileContent, Base64.DEFAULT)
                //params["signed_encrypted_content"] = Base64.encodeToString(signData(encryptFileContent(fileContent, secretKey)), Base64.DEFAULT)
                params["signed_challenge"] = Base64.encodeToString(challengeString?.let { signData(it.toByteArray(Charsets.UTF_8)) }, Base64.DEFAULT)
                //params["public_key"] = "-----BEGIN PUBLIC KEY-----\n"+Base64.encodeToString(publicKey.encoded, Base64.DEFAULT).replace("\n", "")+"\n-----END PUBLIC KEY-----"
                //params["public_key"] = "-----BEGIN PUBLIC KEY-----\n${formatBase64String(publicKey.encoded.toString())}\n-----END PUBLIC KEY-----"
                params["public_key"] = publicKeyString
                params["challenge"] = Base64.encodeToString(challengeString?.toByteArray(Charsets.UTF_8) , Base64.DEFAULT)
                //println(params["public_key"])
                return params

            }
            override fun getRetryPolicy(): RetryPolicy {
                return DefaultRetryPolicy(
                    120000, // 2 minutes timeout
                    DefaultRetryPolicy.DEFAULT_MAX_RETRIES,
                    DefaultRetryPolicy.DEFAULT_BACKOFF_MULT
                )
            }
        }


        queue.add(jsonObjectRequest)
    }
    override fun onSuccess(challenge: String) {
        // Handle the challenge here
        challengeString = challenge
    }
    override fun onFailure(errorMessage: String) {
        // Handle the error here
        Toast.makeText(this, errorMessage, Toast.LENGTH_SHORT).show()
    }
    private fun formatBase64String(encoded: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < encoded.length) {
            sb.append(encoded, i, (i + 64).coerceAtMost(encoded.length)).append("\n")
            i += 64
        }
        return sb.toString()
    }
    private fun writeParamsToFile(context: Context, params: Map<String, String>) {
        val fileName = "request_params.txt"
        val file = File(context.filesDir, fileName)
        println(file.absolutePath)

        FileOutputStream(file).use { fos ->
            OutputStreamWriter(fos).use { writer ->
                writer.write("Params:\n")
                for ((key, value) in params) {
                    writer.write("$key: $value\n")
                }

            }
        }
    }
}

//    private fun signChallenge(challenge: ByteArray): ByteArray? {
//        val keyStore = KeyStore.getInstance("AndroidKeyStore")
//        keyStore.load(null)
//        val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
//
//        val signature = Signature.getInstance("SHA256withRSA")
//        signature.initSign(privateKey)
//        signature.update(challenge)
//
//        return signature.sign()
//    }
//    private fun createKey() {
//        try {
//            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
//            keyGenerator.init(
//                KeyGenParameterSpec.Builder(
//                    KEY_ALIAS,
//                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
//                )
//                    .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
//                    .setDigests(KeyProperties.DIGEST_SHA256)
//                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
//                    .build()
//            )
//            keyGenerator.generateKey()
//        } catch (e: Exception) {
//            e.printStackTrace()
//        }
//    }
//    private fun readFileContent(uri: Uri): ByteArray {
//        val inputStream: InputStream? = contentResolver.openInputStream(uri)
//        val byteArrayOutputStream = ByteArrayOutputStream()
//        val buffer = ByteArray(1024)
//        var length: Int
//        if (inputStream != null) {
//            while (inputStream.read(buffer).also { length = it } != -1) {
//                byteArrayOutputStream.write(buffer, 0, length)
//            }
//        }
//        return byteArrayOutputStream.toByteArray()
//    }
//    private fun pickFile() {
//        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
//            type = "*/*"
//            addCategory(Intent.CATEGORY_OPENABLE)
//        }
//
//        filePickerLauncher.launch(intent)
//    }
//
//
//    private fun performDeviceAttestation() {
//        val integrityManager: IntegrityManager = IntegrityManagerFactory.create(this)
//
//        val nonce = generateNonce()
//        val request = IntegrityTokenRequest.builder()
//            .setNonce(Base64.encodeToString(nonce, Base64.DEFAULT))
//            .build()
//
//        integrityManager.requestIntegrityToken(request)
//            .addOnCompleteListener { task ->
//                if (task.isSuccessful) {
//                    val tokenResponse = task.result
//                    val integrityToken = tokenResponse.token()
//
//                    // Send the integrity token to your server for verification
////                    sendTokenToServer(integrityToken)
//                } else {
//                    task.exception?.printStackTrace()
//                    // Handle failure case
//                }
//            }
//    }
//
//
//
////    private fun sendTokenToServer(integrityToken: String) {
////        val client = OkHttpClient()
////        val json = """
////        {
////            "token": "$integrityToken"
////        }
////    """.trimIndent()
////        val body = RequestBody.create("application/json; charset=utf-8".toMediaType(), json)
////        val request = Request.Builder()
////            .url("https://fileveri-flask.azurewebsites.net/verify")
////            .post(body)
////            .build()
////
////        client.newCall(request).enqueue(object : Callback {
////            override fun onFailure(call: Call, e: IOException) {
////                e.printStackTrace()
////            }
////
////            override fun onResponse(call: Call, response: Response) {
////                response.use {
////                    if (!response.isSuccessful) throw IOException("Unexpected code $response")
////
////                    val responseData = response.body()?.string()
////                    println(responseData)
////                }
////            }
////        })
////    }
//    private fun showFileChooser() {
//        val intent = Intent(Intent.ACTION_GET_CONTENT)
//        intent.type = "*/*"
//        intent.addCategory(Intent.CATEGORY_OPENABLE)
//        try {
//            startActivityForResult(Intent.createChooser(intent, "Select a File"), FILE_SELECT_CODE)
//        } catch (ex: android.content.ActivityNotFoundException) {
//            Toast.makeText(this, "Please install a File Manager.", Toast.LENGTH_SHORT).show()
//        }
//    }
//
//
//    private fun generateNonce(): ByteArray {
//        val nonceData = "Sample nonce".toByteArray()
//        // You should generate a cryptographically secure nonce for production use
//        return nonceData
//    }
//    @Deprecated("This method has been deprecated in favor of using the Activity Result API\n      which brings increased type safety via an {@link ActivityResultContract} and the prebuilt\n      contracts for common intents available in\n      {@link androidx.activity.result.contract.ActivityResultContracts}, provides hooks for\n      testing, and allow receiving results in separate, testable classes independent from your\n      activity. Use\n      {@link #registerForActivityResult(ActivityResultContract, ActivityResultCallback)}\n      with the appropriate {@link ActivityResultContract} and handling the result in the\n      {@link ActivityResultCallback#onActivityResult(Object) callback}.")
//    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
//        super.onActivityResult(requestCode, resultCode, data)
//        if (requestCode == FILE_SELECT_CODE && resultCode == RESULT_OK) {
//            val uri: Uri? = data?.data
//            uri?.let {
//                try {
//                    val fileContent = readFileContent(it)
//                    val signedData = signData(fileContent)
//                    sendSignedDataToServer(fileContent, signedData)
//                } catch (e: Exception) {
//                    e.printStackTrace()
//                }
//            }
//        }
//    }
//
//
//    private fun readFileContent(uri: Uri): ByteArray {
//        val inputStream: InputStream? = contentResolver.openInputStream(uri)
//        val byteArrayOutputStream = ByteArrayOutputStream()
//        val buffer = ByteArray(1024)
//        var length: Int
//        if (inputStream != null) {
//            while (inputStream.read(buffer).also { length = it } != -1) {
//                byteArrayOutputStream.write(buffer, 0, length)
//            }
//        }
//        return byteArrayOutputStream.toByteArray()
//    }
//
//    private fun createKey() {
//        try {
//            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
//            keyGenerator.init(
//                KeyGenParameterSpec.Builder(
//                    KEY_ALIAS,
//                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
//                )
//                    .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
//                    .setDigests(KeyProperties.DIGEST_SHA256)
//                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
//                    .build()
//            )
//            keyGenerator.generateKey()
//        } catch (e: Exception) {
//            e.printStackTrace()
//        }
//    }
//
//    private fun signData(data: ByteArray): ByteArray {
//        val signature: Signature = Signature.getInstance("SHA256withRSA")
//        val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
//        keyStore.load(null)
//        val privateKey: PrivateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
//        signature.initSign(privateKey)
//        signature.update(data)
//        return signature.sign()
//    }
//    private fun isSecureLockScreenEnabled(): Boolean {
//        val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
//        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
//            keyguardManager.isDeviceSecure
//        } else {
//            keyguardManager.isKeyguardSecure
//        }
//    }
//    private fun performDeviceAttestation() {
//        val integrityManager: IntegrityManager = IntegrityManagerFactory.create(this)
//
//        val nonce = generateNonce()
//        val request = IntegrityTokenRequest.builder()
//            .setNonce(Base64.encodeToString(nonce, Base64.DEFAULT))
//            .build()
//
//        integrityManager.requestIntegrityToken(request)
//            .addOnCompleteListener { task ->
//                if (task.isSuccessful) {
//                    val tokenResponse = task.result
//                    val integrityToken = tokenResponse.token()
//
//                    // Send the integrity token to your server for verification
////                    sendTokenToServer(integrityToken)
//                } else {
//                    task.exception?.printStackTrace()
//                    // Handle failure case
//                }
//            }
//    }
