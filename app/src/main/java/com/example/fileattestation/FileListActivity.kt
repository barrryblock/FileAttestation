package com.example.fileattestation

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.android.volley.Request
import com.android.volley.RequestQueue
import com.android.volley.Response
import com.android.volley.toolbox.JsonArrayRequest
import com.android.volley.toolbox.Volley
import org.json.JSONException
import android.view.MenuItem
import androidx.appcompat.widget.Toolbar


class FileListActivity : AppCompatActivity() {

    private lateinit var listView: ListView
    private lateinit var queue: RequestQueue

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_list)

        val toolbar: Toolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Uploaded Files"

        listView = findViewById(R.id.listViewFiles)
        queue = Volley.newRequestQueue(this)

        fetchFileList()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                // Handle the back button click
                finish()
                true
            }

            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun fetchFileList() {
        val url = "https://deviceattestation.azurewebsites.net/api/files"
        val deviceId = "2sjYuOGkiQ9H"
        val deviceToken = "Z7SvEGdnCcf9BobK"

        val jsonArrayRequest = object : JsonArrayRequest(
            Request.Method.GET, url, null,
            { response ->
                try {
                    val fileList = ArrayList<String>()
                    for (i in 0 until response.length()) {
                        val fileObject = response.getJSONObject(i)
                        val fileName = fileObject.getString("name")
                        val fileDate = fileObject.getString("last_modified")
                        val fileSize = fileObject.getString("size")
                        fileList.add("$fileName - $fileSize - $fileDate")
                    }
                    val adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, fileList)
                    listView.adapter = adapter
                } catch (e: JSONException) {
                    e.printStackTrace()
                    Toast.makeText(this, "Error parsing JSON data.", Toast.LENGTH_SHORT).show()
                }
            },
            { error ->
                error.printStackTrace()
                Toast.makeText(this, "Failed to fetch file list.", Toast.LENGTH_SHORT).show()
            }
        ) {
            override fun getHeaders(): Map<String, String> {
                val headers = HashMap<String, String>()
                headers["deviceid"] = deviceId
                headers["deviceToken"] = deviceToken
                return headers
            }
        }

        // Assuming 'queue' is your RequestQueue instance
        queue.add(jsonArrayRequest)
    }
}