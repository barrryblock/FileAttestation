# File Attestation Android App

This Android application demonstrates how to generate a key pair using the Android Keystore, sign data, and upload files along with signed data to a remote server. The app interacts with a backend server to perform device attestation and file uploads securely.

## Features

- **Key Pair Generation**: Generates an RSA key pair using the Android Keystore.
- **File Selection**: Allows users to select files from their device.
- **File Upload**: Uploads the selected file along with its signed content to a remote server.
- **Device Attestation**: Sends the device's public key to a server during registration.
- **Challenge Response**: Retrieves and signs a challenge from the server before uploading.

## How It Works

### Key Pair Generation

The app generates an RSA key pair using the Android Keystore, specifically designed for secure key storage. The private key is used to sign data, while the public key is sent to the server for verification.

### File Selection and Upload

Users can select a file from their device, which is then read and prepared for upload. The file's content is signed using the previously generated private key. Both the file and the signed content are uploaded to the server.

### Challenge Response

The app communicates with a backend server to retrieve a challenge string. This string is signed and sent back to the server along with the file upload, ensuring the integrity and authenticity of the request.

## Dependencies

The app relies on the following libraries:

- **Volley**: For network requests, including JSON handling and POST requests.
- **OkHttp**: For handling file uploads via multipart requests.
- **Android Security Library**: For key generation and data signing.

## Setup and Usage

1. **Clone the Repository**: Clone the project to your local machine.

2. **Configure Server URL and Credentials**:
   - Update the `SERVER_URL`, `DEVICE_ID`, and `DEVICE_TOKEN` constants in the `MainActivity` class with your server details and credentials.

3. **Build and Run**: Build the project in Android Studio and run it on an Android device or emulator.

4. **Select a File**: Use the app's UI to select a file from your device.

5. **Upload File**: After selecting a file, click the upload button to send the file and its signed content to the server.

## Code Overview

- **MainActivity.kt**: The main activity that handles file selection, key generation, and file upload.
- **ChallengeCallback**: Interface for handling the server's challenge response.
- **Key Pair Generation**: The `generateKeyPair()` function generates and stores a key pair in the Android Keystore.
- **File Upload**: The `uploadByteArrayToFlaskServer()` function handles the file upload process using OkHttp.

## Notes

- The app currently interacts with a sample server hosted on Azure (`https://deviceattestation.azurewebsites.net`). Update this URL as needed.
- Ensure that your backend server can handle multipart file uploads and verify signed data.

## License

This project is licensed under the MIT License.

