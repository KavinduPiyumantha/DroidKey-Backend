# DroidKey Backend

DroidKey Backend is a Django-based web application designed to perform comprehensive security analysis on Android APK files. It integrates several powerful tools to decompile, analyze, and assess APKs for potential security vulnerabilities.

## Table of Contents

- Features
- Prerequisites
- Installation
- Running the Project
- API Endpoints
- Project Structure
- Detailed Backend Components
- Environment Variables
- Notes
- Troubleshooting
- Contributing
- License

## Features

- **APK Upload and Analysis**: Upload APK files for automated security analysis.
- **Integration with MobSF**: Uses Mobile Security Framework (MobSF) for static and dynamic analysis.
- **Decompilation with JADX**: Decompiles APKs to Java source code using JADX for deeper inspection.
- **Analysis with Quark Engine**: Utilizes Quark Engine to detect malwares and malicious behaviors.
- **Comprehensive Reports**: Generates detailed security reports highlighting vulnerabilities and recommendations.

## Prerequisites

- **Docker**
- **Docker Compose**
- **Python 3.10**

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/droidkey-backend.git
   cd droidkey-backend
   ```

2. **Ensure Docker and Docker Compose are installed**.

## Running the Project

### Using Docker Compose

Start the application using Docker Compose:

```bash
docker-compose up --build
```

This command will build and start the following services:

- **MobSF**: Mobile Security Framework accessible at `http://localhost:8000`.
- **Django Backend**: Backend server accessible at `http://localhost:8001`.

### Without Docker

If you prefer to run the project without Docker:

1. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

2. **Set Environment Variables**:

   - Create a .env file or set the following environment variables:

     ```env
     MOBSF_API_KEY=your_mobsf_api_key
     MOBSF_API_URL=http://localhost:8000
     DEBUG=1
     DJANGO_ALLOWED_HOSTS=127.0.0.1 localhost
     ```

3. **Run Migrations**:

   ```bash
   python manage.py migrate
   ```

4. **Start the Django Server**:

   ```bash
   python manage.py runserver 0.0.0.0:8001
   ```

5. **Start MobSF**:

   - Download and run MobSF separately if not using Docker.

## API Endpoints

### Upload APK for Analysis

- **URL**: `/api/upload_apk/`
- **Method**: `POST`
- **Content Type**: `multipart/form-data`
- **Parameters**:
  - `file`: The APK file to be uploaded.

**Example using `curl`**:

```bash
curl -X POST -F "file=@/path/to/your/app.apk" http://localhost:8001/api/upload_apk/
```

### Response

The response will include the analysis results, including security scores and detailed findings.

**Sample Response**:

```json
{
  "final_score": 78.33333333333333,
  "detailed_scores": {
    "Mobile Device Security": {
      "Prevent Rooted Device Access": {
        "score": 5,
        "status": "Passed",
        "details": "Application has root detection mechanisms implemented to prevent operation on rooted devices."
      }
    },
    "Data in Transit": {
      "HTTPS Enforcement": {
        "score": 5,
        "status": "Passed",
        "details": "HTTPS is enforced to ensure all communication is encrypted."
      },
      "Prevent Plaintext Transmission": {
        "score": 5,
        "status": "Passed",
        "details": "Sensitive data is not transmitted in plaintext, ensuring secure communication."
      }
    },
    "Data Storage": {
      "Avoid Storing Sensitive Data in External Storage": {
        "score": 5,
        "status": "Passed",
        "details": "Application does not store sensitive data in external storage, which reduces exposure risk."
      },
      "Strong Encryption for Locally Stored Data": {
        "score": 0,
        "status": "Failed",
        "details": "Application uses weak or no encryption for locally stored data."
      },
      "No Hardcoded Keys": {
        "score": 5,
        "status": "Passed",
        "details": "No hardcoded API keys found.",
        "keys": []
      }
    },
    "Cryptographic Practices": {
      "Use Strong Encryption": {
        "score": 0,
        "status": "Insecure",
        "details": "The application does not use strong encryption for local storage."
      },
      "Avoid Weak Hashing Algorithms": {
        "score": 5,
        "status": "Passed",
        "details": "No weak hashing algorithms detected."
      },
      "Avoid Insecure Random Number Generators": {
        "score": 0,
        "status": "Failed",
        "details": "The application uses an insecure Random Number Generator, which is susceptible to predictability and security vulnerabilities."
      }
    },
    "Obfuscation & Code Security": {
      "Code Obfuscation & Shrinking": {
        "score": 5,
        "status": "Enabled",
        "details": "Code obfuscation and shrinking techniques are implemented to protect against reverse engineering and reduce code size."
      },
      "Debugging Disabled": {
        "score": 5,
        "status": "Disabled",
        "details": "Debugging is disabled, which helps prevent attackers from analyzing the app behavior and extracting sensitive data."
      }
    },
    "Authentication & Access Control": {
      "Google API Key Restrictions": {
        "score": 5,
        "status": "No Keys Found",
        "details": "No Google API keys found for analysis."
      }
    }
  },
  "detailed_explanation": {
    "summary": "This analysis provides insights into multiple aspects of your application, including data encryption, root detection, secure storage, and hardcoded key findings.",
    "recommendations": [
      {
        "category": "Data Storage",
        "recommendation": "Application uses weak or no encryption for locally stored data."
      },
      {
        "category": "Cryptographic Practices",
        "recommendation": "The application does not use strong encryption for local storage."
      },
      {
        "category": "Cryptographic Practices",
        "recommendation": "The application uses an insecure Random Number Generator, which is susceptible to predictability and security vulnerabilities."
      }
    ],
    "findings_summary": "0 hardcoded secrets detected in source code. Details are provided in the detailed scores."
  },
  "high": [],
  "warning": [],
  "info": [],
  "secure": [],
  "hotspot": [],
  "total_trackers": 432,
  "trackers": 0,
  "security_score": 76,
  "app_name": "MapApp",
  "file_name": "app-release.apk",
  "hash": "ef66229977048a891fc39f4c911a9df1",
  "version_name": "1.0",
  "version": "v4.0.7",
  "title": "AppSec Scorecard",
  "efr01": false
}
```

## Project Structure

- **apk_analysis**: Contains the Django app for APK analysis.

  - **`views.py`**: Core logic for handling APK uploads and analysis.
  - **`models.py`**: Database models for storing analysis results.
  - **`serializers.py`**: Serializers for converting data to/from JSON.
  - **`urls.py`**: URL configurations for the APK analysis app.

- **rules**: Contains Quark Engine rules for detecting specific behaviors.

- **media**: Directory where uploaded APKs and analysis results are stored.

- **Dockerfile**: Defines the Docker image for the Django application.

- **`docker-compose.yml`**: Orchestrates multiple services using Docker Compose.
- **`requirements.txt`**: Lists Python dependencies.
- **`manage.py`**: Django's command-line utility for administrative tasks.

## Detailed Backend Components

### MobSF Integration

The backend communicates with MobSF using its API to perform static and dynamic analysis of APK files.

- **Upload to MobSF**: The APK file is uploaded to MobSF for analysis using `upload_to_mobsf`.
- **Scan with MobSF**: After uploading, the backend initiates a scan to analyze the APK using `scan_with_mobsf`.
- **Retrieve Scorecard**: The analysis results are retrieved with `get_mobsf_scorecard`.

### JADX Decompilation

JADX is used to decompile the APK into Java source code.

- **Decompilation**: The method `decompile_with_jadx` decompiles APKs to extract source code.
- **Hardcoded Keys Detection**: Searches decompiled code for hardcoded API keys and secrets using `find_hardcoded_keys`.

### Quark Engine Analysis

Quark Engine is used to detect malicious behaviors in the APK.

- **Rule-Based Analysis**: Custom rules in the

rules

directory are parsed and applied in `analyze_with_quark`.

- **Behavior Detection**: Identifies suspicious API calls and code patterns.

### Security Analysis

The backend performs a comprehensive security analysis evaluating various aspects through the `perform_security_analysis` method:

- **Mobile Device Security**: Checks for root detection and emulator detection mechanisms using `analyze_mobile_device_security`.
- **Data in Transit**: Verifies the use of secure communication protocols like HTTPS and SSL pinning using `analyze_data_in_transit`.
- **Data Storage**: Assesses data storage practices, including encryption and secure storage mechanisms using `analyze_data_storage`.
- **Cryptographic Practices**: Evaluates the use of cryptographic algorithms and key management using `analyze_cryptographic_practices`.

### Key Methods in `APKUploadView`

- **`post`**: Handles the APK file upload and initiates the analysis process.
- **`upload_to_mobsf`**: Uploads the APK to MobSF for analysis.
- **`scan_with_mobsf`**: Initiates scanning of the uploaded APK in MobSF.
- **`get_mobsf_scorecard`**: Retrieves the analysis scorecard from MobSF.
- **`decompile_with_jadx`**: Decompiles the APK using JADX.
- **`analyze_with_quark`**: Analyzes the APK using Quark Engine.
- **`perform_security_analysis`**: Aggregates all analysis results to compute final scores and detailed findings.

## Environment Variables

Configure the following environment variables as needed:

- **`MOBSF_API_KEY`**: API key for MobSF.
- **`MOBSF_API_URL`**: URL for the MobSF API (e.g., `http://mobsf:8000`).
- **`DEBUG`**: Set to `1` to enable debug mode.
- **`DJANGO_ALLOWED_HOSTS`**: Allowed hosts for the Django application.

## Notes

- The Django application communicates with MobSF, so ensure the MobSF service is running before making requests.
- All uploaded files and analysis outputs are stored in the

media

directory.

- The backend performs multiple layers of analysis to provide a comprehensive security assessment.

## Troubleshooting

- **Docker Issues**: If you encounter issues with Docker or Docker Compose, ensure they are properly installed and running.
- **MobSF Connectivity**: Verify that MobSF is accessible at the specified URL and the API key is correct.
- **File Permissions**: Ensure the

media

directory has appropriate permissions for file uploads and storage.

- **JADX Installation**: Ensure that JADX is properly installed and accessible if running outside Docker.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License.
