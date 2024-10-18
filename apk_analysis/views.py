import subprocess
from django.conf import settings
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import APKAnalysisSerializer
from .models import APKAnalysis
from django.core.files.storage import default_storage
import os
import requests
import logging
import re

# Set up logger
logger = logging.getLogger(__name__)

class APKUploadView(APIView):
    def post(self, request, *args, **kwargs):
        # Handle APK file upload
        file = request.FILES.get('file')
        if not file:
            logger.error("No file provided for upload.")
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Save file temporarily to the media directory
        file_path = default_storage.save(file.name, file)
        abs_path = os.path.join(settings.MEDIA_ROOT, file_path)
        logger.info(f"File saved to {abs_path}")

        # Perform analysis with MobSF
        upload_response = self.upload_to_mobsf(abs_path, file.name)
        if "error" in upload_response:
            logger.error(f"MobSF upload error: {upload_response['error']}")
            return Response(upload_response, status=status.HTTP_400_BAD_REQUEST)

        logger.info("File uploaded successfully to MobSF")

        # Use the hash to perform the scan
        scan_response = self.scan_with_mobsf(upload_response['hash'])
        if "error" in scan_response:
            logger.error(f"MobSF scan error: {scan_response['error']}")
            return Response(scan_response, status=status.HTTP_400_BAD_REQUEST)

        logger.info("MobSF scan completed successfully")

        # Generate scorecard report with MobSF
        scorecard_response = self.get_mobsf_scorecard(upload_response['hash'])
        if "error" in scorecard_response:
            logger.error(f"MobSF scorecard error: {scorecard_response['error']}")
            return Response(scorecard_response, status=status.HTTP_400_BAD_REQUEST)

        logger.info("MobSF scorecard retrieved successfully")

        # Decompile the APK using JADX
        jadx_result = self.decompile_with_jadx(abs_path)
        if "error" in jadx_result:
            logger.error(f"JADX decompilation error: {jadx_result['error']}")
            return Response(jadx_result, status=status.HTTP_400_BAD_REQUEST)

        logger.info("JADX decompilation completed successfully")

        # Perform security scoring and analysis
        try:
            analysis_result = self.perform_security_analysis(scorecard_response, jadx_result['message'])
        except Exception as e:
            logger.error(f"Exception during security scoring: {str(e)}")
            return Response({"error": f"Exception during security scoring: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Return only the analysis result
        return Response(analysis_result, status=status.HTTP_200_OK)

    def upload_to_mobsf(self, file_path, file_name):
        try:
            # Open the file from the media directory
            with open(file_path, 'rb') as f:
                files = {'file': (file_name, f, 'application/vnd.android.package-archive')}

                # Headers for MobSF API
                headers = {
                    'Authorization': settings.MOBSF_API_KEY
                }

                # Upload API URL
                mobsf_upload_url = f"{settings.MOBSF_API_URL}/api/v1/upload"

                # Send file to MobSF for analysis
                response = requests.post(mobsf_upload_url, files=files, headers=headers)

                if response.status_code == 200:
                    # Successful upload - return analysis details including the hash
                    return response.json()
                else:
                    # Handle error from MobSF API
                    return {"error": f"MobSF API error during upload: {response.text}"}
        except Exception as e:
            logger.error(f"Exception during MobSF file upload: {str(e)}")
            return {"error": f"An exception occurred during file upload: {str(e)}"}

    def scan_with_mobsf(self, file_hash):
        try:
            # Headers for MobSF API
            headers = {
                'Authorization': settings.MOBSF_API_KEY
            }

            # Scan API URL
            mobsf_scan_url = f"{settings.MOBSF_API_URL}/api/v1/scan"

            # Data for scanning
            data = {
                'hash': file_hash
            }

            # Send request to MobSF to scan the uploaded file
            response = requests.post(mobsf_scan_url, headers=headers, data=data)

            if response.status_code == 200:
                # Successful scan - return analysis details
                return response.json()
            else:
                # Handle error from MobSF API
                return {"error": f"MobSF API error during scan: {response.text}"}
        except Exception as e:
            logger.error(f"Exception during MobSF file scan: {str(e)}")
            return {"error": f"An exception occurred during file scan: {str(e)}"}

    def get_mobsf_scorecard(self, file_hash):
        try:
            headers = {
                'Authorization': settings.MOBSF_API_KEY
            }
            mobsf_scorecard_url = f"{settings.MOBSF_API_URL}/api/v1/scorecard"
            data = {
                'hash': file_hash
            }
            response = requests.post(mobsf_scorecard_url, headers=headers, data=data)

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"MobSF API error during scorecard retrieval: {response.text}"}
        except Exception as e:
            logger.error(f"Exception during MobSF scorecard retrieval: {str(e)}")
            return {"error": f"An exception occurred during scorecard retrieval: {str(e)}"}

    def decompile_with_jadx(self, file_path):
        try:
            # Path to output directory for JADX decompiled code
            output_dir = os.path.join(settings.MEDIA_ROOT, 'jadx_output')
            os.makedirs(output_dir, exist_ok=True)

            # Command to run JADX
            command = [
                'jadx',  # Assuming JADX is installed and accessible from the command line
                '-d', output_dir,  # Output directory
                file_path  # APK file path
            ]

            # Run JADX as a subprocess
            result = subprocess.run(command, capture_output=True, text=True)

            # Check if JADX ran successfully
            if result.returncode == 0:
                logger.info(f"JADX decompiled successfully to {output_dir}")
                return {"status": "success", "message": f"Decompiled successfully to {output_dir}"}
            else:
                logger.error(f"JADX error: {result.stderr}")
                return {"error": f"JADX error: {result.stderr}"}
        except Exception as e:
            logger.error(f"Exception during JADX decompilation: {str(e)}")
            return {"error": f"An exception occurred during decompilation: {str(e)}"}

    def perform_security_analysis(self, json_report, jadx_output_dir):
        """
        Perform a comprehensive security analysis using MobSF report and JADX output.
        Returns a detailed JSON result including each criterion's status.
        """
        final_score = 0
        detailed_scores = {}

        # Define criteria weights
        weights = {
            "Mobile Device Security": 15,
            "Data in Transit": 20,
            "Data Storage": 25,
            "Cryptographic Practices": 20,
            "Obfuscation & Code Security": 10,
            "Secure Key Management": 5,
            "Authentication & Access Control": 5,
            "Monitoring & Auditing": 5
        }

        # Perform checks for each category and calculate scores

        # Mobile Device Security
        detailed_scores["Mobile Device Security"] = {
            "prevent_rooted_device_access": {
                "score": 5 if json_report.get("root_detection") == "passed" else 0,
                "status": "Passed" if json_report.get("root_detection") == "passed" else "Failed",
                "details": "Application has root detection mechanisms implemented to prevent operation on rooted devices."
            },
            "disable_emulator_access": {
                "score": 5 if json_report.get("emulator_detection") == "passed" else 0,
                "status": "Passed" if json_report.get("emulator_detection") == "passed" else "Failed",
                "details": "Emulator detection is in place to restrict access when running on emulators."
            }
        }

        # Data in Transit
        detailed_scores["Data in Transit"] = {
            "https_enforced": {
                "score": 5 if json_report.get("uses_https") == "yes" else 0,
                "status": "Passed" if json_report.get("uses_https") == "yes" else "Failed",
                "details": "HTTPS is enforced to ensure all communication is encrypted."
            },
            "prevent_plaintext_transmission": {
                "score": 5 if json_report.get("prevent_plaintext_transmission") == "yes" else 0,
                "status": "Passed" if json_report.get("prevent_plaintext_transmission") == "yes" else "Failed",
                "details": "Sensitive data is not transmitted in plaintext, ensuring secure communication."
            }
        }

        # Data Storage - checking both MobSF report and JADX output
        hardcoded_keys_jadx = self.find_hardcoded_keys(json_report, jadx_output_dir)
        hardcoded_keys_mobsf = self.extract_hardcoded_keys_from_mobsf(json_report)

        detailed_scores["Data Storage"] = {
            "encrypted_storage": {
                "score": 5 if json_report.get("secure_storage") == "yes" else 0,
                "status": "Passed" if json_report.get("secure_storage") == "yes" else "Failed",
                "details": "API keys and sensitive data are stored in encrypted, secure storage."
            },
            "no_hardcoded_keys": {
                "score": 5 if not hardcoded_keys_jadx and not hardcoded_keys_mobsf else 0,
                "status": "Passed" if not hardcoded_keys_jadx and not hardcoded_keys_mobsf else "Failed",
                "details": f"Hardcoded keys found: {hardcoded_keys_jadx + hardcoded_keys_mobsf}" if hardcoded_keys_jadx or hardcoded_keys_mobsf else "No hardcoded API keys found."
            },
            "backup_allowed": {
                "score": 0 if any(item.get('title') == "Application Data can be Backed up" for item in json_report.get("warning", [])) else 5,
                "status": "Failed" if any(item.get('title') == "Application Data can be Backed up" for item in json_report.get("warning", [])) else "Passed",
                "details": "Application data backup is not allowed to ensure sensitive data is not easily copied."
            }
        }

        # Cryptographic Practices
        detailed_scores["Cryptographic Practices"] = {
            "use_strong_encryption": {
                "score": 5 if json_report.get("encryption_algorithm") == "AES-256" else 0,
                "status": "Secure" if json_report.get("encryption_algorithm") == "AES-256" else "Insecure",
                "details": "The application uses AES-256 for encryption, which is considered secure."
            },
            "avoid_weak_hashing": {
                "score": 0 if any(item.get('title') in ["MD5 is a weak hash known to have hash collisions.", "SHA-1 is a weak hash known to have hash collisions."] for item in json_report.get("warning", [])) else 5,
                "status": "Failed" if any(item.get('title') in ["MD5 is a weak hash known to have hash collisions.", "SHA-1 is a weak hash known to have hash collisions."] for item in json_report.get("warning", [])) else "Passed",
                "details": "Avoid weak hashing algorithms like MD5 or SHA-1 which are susceptible to collisions."
            }
        }

        # Obfuscation & Code Security
        detailed_scores["Obfuscation & Code Security"] = {
            "code_obfuscation": {
                "score": 5 if json_report.get("obfuscation_enabled") == "yes" else 0,
                "status": "Enabled" if json_report.get("obfuscation_enabled") == "yes" else "Not Enabled",
                "details": "Code obfuscation techniques are implemented to protect against reverse engineering."
            }
        }

        # Secure Key Management
        detailed_scores["Secure Key Management"] = {
            "server_side_key_management": {
                "score": 5 if json_report.get("server_side_key_management") == "yes" else 0,
                "status": "Passed" if json_report.get("server_side_key_management") == "yes" else "Failed",
                "details": "API keys are managed server-side, reducing the risk of exposure."
            }
        }

        # Authentication & Access Control
        detailed_scores["Authentication & Access Control"] = {
            "token_based_authentication": {
                "score": 5 if json_report.get("token_auth") == "yes" else 0,
                "status": "Passed" if json_report.get("token_auth") == "yes" else "Failed",
                "details": "Token-based authentication (e.g., OAuth 2.0) is used to limit API key exposure."
            }
        }

        # Monitoring & Auditing
        detailed_scores["Monitoring & Auditing"] = {
            "logging_api_key_usage": {
                "score": 5 if json_report.get("logging_enabled") == "yes" else 0,
                "status": "Enabled" if json_report.get("logging_enabled") == "yes" else "Not Enabled",
                "details": "Logging is enabled to monitor API key usage and detect potential abuse."
            }
        }

        # Calculate total score
        for category, criteria in detailed_scores.items():
            for criterion in criteria.values():
                final_score += criterion['score']

        # Normalize final score to be out of 100
        total_weight = sum(weights.values())
        final_score = (final_score / (total_weight * 5)) * 100 if total_weight else 0

        # Prepare and return analysis result in JSON format
        return {
            "final_score": final_score,
            "detailed_scores": detailed_scores,
            "detailed_explanation": {
                "summary": "This analysis provides insights into multiple aspects of your application, including data encryption, root detection, secure storage, and hardcoded key findings.",
                "recommendations": [
                    {
                        "category": "Mobile Device Security",
                        "recommendation": "Ensure root detection and emulator detection mechanisms are in place and tested effectively."
                    },
                    {
                        "category": "Data in Transit",
                        "recommendation": "Use HTTPS with TLS 1.2 or above, avoid plaintext transmission, and implement certificate pinning to prevent MITM attacks."
                    },
                    {
                        "category": "Data Storage",
                        "recommendation": "Use secure storage solutions such as Android Keystore for storing API keys and avoid hardcoded secrets in source code."
                    },
                    {
                        "category": "Cryptographic Practices",
                        "recommendation": "Use strong encryption algorithms (AES-256 or above), avoid weak hash functions (e.g., MD5, SHA-1), and ensure keys are managed securely."
                    },
                    {
                        "category": "Obfuscation & Code Security",
                        "recommendation": "Implement ProGuard or R8 for code obfuscation and make sure debuggable flags are disabled in production."
                    },
                    {
                        "category": "Secure Key Management",
                        "recommendation": "Consider managing keys server-side using key vaults to ensure secure access and automated rotation."
                    },
                    {
                        "category": "Authentication & Access Control",
                        "recommendation": "Use OAuth for authentication and ensure role-based access control to restrict API usage appropriately."
                    },
                    {
                        "category": "Monitoring & Auditing",
                        "recommendation": "Enable detailed logging for API key usage and anomalies. Perform regular security audits."
                    }
                ],
                "findings_summary": f"{len(hardcoded_keys_jadx) + len(hardcoded_keys_mobsf)} hardcoded secrets detected in source code. Details are provided in the detailed scores."
            },
            "high": [],  # Populate based on your criteria
            "warning": [],  # Populate based on your criteria
            "info": [],  # Populate based on your criteria
            "secure": [],  # Populate based on your criteria
            "hotspot": [],  # Populate based on your criteria
            "total_trackers": json_report.get("total_trackers", 0),
            "trackers": json_report.get("trackers", 0),
            "security_score": json_report.get("security_score", 0),
            "app_name": json_report.get("app_name", ""),
            "file_name": json_report.get("file_name", ""),
            "hash": json_report.get("hash", ""),
            "version_name": json_report.get("version_name", ""),
            "version": json_report.get("version", ""),
            "title": json_report.get("title", ""),
            "efr01": json_report.get("efr01", False)
        }

    def extract_hardcoded_keys_from_mobsf(self, json_report):
        """
        Extract hardcoded API keys from MobSF's report.
        """
        hardcoded_keys = []
        secrets_section = [item for item in json_report.get('warning', []) if item.get('title') == "This app may contain hardcoded secrets"]
        for secret in secrets_section:
            description = secret.get("description", "")
            matches = re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', description)
            for key, value in matches:
                hardcoded_keys.append({"key": key, "value": value})
        return hardcoded_keys

    def find_hardcoded_keys(self, json_report, jadx_output_dir):
        """
        Combine MobSF JSON data and JADX output to find hardcoded API keys.
        Returns a list of detected hardcoded keys with their details.
        """
        hardcoded_keys = []

        # Extract hardcoded secrets from MobSF JSON report
        if "secrets" in json_report:
            for secret in json_report["secrets"]:
                hardcoded_keys.append({
                    "source": "MobSF Report",
                    "key": secret
                })

        # Find hardcoded keys in JADX decompiled code
        key_patterns = [
            r'AIza[0-9A-Za-z-_]{35}',  # Google API Key
            r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',  # Firebase Key
            r'pk_live_[0-9a-zA-Z]{24}',  # Stripe Live Key
        ]

        for root, dirs, files in os.walk(jadx_output_dir):
            for file in files:
                if file.endswith(".java") or file.endswith(".xml"):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        for pattern in key_patterns:
                            matches = re.findall(pattern, content)
                            if matches:
                                for match in matches:
                                    hardcoded_keys.append({
                                        "source": "JADX Decompiled Code",
                                        "file": file_path,
                                        "key": match
                                    })

        return hardcoded_keys