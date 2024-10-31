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
from quark.script import runQuarkAnalysis, Rule 

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

        # Perform Quark Engine Analysis
        try:
            if not os.path.isfile(abs_path):
                raise FileNotFoundError(f"APK file not found for analysis: {abs_path}")

            quark_result = self.analyze_with_quark(abs_path)
            if "error" in quark_result:
                logger.error(f"Quark analysis error: {quark_result['error']}")
                return Response(quark_result, status=status.HTTP_400_BAD_REQUEST)
            logger.info("Quark analysis completed successfully")
        except FileNotFoundError as fnf_error:
            logger.error(f"File not found error during Quark analysis: {str(fnf_error)}")
            return Response({'error': str(fnf_error)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Exception during Quark analysis: {str(e)}")
            return Response({'error': f'An exception occurred during Quark analysis: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        # logger.info({quark_result})
        logger.info("Quark analysis completed successfully")

        # Perform security scoring and analysis with combined results
        try:
            analysis_result = self.perform_security_analysis(scan_response,scorecard_response, jadx_result['message'], quark_result)
        except Exception as e:
            logger.error(f"Exception during security scoring: {str(e)}")
            return Response({"error": f"Exception during security scoring: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Return only the analysis result
        return Response(analysis_result, status=status.HTTP_200_OK)

    def analyze_with_quark(self, file_path, rule_directory="/code/rules"):
        """
        Perform analysis using Quark Engine for each rule available in the rule directory.
        :param file_path: Path to the APK file to be analyzed.
        :param rule_directory: Path to the directory containing the rule JSON files.
        :return: Dictionary containing the analysis results.
        """
        # Function logic remains the same
        try:
            # Ensure the file exists and is a valid file
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"Provided file path is not a valid file: {file_path}")

            # List to hold all rule results
            full_analysis_result = {
                "summary": {
                    "total_rules": 0,
                    "total_behaviors_detected": 0,
                    "risk_level": "Low"  # Default risk level
                },
                "rules": []
            }

            # Check if rule directory is valid and exists
            if not os.path.isdir(rule_directory):
                raise NotADirectoryError(f"Provided rule path is not a directory: {rule_directory}")

            # Iterate over all files in the rule directory and perform analysis for each rule
            rule_files = os.listdir(rule_directory)
            full_analysis_result["summary"]["total_rules"] = len([f for f in rule_files if f.endswith('.json')])

            for rule_filename in rule_files:
                rule_path = os.path.join(rule_directory, rule_filename)

                if not rule_filename.endswith(".json"):
                    logger.warning(f"Skipping non-JSON file in rule directory: {rule_filename}")
                    continue

                try:
                    # Load and run the rule against the sample APK
                    rule_instance = Rule(rule_path)

                    # Verify if the rule instance is loaded correctly
                    if not rule_instance:
                        logger.error(f"Failed to load rule instance from: {rule_path}")
                        continue

                    quark_result = runQuarkAnalysis(file_path, rule_instance)

                    # Prepare the analysis result for each rule
                    rule_result = {
                        "rule_name": rule_instance.crime,
                        "rule_file": rule_filename,
                        "behavior_occurrences": []
                    }

                    # Collect the detected behaviors from the analysis
                    for behavior in quark_result.behaviorOccurList:
                        behavior_data = {
                            "methodCaller": behavior.methodCaller.fullName if behavior.methodCaller else None,
                            "firstAPI": behavior.firstAPI.fullName if behavior.firstAPI else None,
                            "secondAPI": behavior.secondAPI.fullName if behavior.secondAPI else None,
                            "params": behavior.getParamValues() if behavior.getParamValues() else [],
                        }
                        rule_result["behavior_occurrences"].append(behavior_data)

                    # Track the number of behaviors detected for this rule
                    behavior_count = len(rule_result["behavior_occurrences"])
                    full_analysis_result["summary"]["total_behaviors_detected"] += behavior_count

                    # Update risk information if a malicious behavior is found
                    if behavior_count > 0 and "malicious" in rule_instance.crime.lower():
                        full_analysis_result["summary"]["risk_level"] = "High"

                    # Add the rule result to the complete analysis result
                    full_analysis_result["rules"].append(rule_result)

                    logger.info(f"Analysis with rule {rule_filename} completed successfully. Detected {behavior_count} occurrences.")

                except Exception as e:
                    logger.error(f"Exception during analysis with rule {rule_filename}: {str(e)}")

            # Returning JSON summary of analysis results
            return full_analysis_result

        except FileNotFoundError as fnf_error:
            logger.error(f"File not found error during Quark analysis: {str(fnf_error)}")
            return {"error": str(fnf_error)}

        except NotADirectoryError as nd_error:
            logger.error(f"Rule directory error during Quark analysis: {str(nd_error)}")
            return {"error": str(nd_error)}

        except Exception as e:
            logger.error(f"Exception during Quark analysis: {str(e)}")
            return {"error": f"An exception occurred during Quark analysis: {str(e)}"}

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

    def perform_security_analysis(self,scan_response, scorecard_response, jadx_output_dir, quark_result):
        """
        Perform a comprehensive security analysis using MobSF report, JADX output, and Quark Engine results.
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

        # Call sub-functions for each category
        detailed_scores["Mobile Device Security"] = self.analyze_mobile_device_security(scorecard_response,scan_response, quark_result)
        detailed_scores["Data in Transit"] = self.analyze_data_in_transit(scorecard_response,scan_response, quark_result)
        detailed_scores["Data Storage"] = self.analyze_data_storage(scorecard_response,scan_response, jadx_output_dir, quark_result)
        detailed_scores["Cryptographic Practices"] = self.analyze_cryptographic_practices(scorecard_response,scan_response, quark_result)
        detailed_scores["Obfuscation & Code Security"] = self.analyze_obfuscation_and_code_security(scorecard_response,scan_response, quark_result)
        detailed_scores["Secure Key Management"] = self.analyze_secure_key_management(scorecard_response,scan_response, quark_result)
        detailed_scores["Authentication & Access Control"] = self.analyze_authentication_and_access_control(scorecard_response,scan_response, quark_result)
        detailed_scores["Monitoring & Auditing"] = self.analyze_monitoring_and_auditing(scorecard_response,scan_response, quark_result)

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
                "recommendations": self.generate_recommendations(detailed_scores),
                "findings_summary": f"{self.count_hardcoded_keys(detailed_scores)} hardcoded secrets detected in source code. Details are provided in the detailed scores."
            },
            "high": [],  # Populate based on your criteria
            "warning": [],  # Populate based on your criteria
            "info": [],  # Populate based on your criteria
            "secure": [],  # Populate based on your criteria
            "hotspot": [],  # Populate based on your criteria
            "total_trackers": scorecard_response.get("total_trackers", 0),
            "trackers": scorecard_response.get("trackers", 0),
            "security_score": scorecard_response.get("security_score", 0),
            "app_name": scorecard_response.get("app_name", ""),
            "file_name": scorecard_response.get("file_name", ""),
            "hash": scorecard_response.get("hash", ""),
            "version_name": scorecard_response.get("version_name", ""),
            "version": scorecard_response.get("version", ""),
            "title": scorecard_response.get("title", ""),
            "efr01": scorecard_response.get("efr01", False)
        }

    def analyze_mobile_device_security(self,scan_response, scorecard_response, quark_result):
        """
        Analyze Mobile Device Security aspects of the application using MobSF and Quark results.
        """
        rooted_detection = scorecard_response.get("root_detection") == "passed" or any(
            rule["rule_name"].lower() == "detect rooted device" and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )
        emulator_detection = scorecard_response.get("emulator_detection") == "passed" or any(
            rule["rule_name"].lower() == "emulator detection" and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )

        return {
            "prevent_rooted_device_access": {
                "score": 5 if rooted_detection else 0,
                "status": "Passed" if rooted_detection else "Failed",
                "details": "Application has root detection mechanisms implemented to prevent operation on rooted devices."
            },
            "disable_emulator_access": {
                "score": 5 if emulator_detection else 0,
                "status": "Passed" if emulator_detection else "Failed",
                "details": "Emulator detection is in place to restrict access when running on emulators."
            }
        }

    def analyze_data_in_transit(self,scan_response, scorecard_response, quark_result):
        """
        Analyze Data in Transit security aspects using MobSF and Quark results.
        """
        https_enforced = scorecard_response.get("uses_https") == "yes" or any(
            rule["rule_name"].lower() == "https enforcement" and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )
        plaintext_transmission_prevented = scorecard_response.get("prevent_plaintext_transmission") == "yes" or not any(
            rule["rule_name"].lower() == "detect plaintext transmission" and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )

        return {
            "https_enforced": {
                "score": 5 if https_enforced else 0,
                "status": "Passed" if https_enforced else "Failed",
                "details": "HTTPS is enforced to ensure all communication is encrypted."
            },
            "prevent_plaintext_transmission": {
                "score": 5 if plaintext_transmission_prevented else 0,
                "status": "Passed" if plaintext_transmission_prevented else "Failed",
                "details": "Sensitive data is not transmitted in plaintext, ensuring secure communication."
            }
        }

    def analyze_data_storage(self,scan_response, scorecard_response, jadx_output_dir, quark_result):
        """
        Analyze Data Storage aspects using MobSF, JADX, and Quark results.
        """
        hardcoded_keys_jadx = self.find_hardcoded_keys(scan_response,scorecard_response, jadx_output_dir)
        hardcoded_keys_mobsf = self.extract_hardcoded_keys_from_mobsf(scan_response,scorecard_response)
        hardcoded_keys_quark = [
            item for rule in quark_result.get("rules", [])
            if "hardcoded" in rule["rule_name"].lower() and rule["behavior_occurrences"]
            for item in rule["behavior_occurrences"]
        ]

        return {
            "encrypted_storage": {
                "score": 5 if scorecard_response.get("secure_storage") == "yes" else 0,
                "status": "Passed" if scorecard_response.get("secure_storage") == "yes" else "Failed",
                "details": "API keys and sensitive data are stored in encrypted, secure storage."
            },
            "no_hardcoded_keys": {
                "score": 5 if not hardcoded_keys_jadx and not hardcoded_keys_mobsf and not hardcoded_keys_quark else 0,
                "status": "Passed" if not hardcoded_keys_jadx and not hardcoded_keys_mobsf and not hardcoded_keys_quark else "Failed",
                "details": f"Hardcoded keys found: {hardcoded_keys_jadx + hardcoded_keys_mobsf + hardcoded_keys_quark}" if hardcoded_keys_jadx or hardcoded_keys_mobsf or hardcoded_keys_quark else "No hardcoded API keys found."
            },
            "backup_allowed": {
                "score": 0 if any(item.get('title') == "Application Data can be Backed up" for item in scorecard_response.get("warning", [])) else 5,
                "status": "Failed" if any(item.get('title') == "Application Data can be Backed up" for item in scorecard_response.get("warning", [])) else "Passed",
                "details": "Application data backup is not allowed to ensure sensitive data is not easily copied."
            }
        }

    def analyze_cryptographic_practices(self,scan_response, scorecard_response, quark_result):
        """
        Analyze Cryptographic Practices using MobSF and Quark results.
        """
        weak_prng_detected = any(rule["rule_name"].lower() == "use weak prng" and rule["behavior_occurrences"] for rule in quark_result.get("rules", []))

        return {
            "use_strong_encryption": {
                "score": 5 if scorecard_response.get("encryption_algorithm") == "AES-256" else 0,
                "status": "Secure" if scorecard_response.get("encryption_algorithm") == "AES-256" else "Insecure",
                "details": "The application uses AES-256 for encryption, which is considered secure."
            },
            "avoid_weak_hashing": {
                "score": 0 if any(item.get('title') in ["MD5 is a weak hash known to have hash collisions.", "SHA-1 is a weak hash known to have hash collisions."] for item in scorecard_response.get("warning", [])) or weak_prng_detected else 5,
                "status": "Failed" if weak_prng_detected else "Passed",
                "details": "Avoid weak hashing algorithms like MD5 or SHA-1 which are susceptible to collisions."
            }
        }
        
    def analyze_obfuscation_and_code_security(self,scan_response, scorecard_response, quark_result):
        """
        Analyze Obfuscation & Code Security aspects.
        """
        return {
            "code_obfuscation": {
                "score": 5 if scorecard_response.get("obfuscation_enabled") == "yes" else 0,
                "status": "Enabled" if scorecard_response.get("obfuscation_enabled") == "yes" else "Not Enabled",
                "details": "Code obfuscation techniques are implemented to protect against reverse engineering."
            }
        }

    def analyze_secure_key_management(self,scan_response, scorecard_response, quark_result):
        """
        Analyze Secure Key Management.
        """
        return {
            "server_side_key_management": {
                "score": 5 if scorecard_response.get("server_side_key_management") == "yes" else 0,
                "status": "Passed" if scorecard_response.get("server_side_key_management") == "yes" else "Failed",
                "details": "API keys are managed server-side, reducing the risk of exposure."
            }
        }

    def analyze_authentication_and_access_control(self, scan_response,scorecard_response, quark_result):
        """
        Analyze Authentication & Access Control aspects.
        """
        return {
            "token_based_authentication": {
                "score": 5 if scorecard_response.get("token_auth") == "yes" else 0,
                "status": "Passed" if scorecard_response.get("token_auth") == "yes" else "Failed",
                "details": "Token-based authentication (e.g., OAuth 2.0) is used to limit API key exposure."
            }
        }

    def analyze_monitoring_and_auditing(self,scan_response, scorecard_response, quark_result):
        """
        Analyze Monitoring & Auditing aspects.
        """
        return {
            "logging_api_key_usage": {
                "score": 5 if scorecard_response.get("logging_enabled") == "yes" else 0,
                "status": "Enabled" if scorecard_response.get("logging_enabled") == "yes" else "Not Enabled",
                "details": "Logging is enabled to monitor API key usage and detect potential abuse."
            }
        }

    def generate_recommendations(self, detailed_scores):
        """
        Generate a list of security recommendations based on detailed scores.
        """
        recommendations = []
        for category, criteria in detailed_scores.items():
            for criterion, details in criteria.items():
                if details['status'] == "Failed" or details['status'] == "Insecure":
                    recommendations.append({
                        "category": category,
                        "recommendation": details.get('details', 'Review and improve security practices.')
                    })
        return recommendations

    def count_hardcoded_keys(self, detailed_scores):
        """
        Count hardcoded keys based on detailed scores.
        """
        hardcoded_keys_count = 0
        for criteria in detailed_scores.get("Data Storage", {}).values():
            if "hardcoded keys" in criteria.get("details", "").lower():
                hardcoded_keys_count += 1
        return hardcoded_keys_count

    def extract_hardcoded_keys_from_mobsf(self, scan_response, scorecard_response):
        """
        Extract hardcoded API keys from MobSF's report.
        """
        hardcoded_keys = []
        secrets_section = [item for item in scorecard_response.get('warning', []) if item.get('title') == "This app may contain hardcoded secrets"]
        for secret in secrets_section:
            description = secret.get("description", "")
            matches = re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', description)
            for key, value in matches:
                hardcoded_keys.append({"key": key, "value": value, "source": "MobSF"})
        return hardcoded_keys

    def find_hardcoded_keys(self, scan_response,scorecard_response, jadx_output_dir):
        """
        Combine MobSF JSON data and JADX output to find hardcoded API keys.
        Returns a list of detected hardcoded keys with their details.
        """
        hardcoded_keys = []

        # Extract hardcoded secrets from MobSF JSON report
        mobsf_keys = self.extract_hardcoded_keys_from_mobsf(scorecard_response)
        hardcoded_keys.extend(mobsf_keys)

        # Define key patterns to search for in JADX decompiled code
        key_patterns = [
            r'AIza[0-9A-Za-z-_]{35}',  # Google API Key
            r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',  # Firebase Key
            r'pk_live_[0-9a-zA-Z]{24}',  # Stripe Live Key
            r'password\s*=\s*["\']([^"\']+)["\']',  # Generic password assignment
            r'username\s*=\s*["\']([^"\']+)["\']',  # Generic username assignment
        ]

        # Find hardcoded keys in JADX decompiled code
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

        # Consolidate findings from both MobSF and JADX for analysis
        consolidated_keys = self.consolidate_keys(hardcoded_keys)

        return consolidated_keys

    def consolidate_keys(self, hardcoded_keys):
        """
        Consolidate findings from MobSF and JADX to remove duplicates and provide comprehensive analysis.
        """
        consolidated = []
        seen_keys = set()

        for key_entry in hardcoded_keys:
            key_identifier = (key_entry.get("key"), key_entry.get("value"))
            if key_identifier not in seen_keys:
                seen_keys.add(key_identifier)
                consolidated.append(key_entry)
            else:
                # If duplicate found, append file paths to the existing entry for completeness
                for item in consolidated:
                    if item["key"] == key_entry["key"] and item["value"] == key_entry["value"]:
                        item["file"] = f'{item.get("file", "")}, {key_entry.get("file", "")}'

        return consolidated