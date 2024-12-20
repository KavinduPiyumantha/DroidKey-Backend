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
import json
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
            logger.info(f"Quark result: {quark_result}")
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
            analysis_result = self.perform_security_analysis(abs_path,scan_response,scorecard_response, jadx_result['message'], quark_result)
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

    def perform_security_analysis(self, abs_path, scan_response, scorecard_response, jadx_output_dir, quark_result):
        logger.info(f"Security analysis STARTED")
        try:
            """
            Perform a comprehensive security analysis using MobSF report, JADX output, and Quark Engine results.
            Returns a detailed JSON result including each criterion's status.
            """
            detailed_scores = {}

            # Define criteria weights
            weights = {
                "Mobile Device Security": 15,
                "Data in Transit": 20,
                "Data Storage": 25,
                "Cryptographic Practices": 20,
                "Obfuscation & Code Security": 10,
                "Authentication & Access Control": 10
            }

            # Call sub-functions for each category
            detailed_scores["Mobile Device Security"] = self.analyze_mobile_device_security(scan_response, scorecard_response, quark_result)
            detailed_scores["Data in Transit"] = self.analyze_data_in_transit(scan_response, scorecard_response, quark_result)
            detailed_scores["Data Storage"] = self.analyze_data_storage(scan_response, scorecard_response, jadx_output_dir, quark_result)
            logger.info(f"Data Storage analysis COMPLETED")
            detailed_scores["Cryptographic Practices"] = self.analyze_cryptographic_practices(scan_response, scorecard_response, quark_result)
            detailed_scores["Obfuscation & Code Security"] = self.analyze_obfuscation_and_code_security(abs_path, scorecard_response, scan_response, quark_result)
            # Run authentication analysis (synchronous)
            auth_control_result = self.analyze_authentication_and_access_control(detailed_scores["Data Storage"])
            detailed_scores["Authentication & Access Control"] = auth_control_result

            logger.info(f"Mobile Device Security analysis : {detailed_scores['Mobile Device Security']}")
            logger.info(f"Authentication & Access Control analysis : {detailed_scores['Authentication & Access Control']}")

            # Ensure all criteria have 'status' key
            for category, criteria in detailed_scores.items():
                for criterion_name, criterion in criteria.items():
                    if 'status' not in criterion:
                        criterion['status'] = 'Unknown'

            # Calculate total weighted score
            final_score = 0
            total_weight = sum(weights.values())
            for category, criteria in detailed_scores.items():
                category_weight = weights.get(category, 0)
                max_category_score = len(criteria) * 5  # Assuming each criterion has a max score of 5
                category_score = sum(criterion.get('score', 0) for criterion in criteria.values())
                if max_category_score > 0:
                    # Normalize category score to its weight
                    weighted_category_score = (category_score / max_category_score) * category_weight
                else:
                    weighted_category_score = 0
                final_score += weighted_category_score

            logger.info(f"Final weighted score calculated: {final_score}")

            # Normalize final score to be out of 100
            final_score = (final_score / total_weight) * 100 if total_weight else 0
            logger.info(f"Security analysis COMPLETED with final score: {final_score}")

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
        except Exception as e:
            logger.error(f"Exception during security analysis: {str(e)}")
            return {"error": f"An exception occurred during security analysis: {str(e)}"}

    def analyze_mobile_device_security(self, scan_response, scorecard_response, quark_result):
        """
        Analyze Mobile Device Security aspects of the application using MobSF (scan and scorecard) and Quark results.
        """

        # Root Detection Analysis from MobSF Scorecard - "warning" and "secure" sections
        rooted_detection_mobsf = (
            scorecard_response.get("root_detection") == "passed" or
            any(
                warning.get("title") == "This App may have root detection capabilities."
                for warning in scorecard_response.get("warning", [])
            ) or
            any(
                secure.get("title") == "This App may have root detection capabilities."
                for secure in scorecard_response.get("secure", [])
            )
        )

        # Root Detection Analysis from MobSF Scan (updated hierarchy)
        rooted_detection_mobsf_scan = (
            "android_detect_root" in scan_response.get("code_analysis", {}).get("findings", {}) and
            scan_response["code_analysis"]["findings"]["android_detect_root"].get("files")
        )

        # Root Detection Analysis from Quark
        rooted_detection_quark = any(
            rule["rule_name"].lower() == "detect rooted device" and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )

        # Final Root Detection - True if detected by MobSF (scorecard or scan) or Quark
        rooted_detection = rooted_detection_mobsf or rooted_detection_mobsf_scan or rooted_detection_quark

        # Emulator Detection Analysis from MobSF Scorecard
        emulator_detection_mobsf = scorecard_response.get("emulator_detection") == "passed"

        # Emulator Detection Analysis from Quark
        emulator_detection_quark = any(
            rule["rule_name"].lower() == "emulator detection" and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )

        # Final Emulator Detection - True if detected by MobSF or Quark
        emulator_detection = emulator_detection_mobsf or emulator_detection_quark

        # Prepare the analysis result for Mobile Device Security
        return {
            "Prevent Rooted Device Access": {
                "score": 5 if rooted_detection else 0,
                "status": "Passed" if rooted_detection else "Failed",
                "details": "Application has root detection mechanisms implemented to prevent operation on rooted devices."
                        # f" MobSF Scorecard: {'Yes' if rooted_detection_mobsf else 'No'},"
                        # f" MobSF Scan: {'Yes' if rooted_detection_mobsf_scan else 'No'},"
                        # f" Quark: {'Yes' if rooted_detection_quark else 'No'}."
            },
            # "Disable Emulator Access": {
            #     "score": 5 if emulator_detection else 0,
            #     "status": "Passed" if emulator_detection else "Failed",
            #     "details": "Emulator detection is in place to restrict access when running on emulators."
            #             # f" MobSF: {'Yes' if emulator_detection_mobsf else 'No'},"
            #             # f" Quark: {'Yes' if emulator_detection_quark else 'No'}."
            # }
        }

    def analyze_data_in_transit(self, scan_response, scorecard_response, quark_result):
        """
        Analyze Data in Transit security aspects using MobSF (scan and scorecard) and Quark results.
        """
        
        # HTTPS Enforcement Analysis from MobSF Scorecard - "secure" section
        https_enforced_mobsf = (
            scorecard_response.get("uses_https") == "yes" or
            any(
                secure.get("title") == "This App uses SSL certificate pinning to detect or  prevent MITM attacks in secure communication channel."
                for secure in scorecard_response.get("secure", [])
            )
        )

        # HTTPS Enforcement Analysis from MobSF Scan (updated hierarchy)
        https_enforced_mobsf_scan = (
            "android_ssl_pinning" in scan_response.get("code_analysis", {}).get("findings", {}) and
            scan_response["code_analysis"]["findings"]["android_ssl_pinning"].get("files")
        )

        # HTTPS Enforcement Analysis from Quark
        https_enforced_quark = any(
            rule["rule_name"].lower() == "https enforcement" and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )

        # Final HTTPS Enforcement - True if detected by MobSF (scorecard or scan) or Quark
        https_enforced = https_enforced_mobsf or https_enforced_mobsf_scan or https_enforced_quark

        # Plaintext Transmission Prevention Analysis from MobSF Scorecard
        plaintext_transmission_prevented_mobsf = scorecard_response.get("prevent_plaintext_transmission") == "yes"

        # Plaintext Transmission Prevention Analysis from Quark
        plaintext_transmission_prevented_quark = not any(
            rule["rule_name"].lower() == "detect plaintext transmission" and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )

        # Final Plaintext Transmission Prevention - True if detected by MobSF or Quark
        plaintext_transmission_prevented = plaintext_transmission_prevented_mobsf or plaintext_transmission_prevented_quark

        # Prepare the analysis result for Data in Transit Security
        return {
            "HTTPS Enforcement": {
                "score": 5 if https_enforced else 0,
                "status": "Passed" if https_enforced else "Failed",
                "details": "HTTPS is enforced to ensure all communication is encrypted."
                        # f" MobSF Scorecard: {'Yes' if https_enforced_mobsf else 'No'},"
                        # f" MobSF Scan: {'Yes' if https_enforced_mobsf_scan else 'No'},"
                        # f" Quark: {'Yes' if https_enforced_quark else 'No'}."
            },
            "Prevent Plaintext Transmission": {
                "score": 5 if plaintext_transmission_prevented else 0,
                "status": "Passed" if plaintext_transmission_prevented else "Failed",
                "details": "Sensitive data is not transmitted in plaintext, ensuring secure communication."
                        # f" MobSF: {'Yes' if plaintext_transmission_prevented_mobsf else 'No'},"
                        # f" Quark: {'Yes' if plaintext_transmission_prevented_quark else 'No'}."
            }
        }

    def analyze_data_storage(self, scan_response, scorecard_response, jadx_output_dir, quark_result):
        """
        Analyze Data Storage aspects using MobSF, JADX, and Quark results with a focus on key criteria.
        """
        # Collect all the hardcoded secrets from scan_response, JADX, and MobSF reports
        # hardcoded_keys_scan = self.extract_secrets_from_scan_response(scan_response)
        hardcoded_keys_jadx = self.find_hardcoded_keys(scan_response, scorecard_response, jadx_output_dir)
        # hardcoded_keys_mobsf = self.extract_hardcoded_keys_from_mobsf( scorecard_response)
        hardcoded_keys_quark = [
            item for rule in quark_result.get("rules", [])
            if "hardcoded" in rule["rule_name"].lower() and rule["behavior_occurrences"]
            for item in rule["behavior_occurrences"]
        ]

        # External Storage Usage Analysis using scorecard_response
        external_storage_risk_mobsf = any(
            warning.get('title') == "App can read/write to External Storage. Any App can read data written to External Storage."
            for warning in scorecard_response.get('warning', [])
        )

        # # Secure Storage Mechanism Analysis (MobSF or Quark Results)
        # secure_storage_mechanism_detected = scorecard_response.get("secure_storage") == "yes" or any(
        #     rule["rule_name"].lower() == "secure storage mechanism" and rule["behavior_occurrences"]
        #     for rule in quark_result.get("rules", [])
        # )

        # Strong Encryption for Locally Stored Data Analysis
        encryption_algorithm = scorecard_response.get("encryption_algorithm", "").lower()
        strong_encryption_detected = encryption_algorithm == "aes-256"  # Example of a strong encryption algorithm

        return {
            # # Check for the use of secure storage mechanisms like Android Keystore
            # "use_secure_storage_mechanism": {
            #     "score": 5 if secure_storage_mechanism_detected else 0,
            #     "status": "Passed" if secure_storage_mechanism_detected else "Failed",
            #     "details": "The application uses secure storage mechanisms like Android Keystore to protect API keys and sensitive data."
            #             f" MobSF: {'Yes' if secure_storage_mechanism_detected else 'No'}."
            # },
            # Check to avoid storing sensitive data in external storage
            "Avoid Storing Sensitive Data in External Storage": {
                "score": 5 if not external_storage_risk_mobsf else 0,
                "status": "Passed" if not external_storage_risk_mobsf else "Failed",
                "details": "Application does not store sensitive data in external storage, which reduces exposure risk."
                        # f" MobSF: {'Yes' if external_storage_risk_mobsf else 'No'}."
            },
            # Check for strong encryption for locally stored data
            "Strong Encryption for Locally Stored Data": {
                "score": 5 if strong_encryption_detected else 0,
                "status": "Passed" if strong_encryption_detected else "Failed",
                "details": f"Application uses {'strong encryption (AES-256)' if strong_encryption_detected else 'weak or no encryption'} for locally stored data."
            },
            # Hardcoded keys check across MobSF, JADX, and Quark, as well as scan response secrets
            # "no_hardcoded_keys": {
            #     "score": 5 if not hardcoded_keys_scan and not hardcoded_keys_jadx and not hardcoded_keys_mobsf and not hardcoded_keys_quark else 0,
            #     "status": "Passed" if not hardcoded_keys_scan and not hardcoded_keys_jadx and not hardcoded_keys_mobsf and not hardcoded_keys_quark else "Failed",
            #     "details": f"Hardcoded keys found: {hardcoded_keys_jadx}" if hardcoded_keys_scan or hardcoded_keys_jadx or hardcoded_keys_mobsf or hardcoded_keys_quark else "No hardcoded API keys found."
            # },
            "No Hardcoded Keys": {
                "score": 5 if not hardcoded_keys_jadx and not hardcoded_keys_quark else 0,
                "status": "Passed" if not hardcoded_keys_jadx and not hardcoded_keys_quark else "Failed",
                "details": f"Hardcoded keys found:" if hardcoded_keys_jadx or hardcoded_keys_quark else "No hardcoded API keys found.",
                "keys": hardcoded_keys_jadx
            },
            
        }

    def analyze_cryptographic_practices(self, scan_response, scorecard_response, quark_result):
        """
        Analyze Cryptographic Practices using MobSF, Scorecard, and Quark results.
        """
        # Analyze insecure random number generator usage based on scan response, scorecard response, and Quark
        insecure_rng_detected_scan = "android_insecure_random" in scan_response.get("code_analysis", {}).get("findings", {})
        insecure_rng_detected_scorecard = any(
            warning.get("title") == "The App uses an insecure Random Number Generator."
            for warning in scorecard_response.get("warning", [])
        )
        insecure_rng_detected_quark = any(
            rule["rule_name"].lower() == "use weak prng" and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )
        insecure_rng_detected = insecure_rng_detected_scan or insecure_rng_detected_scorecard or insecure_rng_detected_quark

        # Analyze weak hashing usage (e.g., MD5, SHA-1) from MobSF warnings
        weak_hashing_detected_scorecard = any(
            warning.get("title") in ["MD5 is a weak hash known to have hash collisions.", "SHA-1 is a weak hash known to have hash collisions."]
            for warning in scorecard_response.get("warning", [])
        )
        weak_hashing_detected_quark = any(
            rule["rule_name"].lower() in ["use md5", "use sha-1"] and rule["behavior_occurrences"]
            for rule in quark_result.get("rules", [])
        )
        weak_hashing_detected_scan = any(
            key == "android_md5" for key in scan_response.get("code_analysis", {}).get("findings", {})
        )
        weak_hashing_detected = weak_hashing_detected_scorecard or weak_hashing_detected_quark or weak_hashing_detected_scan

        # Determine encryption strength (MobSF scorecard or other sources)
        encryption_algorithm = scorecard_response.get("encryption_algorithm", "").lower()
        strong_encryption_detected = encryption_algorithm == "aes-256"  # Example of a strong encryption algorithm

        return {
            "Use Strong Encryption": {
                "score": 5 if strong_encryption_detected else 0,
                "status": "Secure" if strong_encryption_detected else "Insecure",
                "details": "The application uses AES-256 for encryption, which is considered secure." if strong_encryption_detected else "The application does not use strong encryption for local storage."
            },
            "Avoid Weak Hashing Algorithms": {
                "score": 0 if weak_hashing_detected else 5,
                "status": "Failed" if weak_hashing_detected else "Passed",
                "details": "The application uses a weak hashing algorithm (MD5, SHA-1) which is susceptible to hash collisions." if weak_hashing_detected else "No weak hashing algorithms detected."
            },
            "Avoid Insecure Random Number Generators": {
                "score": 0 if insecure_rng_detected else 5,
                "status": "Failed" if insecure_rng_detected else "Passed",
                "details": "The application uses an insecure Random Number Generator, which is susceptible to predictability and security vulnerabilities." if insecure_rng_detected else "No insecure Random Number Generators detected."
            }
        }
        
    def analyze_obfuscation_and_code_security(self, apk_path, scorecard_response, scan_response, quark_result):
        """
        Analyze Obfuscation & Code Security aspects using MobSF, Quark, APKiD results, and Scan response.
        """
        obfuscation_detected = False
        shrink_detected = False
        apkid_result = None
        debugging_disabled = True  # Assume debugging is disabled unless detected otherwise

        try:
            # Run APKiD on the APK file and get the output in JSON format
            result = subprocess.run(['apkid', '-j', apk_path], capture_output=True, text=True)
            apkid_result = json.loads(result.stdout)
            logger.info(f"APKiD result: {apkid_result}")

            # Check if obfuscation or shrink was detected in the APKiD results
            for file_entry in apkid_result.get('files', []):
                detections = file_entry.get('matches', {})

                # Check for "compiler" matches that indicate shrinking or obfuscation
                if "compiler" in detections:
                    for compiler in detections["compiler"]:
                        if "r8" in compiler.lower() or "proguard" in compiler.lower():
                            shrink_detected = True
                            obfuscation_detected = True

                # Check for "anti_vm" or other detections indicating anti-analysis techniques
                if "anti_vm" in detections:
                    obfuscation_detected = True

        except Exception as e:
            # Handle the case if APKiD execution fails
            print(f"Error running APKiD: {str(e)}")
            apkid_result = {"error": str(e)}

        # Use MobSF scorecard to also determine obfuscation (existing logic)
        mobsf_obfuscation = scorecard_response.get("obfuscation_enabled") == "yes"
        obfuscation_detected = obfuscation_detected or mobsf_obfuscation

        # Check for debugging settings using scorecard_response
        debug_enabled_issues = [item for item in scorecard_response.get('high', []) if (item.get('title') == "Debug Enabled For App" or item.get('title') == "Debug configuration enabled. Production builds must not be debuggable.")]
        if debug_enabled_issues:
            debugging_disabled = False

        # Ensure debugging status is returned correctly
        debug_score = 0 if not debugging_disabled else 5
        debug_status = "Enabled" if not debugging_disabled else "Disabled"
        debug_details = (
            "Debugging is enabled, which can expose the app to reverse engineering."
            if not debugging_disabled
            else "Debugging is disabled, which helps prevent attackers from analyzing the app behavior and extracting sensitive data."
        )
        
        return {
            "Code Obfuscation & Shrinking": {
                "score": 5 if obfuscation_detected and shrink_detected else 0,
                "status": "Enabled" if obfuscation_detected and shrink_detected else "Not Enabled",
                "details": "Code obfuscation and shrinking techniques are implemented to protect against reverse engineering and reduce code size." if obfuscation_detected and shrink_detected else "No obfuscation or shrinking techniques detected."
            },
            "Debugging Disabled": {
                "score": debug_score,
                "status": debug_status,
                "details": debug_details
            }
        }
        
    def analyze_authentication_and_access_control(self, data_storage_results):
        logger.info(f"Authentication & Access Control analysis STARTED")
        """
        Analyze Authentication & Access Control aspects using the hardcoded keys found in Data Storage analysis.
        """
        hardcoded_keys = data_storage_results.get("No Hardcoded Keys", {}).get("keys", [])
        google_key_results = []

        try:
            logger.info(f"Hardcoded keys found: {hardcoded_keys}")
            # Validate each Google API key found
            for key_entry in hardcoded_keys:
                key_value = key_entry.get("key", "")
                if re.match(r'AIza[0-9A-Za-z-_]{35}', key_value):
                    is_restricted = self.validate_google_api_key(key_value)
                    logger.info(f"Validating Google API key Completed for {key_value} with is_restricted: {is_restricted}")
                    if is_restricted is True:
                        google_key_results.append({
                            "key": key_value,
                            "status": "Restricted",
                            "details": "Restrictions are enabled for this Google API key."
                        })
                    elif is_restricted is False:
                        google_key_results.append({
                            "key": key_value,
                            "status": "Unrestricted",
                            "details": "Restrictions are NOT enabled for this Google API key."
                        })
                    else:
                        google_key_results.append({
                            "key": key_value,
                            "status": "Unknown",
                            "details": "Unable to determine if restrictions are enabled for this Google API key."
                        })

            # Check if there are any Google API keys to analyze
            if google_key_results:
                # If there are Google API keys analyzed, determine score and status
                all_restricted = all(key.get("status") == "Restricted" for key in google_key_results)
                score = 5 if all_restricted else 0
                status = "Passed" if all_restricted else "Failed"
            else:
                # If there are no Google API keys, set score and status accordingly
                score = 5
                status = "No Keys Found"

            # Generate results for Authentication & Access Control
            logger.info(f"Authentication & Access Control analysis COMPLETED")
            return {
                "Google API Key Restrictions": {
                    "score": score,
                    "status": status,
                    "details": google_key_results if google_key_results else "No Google API keys found for analysis."
                }
            }
            
        except Exception as e:
            logger.error(f"Exception during Authentication & Access Control analysis: {str(e)}")
            return {
                "Google API Key Restrictions": {
                    "score": 0,
                    "status": "Failed",
                    "details": f"An error occurred during analysis: {str(e)}"
                }
            }

    def generate_recommendations(self, detailed_scores):
        """
        Generate a list of security recommendations based on detailed scores.
        """
        recommendations = []
        for category, criteria in detailed_scores.items():
            for criterion, details in criteria.items():
                if details['status'] in ["Failed", "Insecure"]:
                    # Provide detailed recommendation based on criterion
                    if category == "Mobile Device Security":
                        if criterion == "Prevent Rooted Device Access":
                            recommendation = "Implement root detection mechanisms to prevent the app from running on rooted or jailbroken devices."
                        else:
                            recommendation = "Review and improve security practices related to mobile device security."
                    elif category == "Data in Transit":
                        if criterion == "HTTPS Enforcement":
                            recommendation = "Ensure that all network communication uses HTTPS to protect data in transit."
                        elif criterion == "Prevent Plaintext Transmission":
                            recommendation = "Avoid transmitting sensitive data in plaintext; use encryption protocols instead."
                        else:
                            recommendation = "Review and improve data in transit security practices."
                    elif category == "Data Storage":
                        if criterion == "Avoid Storing Sensitive Data in External Storage":
                            recommendation = "Refrain from storing sensitive data on external storage where it can be accessed by other apps."
                        elif criterion == "Strong Encryption for Locally Stored Data":
                            recommendation = "Use strong encryption algorithms like AES-256 to secure locally stored data."
                        elif criterion == "No Hardcoded Keys":
                            recommendation = "Remove hardcoded keys from the source code and retrieve them securely at runtime."
                        else:
                            recommendation = "Review and improve data storage security practices."
                    elif category == "Cryptographic Practices":
                        if criterion == "Use Strong Encryption":
                            recommendation = "Ensure that strong encryption algorithms are used for all cryptographic operations."
                        elif criterion == "Avoid Weak Hashing Algorithms":
                            recommendation = "Replace weak hashing algorithms like MD5 or SHA-1 with stronger ones like SHA-256."
                        elif criterion == "Avoid Insecure Random Number Generators":
                            recommendation = "Use secure random number generators provided by the platform's security library."
                        else:
                            recommendation = "Review and improve cryptographic practices."
                    elif category == "Obfuscation & Code Security":
                        recommendation = "Review and improve obfuscation and code security practices."
                    elif category == "Authentication & Access Control":
                        if criterion == "Google API Key Restrictions":
                            recommendation = "Restrict Google API keys to authorized domains or IP addresses to prevent unauthorized use."
                        else:
                            recommendation = "Review and improve authentication and access control practices."
                    else:
                        recommendation = "Review and improve security practices."

                    recommendations.append({
                        "category": category,
                        "criterion": criterion,
                        "recommendation": recommendation
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

    def extract_secrets_from_scan_response(self, scan_response):
        """
        Extract hardcoded secrets from scan_response.
        """
        hardcoded_keys = []
        secrets = scan_response.get("secrets", [])
        for secret in secrets:
            hardcoded_keys.append({
                "key": secret
            })
            
        return hardcoded_keys

    # def extract_hardcoded_keys_from_mobsf(self, scorecard_response):
    #     """
    #     Extract hardcoded API keys from MobSF's report.
    #     """
    #     hardcoded_keys = []
    #     secrets_section = [item for item in scorecard_response.get('warning', []) if item.get('title') == "This app may contain hardcoded secrets"]
    #     for secret in secrets_section:
    #         description = secret.get("description", "")
    #         matches = re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', description)
    #         for key, value in matches:
    #             hardcoded_keys.append({"key": key, "value": value, "source": "MobSF"})
    #     return hardcoded_keys

    def find_hardcoded_keys(self, scan_response, scorecard_response, jadx_output_dir):
        """
        Combine MobSF JSON data, Scan Response data, and JADX output to find hardcoded API keys.
        Returns a list of detected hardcoded keys with their details.
        """
        hardcoded_keys = []

        # Extract hardcoded secrets from MobSF JSON report and scan response
        # mobsf_keys = self.extract_hardcoded_keys_from_mobsf(scorecard_response)
        scan_keys = self.extract_secrets_from_scan_response(scan_response)
        # hardcoded_keys.extend(mobsf_keys)
        hardcoded_keys.extend(scan_keys)

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

        # Consolidate findings from MobSF, Scan Response, and JADX for analysis
        logger.info(f"Hardcoded keys found: {hardcoded_keys}")
        consolidated_keys = self.consolidate_keys(hardcoded_keys)
        return consolidated_keys

    def consolidate_keys(self, hardcoded_keys):
        """
        Consolidate findings from MobSF, Scan Response, and JADX to remove duplicates and provide comprehensive analysis.
        """
        consolidated = []
        seen_keys = {}

        for key_entry in hardcoded_keys:
            key_str = key_entry.get("key")
            
            # Extract only the value from the key string
            if ":" in key_str:
                key_value = key_str.split(":", 1)[1].strip().strip('"').strip("'")
            else:
                key_value = key_str.strip().strip('"').strip("'")

            # Check if this key has been seen before
            if key_value not in seen_keys:
                # Add the key to seen_keys and consolidated list
                seen_keys[key_value] = {
                    "key": key_value,
                    "file": key_entry.get("file", "")
                }
                consolidated.append(seen_keys[key_value])
            else:
                # If the key already exists, append file paths for completeness
                existing_entry = seen_keys[key_value]
                existing_entry["file"] = f'{existing_entry.get("file", "")}, {key_entry.get("file", "")}'

        return consolidated
    
    def validate_google_api_key(self, api_key):
        logger.info(f"Validating Google API key STARTED for key: {api_key}")
        """
        Check if Google API key is restricted or not.
        :param api_key: The Google API key to be validated.
        :return: Boolean indicating if the key has restrictions enabled.
        """
        try:
            # Using Google Maps Geocode API to test the API key
            url = f"https://maps.googleapis.com/maps/api/geocode/json?address=12,+bond+street,+Ringwood,+VICTORIA,+postcode,+AUSTRALIA&key={api_key}"
            
            # Send request to Google Maps Geocode API to validate the key
            response = requests.get(url, timeout=10)  # Set a timeout to avoid hanging indefinitely
            response_data = response.json()

            # Check for the response status
            if response.status_code == 200:
                # Determine if restrictions are enabled based on the response
                if response_data.get('status') == "REQUEST_DENIED" and "not authorized" in response_data.get("error_message", "").lower():
                    logger.info(f"API key {api_key} is restricted.")
                    return True  # Restrictions are enabled
                elif response_data.get('status') == "OK":
                    logger.info(f"API key {api_key} is unrestricted.")
                    return False  # Restrictions are not enabled
                else:
                    # Handle other cases such as limit exceeded or other request issues
                    logger.warning(f"Unexpected response while validating Google API key: {response_data}")
                    return None
            else:
                # Handle error cases
                logger.error(f"Failed to validate Google API key. Status code: {response.status_code}, Response: {response.text}")
                return None

        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout error while validating Google API key: {str(e)}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Network-related error while validating Google API key: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Exception occurred while validating Google API key: {str(e)}")
            return None