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

class APKUploadView(APIView):
    def post(self, request, *args, **kwargs):
        # Handle APK file upload
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Save file temporarily to the media directory
        file_path = default_storage.save(file.name, file)
        abs_path = os.path.join(settings.MEDIA_ROOT, file_path)

        # Perform analysis with MobSF
        upload_response = self.upload_to_mobsf(abs_path, file.name)
        if "error" in upload_response:
            return Response(upload_response, status=status.HTTP_400_BAD_REQUEST)

        # Use the hash to perform the scan
        scan_response = self.scan_with_mobsf(upload_response['hash'])
        if "error" in scan_response:
            return Response(scan_response, status=status.HTTP_400_BAD_REQUEST)

        # Generate JSON report with MobSF
        json_report_response = self.generate_json_report(upload_response['hash'])
        if "error" in json_report_response:
            return Response(json_report_response, status=status.HTTP_400_BAD_REQUEST)

        # Decompile the APK using JADX
        jadx_result = self.decompile_with_jadx(abs_path)
        if "error" in jadx_result:
            return Response(jadx_result, status=status.HTTP_400_BAD_REQUEST)

        # Save analysis result to database (combined MobSF and JADX results)
        combined_result = {
            "mobsf_analysis": json_report_response,
            "jadx_decompilation": jadx_result
        }
        apk_analysis = APKAnalysis.objects.create(
            file_name=file.name,
            analysis_result=combined_result
        )
        serializer = APKAnalysisSerializer(apk_analysis)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

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
            # Handle any other errors
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
            # Handle any other errors
            return {"error": f"An exception occurred during file scan: {str(e)}"}

    def generate_json_report(self, file_hash):
        try:
            # Headers for MobSF API
            headers = {
                'Authorization': settings.MOBSF_API_KEY
            }

            # Generate JSON report API URL
            mobsf_json_report_url = f"{settings.MOBSF_API_URL}/api/v1/report_json"

            # Data for generating JSON report
            data = {
                'hash': file_hash
            }

            # Send request to MobSF to generate JSON report
            response = requests.post(mobsf_json_report_url, headers=headers, data=data)

            if response.status_code == 200:
                # Successful report generation - return JSON report details
                return response.json()
            else:
                # Handle error from MobSF API
                return {"error": f"MobSF API error during JSON report generation: {response.text}"}
        except Exception as e:
            # Handle any other errors
            return {"error": f"An exception occurred during JSON report generation: {str(e)}"}

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
                return {"status": "success", "message": f"Decompiled successfully to {output_dir}"}
            else:
                return {"error": f"JADX error: {result.stderr}"}
        except Exception as e:
            return {"error": f"An exception occurred during decompilation: {str(e)}"}
