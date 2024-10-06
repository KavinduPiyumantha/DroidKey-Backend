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

        # Perform analysis with MobSF - upload APK
        upload_response = self.upload_to_mobsf(abs_path, file.name)
        if "error" in upload_response:
            return Response(upload_response, status=status.HTTP_400_BAD_REQUEST)

        # Perform scan with MobSF using the hash obtained
        scan_response = self.scan_with_mobsf(upload_response['hash'])
        if "error" in scan_response:
            return Response(scan_response, status=status.HTTP_400_BAD_REQUEST)

        # Generate JSON report with MobSF using the hash
        json_report_response = self.generate_json_report(upload_response['hash'])
        if "error" in json_report_response:
            return Response(json_report_response, status=status.HTTP_400_BAD_REQUEST)

        # Save analysis result to database
        apk_analysis = APKAnalysis.objects.create(
            file_name=file.name,
            analysis_result=json_report_response
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

            # JSON Report API URL
            json_report_url = f"{settings.MOBSF_API_URL}/api/v1/report_json"

            # Data to request JSON report
            data = {
                'hash': file_hash
            }

            # Send request to MobSF to generate the JSON report
            response = requests.post(json_report_url, headers=headers, data=data)

            if response.status_code == 200:
                # Successful response - return the JSON report
                return response.json()
            else:
                # Handle error from MobSF API
                return {"error": f"MobSF API error during JSON report generation: {response.text}"}
        except Exception as e:
            # Handle any other errors
            return {"error": f"An exception occurred during JSON report generation: {str(e)}"}
