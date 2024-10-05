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
        analysis_result = self.analyze_with_mobsf(abs_path, file.name)

        # Save analysis result to database
        apk_analysis = APKAnalysis.objects.create(
            file_name=file.name,
            analysis_result=analysis_result
        )
        serializer = APKAnalysisSerializer(apk_analysis)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def analyze_with_mobsf(self, file_path, file_name):
        try:
            # Open the file from the media directory
            with open(file_path, 'rb') as f:
                files = {'file': (file_name, f, 'application/vnd.android.package-archive')}

                # Headers for MobSF API
                headers = {
                    # 'Authorization': "113ab90737077f3aa77a671febb83a892f2fb16b9f821b4e9ac8b5cc2da766bb"
                    'Authorization': settings.MOBSF_API_KEY
                }

                # MOBSF_API_URL = "http://mobsf:8000/api/v1/upload"

                # Send file to MobSF for analysis
                response = requests.post(settings.MOBSF_API_URL, files=files, headers=headers)

                if response.status_code == 200:
                    # Successful analysis - return analysis details
                    analysis_data = response.json()
                    return analysis_data
                else:
                    # Handle error from MobSF API
                    return {"error": f"MobSF API error: {response.text}"}
        except Exception as e:
            # Handle any other errors
            return {"error": f"An exception occurred: {str(e)}"}
