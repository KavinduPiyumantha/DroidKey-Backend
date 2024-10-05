from django.urls import path
from .views import APKUploadView

urlpatterns = [
    path('upload-apk/', APKUploadView.as_view(), name='upload-apk'),  # Example endpoint for uploading APKs
]
