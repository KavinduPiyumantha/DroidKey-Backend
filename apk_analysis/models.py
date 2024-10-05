from django.db import models

class APKAnalysis(models.Model):
    file_name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    analysis_result = models.TextField(blank=True, null=True)  # To store JSON or analysis details
    
    def __str__(self):
        return self.file_name
