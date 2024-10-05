from rest_framework import serializers
from .models import APKAnalysis

class APKAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = APKAnalysis
        fields = '__all__'
