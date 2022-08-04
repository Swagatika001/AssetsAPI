from rest_framework import serializers
from .models import Assets,AssetsIssuance


class AssetsSerializer(serializers.ModelSerializer):

    class Meta:
        model = Assets
        fields = ['id', 'asset_name','asset_serial_No',
                 'asset_manufacturer','date_purchased','asset_issued','asset_image']


class AssetsIssuanceSerializer(serializers.ModelSerializer):

    class Meta:
        model = AssetsIssuance
        fields = ['asset','asset_location','date_issued','asset_assignee']