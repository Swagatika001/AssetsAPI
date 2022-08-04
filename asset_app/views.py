from django.shortcuts import render
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from .models import Assets,AssetsIssuance
from rest_framework import permissions
from .permissions import IsOwner
from .serializers import AssetsSerializer,AssetsIssuanceSerializer


class AssetsListAPIView(ListCreateAPIView):
    serializer_class = AssetsSerializer
    queryset = Assets.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)


class AssetsDetailAPIView(RetrieveUpdateDestroyAPIView):
    serializer_class = AssetsSerializer
    permission_classes = (permissions.IsAuthenticated, IsOwner,)
    queryset = Assets.objects.all()
    lookup_field = "id"

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)

