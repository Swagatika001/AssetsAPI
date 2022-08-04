from django.urls import path
from . import views


urlpatterns = [
    path('', views.AssetsListAPIView.as_view(), name="assetlist"),
    path('<int:id>', views.AssetsDetailAPIView.as_view(), name="assetsdetail"),
]