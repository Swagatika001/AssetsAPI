from django.shortcuts import render
from django.conf import settings
import jwt
from .renderers import UserRenderer
from .serializers import (RegisterSerializer,EmailVerificationSerializer,LogoutSerializer,
    LoginSerializer,UserProfileSerializer,ResetPasswordEmailRequestSerializer,SetNewPasswordSerializer)
from rest_framework import generics, status, views, permissions
from .models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
#from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework import permissions

#jwt token creating manually

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class RegisterView(generics.GenericAPIView):
    renderer_classes = [UserRenderer]
    serializer_class=RegisterSerializer

    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data=serializer.data
        user=User.objects.get(email=user_data['email'])
        token=get_tokens_for_user(user)
        
        #This is emailverification while registering
        
        #token=RefreshToken.for_user(user).access_token
        #current_site=get_current_site(request).domain
        #relative_link=reverse('email-verify')
        #absurl="https://"+current_site+relative_link+'?token='+str(token)
        #email_body='Hi '+user.username + \
        #    ' Use the link below to verify your email \n' + absurl
        #data={
        #    'email_body':email_body,
        #    'to_email':user.email,
        #    'email_subject':'verify your email'
        #}
        
        #Util.send_email(data)

        return Response({'user_data':user_data,'token':token}, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    serializer_class=EmailVerificationSerializer

    token_param_config=openapi.Parameter('token',in_=openapi.IN_QUERY, 
    description='Description', type=openapi.TYPE_STRING)
    
    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self,request):
        token=request.GET.get('token')
        try:
            payload=jwt.decode(token,settings.SECRET_KEY)
            user=User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified=True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class=LoginSerializer
    renderer_classes = [UserRenderer]
    permission_classes = (permissions.IsAuthenticated,)

    def post(self,request):
        serializer=self.serializer_class(data=request.data)   
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class UserProfileAPIView(views.APIView):
    renderer_classes = [UserRenderer]
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class=UserProfileSerializer
    def get(self,request,format=None):
        serializer=self.serializer_class(request.user) 
        serialzer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    renderer_classes = [UserRenderer]
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class=ResetPasswordEmailRequestSerializer

    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        def validate(self,attrs):
            email=attrs.get('email','')
            if User.objects.filter(email=email).exists():
                email=User.objects.get(email=email)
                uidb64=urlsafe_base64_encode(smart_bytes(user.id))
                token=PasswordResetTokenGenerator.make_token(user)
                current_site = get_current_site(
                request=request).domain
                relativeLink = reverse('password-reset-confirm', 
                                    kwargs={'uidb64': uidb64, 'token': token})
                absurl = 'http://'+current_site + relativeLink
                email_body = 'Hello, \n Use link below to reset your password  \n' + absurl
                data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
                Util.send_email(data)
            return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPiView(generics.GenericAPIView):
    renderer_classes = [UserRenderer]
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class=SetNewPasswordSerializer
    def get(self,request,uidb64,token):
        try:
            id=smart_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error':'token is not valid...please reuest a new one'},status=status.HTTP_401_UNAUTHORIZED)
        
            return Response({'success':True,'message':'Credentials Valid','uidb64':uidb64,'token':token},status=status.HTTP_200_OK)

           
        except DjangoUnicodeDecodeError as identifier:
            return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(generics.GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    renderer_classes = [UserRenderer]
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class=LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)
    
    def post(self,request):
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

