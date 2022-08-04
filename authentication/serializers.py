from rest_framework import serializers
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from .models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


class RegisterSerializer(serializers.ModelSerializer):

    password=serializers.CharField(max_length=120,min_length=6,write_only=True)
    #password2=serializers.CharField(style={'input_type':'password'},max_length=120,
                                #min_length=6,write_only=True)
    
    default_error_messages = {
        'username': 
            'The username should only contain alphabet characters'}

    
    class Meta:
        model=User
        fields=['email', 'username', 'password']
        #extra_kwargs={
        #    'password':{'write_only':True}
        #}

        def validate(self,attrs):
            username=attrs.get('username')
            email=attrs.get('email')
            #password=attrs.get('password')
            #password2=attrs.get('password2')

            if not username.isalnum():
                raise serializer.ValidationError(self.default_error_messages)

            #if password != password2:
            #    raise serializer.ValidationError("password and confirm password doesn't match")

            return attrs

        def create(self,validated_data):
            return User.objects.create_user(**validated_data)

class EmailVerificationSerializer(serializers.ModelSerializer):
    token=serializers.CharField(max_length=444)
    class Meta:
        model=User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(
        max_length=255, min_length=3, read_only=True)
    tokens = serializers.CharField(max_length=255,min_length=7,read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    
    
    def validate(self,attrs):
        email=attrs.get('email','')
        password=attrs.get('password','')
        user = auth.authenticate(email=email, password=password)
        
        
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'username': user.username,
            'token': user.tokens
        }

        return super().validate(attrs)


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','username','email']

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email=serializers.CharField(max_length=200)

    class Meta:
        fields=['email']

    
class SetNewPasswordSerializer(serializers.Serializer):
    password=serializers.CharField(min_length=6,max_length=255,write_only=True) 
    token=serializers.CharField(min_length=6,max_length=300,write_only=True) 
    uidb64=serializers.CharField(min_length=6,max_length=200,write_only=True)     

    class Meta:
        fiields=['password','token','uidb64']

    def validate(self,attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)
            

class LogoutSerializer(serializers.Serializer):
    refresh=serializers.CharField(max_length=222)

    default_error_message={
        'bad_token':'token is invalid'
    }

    def validate(self, attrs):
        self.token=attrs['refresh']
        return attrs

    def save(self,**kwargs):
        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')

