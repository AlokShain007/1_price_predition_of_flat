from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import View
from django.shortcuts import render, redirect
from django.contrib import messages
from serializers import *
from .forms import PasswordResetForm, SetPasswordForm
from myapp.models import RealEstateListing
from joblib import load
import numpy as np
import os
import joblib
from random import randint
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.http import HttpResponse
from rest_framework.decorators import permission_classes

User = get_user_model()

# Define the path to the directory containing the trained model
model_directory = '/Users/administrator/Desktop/price/mypro/savedmodels'
model_file_path = os.path.join(model_directory, 'model.joblib')

# Load the trained model
model = joblib.load(model_file_path)
 

class OutputView(generics.GenericAPIView):
    serializer_class = RealEstateListingSerializer

    def get(self, request):
        return render(request, "output.html")


class HomePageView(generics.GenericAPIView):
    def get(self, request):
        return render(request, 'home.html')


class PredictView(generics.GenericAPIView):
    def get(self, request):
        return render(request, 'predict.html')


# class PredictionView(generics.GenericAPIView):
#     serializer_class = RealEstateListingSerializer

#     @swagger_auto_schema(request_body=RealEstateListingSerializer, responses={200: openapi.Schema(
#         type=openapi.TYPE_OBJECT,
#         properties={
#             'predicted_price': openapi.Schema(type=openapi.TYPE_NUMBER),
#         }
#     )})
#     def post(self, request):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         total_area = serializer.validated_data['total_area']
#         total_rooms = serializer.validated_data['total_rooms']
#         bhk = serializer.validated_data['bhk']
#         city = serializer.validated_data['city']

#         # Perform data validation
#         if not total_area or not total_rooms or not bhk or not city:
#             return Response({'error': 'Please fill in all the fields'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             total_area = float(total_area)
#             total_rooms = int(total_rooms)
#             bhk = int(bhk)

#             # Perform one-hot encoding of the selected city
#             cities = ['Bangalore', 'Chennai', 'Hyderabad', 'Kolkata', 'Mumbai', 'New Delhi', 'Pune']
#             encoded_city = [1 if c == city else 0 for c in cities]

#             input_data = np.array([[total_area, total_rooms, bhk] + encoded_city])

#             # Make the prediction using the loaded model
#             predicted_price = model.predict(input_data)[0]

#             return Response({'predicted_price': predicted_price}, status=status.HTTP_200_OK)

#         except ValueError:
#             return Response({'error': 'Invalid input. Please enter valid values'}, status=status.HTTP_400_BAD_REQUEST)

import numpy as np
import joblib
from rest_framework import generics, status
from rest_framework.response import Response
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from django.contrib.auth.decorators import login_required
model_directory = '/Users/administrator/Desktop/price/mypro/savedmodels'
model_file_path = os.path.join(model_directory, 'model.joblib')
model = joblib.load(model_file_path)

class PredictionView(generics.GenericAPIView):
    serializer_class = RealEstateListingSerializer

    @swagger_auto_schema(request_body=RealEstateListingSerializer, responses={200: openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'predicted_price': openapi.Schema(type=openapi.TYPE_NUMBER),
        }
    )})
    def post(self, request):
        bedroom = int(request.data.get('bedroom'))
        bathroom = int(request.data.get('bathroom'))
        sqft_living = int(request.data.get('sqft_living'))
        sqft_lot = int(request.data.get('sqft_lot'))
        floors = int(request.data.get('floors'))
        waterfront = int(request.data.get('waterfront'))

        # Perform data validation
        if any(value is None for value in [bedroom, bathroom, sqft_living, sqft_lot, floors, waterfront]):
            return Response({'error': 'Please fill in all the fields'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            input_data = np.array([[bedroom, bathroom, sqft_living, sqft_lot, floors, waterfront]])

            # Make the prediction using the loaded model
            price = model.predict(input_data)[0]

            return Response({'predicted_price': price}, status=status.HTTP_200_OK)

        except ValueError:
            return Response({'error': 'Invalid input. Please enter valid values'}, status=status.HTTP_400_BAD_REQUEST)

class SignupView(generics.CreateAPIView):
    serializer_class = SignupSerializer
    permission_classes = [permissions.AllowAny]


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=LoginSerializer, responses={200: openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'message': openapi.Schema(type=openapi.TYPE_STRING),
        }
    )})
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return Response({'message': 'User logged in successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)




class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(responses={200: openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'message': openapi.Schema(type=openapi.TYPE_STRING),
        }
    )})
    def post(self, request):
        logout(request)
        return Response({'message': 'User logged out successfully'}, status=status.HTTP_200_OK)


class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=PasswordResetSerializer, responses={200: openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'message': openapi.Schema(type=openapi.TYPE_STRING),
        }
    )})
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        users = User.objects.filter(email=email)
        user_count = users.count()

        if user_count == 0:
            return Response({'error': 'User with the provided email address does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
        elif user_count == 1:
            user = users.first()
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = request.build_absolute_uri(f"/reset-password/{email}/{uid}/{token}/")

            otp = generate_otp()

            request.session['otp'] = otp
            request.session['reset_email'] = email

            send_otp_email(email, otp)

            return Response({'message': 'OTP has been sent to your email. Please enter it to reset your password.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Multiple users found with the provided email address. Please contact support.'}, status=status.HTTP_400_BAD_REQUEST)


from rest_framework import generics, permissions, status
from rest_framework.response import Response

class OtpVerificationView(generics.GenericAPIView):
    serializer_class = OtpVerificationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        otp = serializer.validated_data.get('otp')

        # Check if the email or OTP is empty
        if not email or not otp:
            return Response({'error': 'Please provide both email and OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if 'otp' in request.session and 'reset_email' in request.session:
            saved_otp = request.session['otp']
            saved_email = request.session['reset_email']

            if email == saved_email and otp == saved_otp:
                return Response({'message': 'OTP verification successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'OTP session data not found. Please restart the password reset process.'}, status=status.HTTP_400_BAD_REQUEST)




class ResetPasswordView(generics.GenericAPIView):
    serializer_class = SetPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, email):
        user = User.objects.filter(email=email).first()

        if user:
            serializer = self.get_serializer(user, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            # Clear the OTP session data after password reset
            request.session.pop('otp', None)
            request.session.pop('reset_email', None)

            return Response({'message': 'Your password has been reset successfully. You can now login with your new password.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid password reset link.'}, status=status.HTTP_400_BAD_REQUEST)




def send_otp_email(email, otp):
    subject = 'OTP Verification'
    message = f'Your OTP for password reset is: {otp}'
    email_from = 'abhishek.prasad@indicchain.com'
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)


def generate_otp():
    return str(randint(100000, 999999))


class HomePage(generics.GenericAPIView):
    def get(self, request):
        return render(request, 'home.html')


class PredictView(generics.GenericAPIView):
    def get(self, request):
        return render(request, 'predict.html')

class PredictionView(generics.GenericAPIView):
    serializer_class = RealEstateListingSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        total_area = serializer.validated_data.get('total_area')
        total_rooms = serializer.validated_data.get('total_rooms')
        bhk = serializer.validated_data.get('bhk')
        city = serializer.validated_data.get('city')

        # Perform data validation
        if not total_area or not total_rooms or not bhk or not city:
            return Response({'error': 'Please provide all the required fields'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            total_area = float(total_area)
            total_rooms = int(total_rooms)
            bhk = int(bhk)

            # Perform one-hot encoding of the selected city
            cities = ['Bangalore', 'Chennai', 'Hyderabad', 'Kolkata', 'Mumbai', 'New Delhi', 'Pune']
            encoded_city = [1 if c == city else 0 for c in cities]

            input_data = np.array([[total_area, total_rooms, bhk] + encoded_city])

            # Make the prediction using the loaded model
            predicted_price = model.predict(input_data)[0]

            return Response({'predicted_price': predicted_price}, status=status.HTTP_200_OK)

        except ValueError:
            return Response({'error': 'Invalid input. Please provide valid values'}, status=status.HTTP_400_BAD_REQUEST)



class SignupView(generics.GenericAPIView):
    serializer_class = SignupSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        # Check if the username is empty
        if not username:
            return Response({'error': 'Please provide a username'}, status=status.HTTP_400_BAD_REQUEST)

        # Create the user
        try:
            user = User.objects.create_user(username=username, email=email, password=password)
            return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        except:
            return Response({'error': 'Failed to create user'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]
    
    def get(request):
        return render('login.html')

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')

        # Check if the username is empty
        if not username:
            return Response({'error': 'Please provide a username'}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return Response({'message': 'User logged in successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)



class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({'message': 'User logged out successfully'}, status=status.HTTP_200_OK)



class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')

        # Check if the email is empty
        if not email:
            return Response({'error': 'Please provide an email address'}, status=status.HTTP_400_BAD_REQUEST)

        users = User.objects.filter(email=email)
        user_count = users.count()

        if user_count == 0:
            return Response({'error': 'User with the provided email address does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
        elif user_count == 1:
            user = users.first()
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = request.build_absolute_uri(f"/reset-password/{email}/{uid}/{token}/")

            otp = generate_otp()

            request.session['otp'] = otp
            request.session['reset_email'] = email

            send_otp_email(email, otp)

            return Response({'message': 'OTP has been sent to your email. Please enter it to reset your password.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Multiple users found with the provided email address. Please contact support.'}, status=status.HTTP_400_BAD_REQUEST)



class OtpVerificationView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        # Check if the email or OTP is empty
        if not email or not otp:
            return Response({'error': 'Please provide both email and OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if 'otp' in request.session and 'reset_email' in request.session:
            saved_otp = request.session['otp']
            saved_email = request.session['reset_email']

            if email == saved_email and otp == saved_otp:
                return Response({'message': 'OTP verification successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'OTP session data not found. Please restart the password reset process.'}, status=status.HTTP_400_BAD_REQUEST)



class ResetPasswordView(generics.GenericAPIView):
    def post(self, request, email):
        user = User.objects.filter(email=email).first()

        if user:
            form = SetPasswordForm(user, request.data)
            if form.is_valid():
                form.save()
                return Response({'message': 'Your password has been reset successfully. You can now login with your new password.'}, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid password reset link.'}, status=status.HTTP_400_BAD_REQUEST)


def send_otp_email(email, otp):
    subject = 'OTP Verification'
    message = f'Your OTP for password reset is: {otp}'
    email_from = 'your_email@example.com'
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)


def generate_otp():
    return str(randint(100000, 999999))




