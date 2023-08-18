import pandas as pd
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from serializers import *
from app.models import RealEstateListing
from joblib import load
import numpy as np
import os
import joblib
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.mixins import PermissionRequiredMixin

model_directory = '/Users/administrator/Desktop/price/mypro/savedmodels'
model_file_path = os.path.join(model_directory, 'model.joblib')
model = load(model_file_path)

@login_required(login_url='login')
def output(request):
    return render(request, "output.html")



def HomePage(request):
    return render(request, 'home.html')


@login_required(login_url='login')
def predict(request):
    return render(request, 'predict.html')


import numpy as np
import joblib
from django.shortcuts import render
from .models import RealEstateListing

# Define the path to the directory containing the trained model
model_directory = '/Users/administrator/Desktop/price/mypro/savedmodels' 
model_file_path = os.path.join(model_directory, 'model.joblib')
model = joblib.load(model_file_path)

@login_required(login_url='login')
def prediction_view(request):
    if request.method == 'POST':
        total_sqft = request.POST.get('total_sqft')
        bath = request.POST.get('bath')
        bhk = request.POST.get('bhk')

        # Perform data validation
        if not all(value for value in [total_sqft, bath, bhk]):
            return render(request, 'input.html', {'error': 'Please fill in all the fields'})

        try:
            total_sqft = int(total_sqft)
            bath = float(bath)
            bhk = float(bhk)

            input_data = np.array([[total_sqft, bath, bhk]])
            price = model.predict(input_data)[0]
            price_per_sqft=float(price/total_sqft) 

            city = request.POST.get('city')  

            if city == "city_New Delhi":
                p=(price_per_sqft*10)/100
                p1=price_per_sqft-p
                price=p1*total_sqft
                
            elif city == "city_Chennai":
                
                p=(price_per_sqft*4)/100
                p1=price_per_sqft-p
                price=p1*total_sqft
            elif city == "city_Hyderabad":
                
                p=(price_per_sqft*17)/100
                p1=price_per_sqft-p
                price=p1*total_sqft
            elif city == "city_Kolkata":
                
                p=(price_per_sqft*16)/100
                p1=price_per_sqft-p
                price=p1*total_sqft
            elif city == "city_Mumbai":
                
                p=(price_per_sqft*5)/100
                p1=price_per_sqft+p
                price=p1*total_sqft
            elif city == "city_Pune":
                
                p=(price_per_sqft*7)/100
                p1=price_per_sqft+p
                price=p1*total_sqft
            elif city == "city_Thane":
                
                p=(price_per_sqft*4)/100
                p1=price_per_sqft+p
                price=p1*total_sqft
            else:
                price=price

            # Save the input data and predicted price to the database
            prediction_object = RealEstateListing(
                bhk=bhk,
                bath=bath,
                total_sqft=total_sqft,
                price=price
            )
            prediction_object.save()

            # Fetch all predictions from the database (for debugging purposes)
            prediction_data = RealEstateListing.objects.values()

            # Create a DataFrame from the QuerySet
            prediction_df = pd.DataFrame(prediction_data)

            # Save DataFrame to a CSV file in Django (for debugging purposes)
            csv_file_path = 'prediction_data.csv'
            prediction_df.to_csv(csv_file_path, index=False)

            return render(request, 'output.html', {'predicted_price': price})

        except ValueError:
            return render(request, 'input.html', {'error': 'Invalid input. Please enter valid values'})

    return render(request, 'input.html')


def comparison_view(request):
    city = request.POST.get('city', '')  # Get the selected city from the form

    # Fetch the latest predicted real estate listing from the database
    latest_prediction = RealEstateListing.objects.latest('id')

    # Calculate price per square foot for the latest prediction
    latest_prediction.price_per_sqft = latest_prediction.price / latest_prediction.total_sqft

    if city:
        # Fetch all real estate listings for the specified city
        similar_properties = RealEstateListing.objects.filter(city=city).exclude(id=latest_prediction.id)

        # Calculate price per square foot for the similar properties
        for property in similar_properties:
            property.price_per_sqft = property.price / property.total_sqft

        # Sort the similar properties based on the price per square foot
        similar_properties = sorted(similar_properties, key=lambda x: abs(x.price_per_sqft - latest_prediction.price_per_sqft))
    else:
        similar_properties = []

    return render(request, 'comparison.html', {'latest_prediction': latest_prediction, 'similar_properties': similar_properties, 'selected_city': city})



@login_required(login_url='login')
def output(request, predicted_price):
    return render(request, 'output.html', {'predicted_price': predicted_price})


         
def SignupPage(request):
    if request.method == 'POST':
        uname = request.POST.get('username')
        email = request.POST.get('email')
        pass1 = request.POST.get('password1')
        pass2 = request.POST.get('password2')

        if pass1 != pass2:
            return HttpResponse("Your password and confirm password are not the same!")
        else:
            if User.objects.filter(email=email).exists():
                return render(request, 'signup.html', {"message": "Email already exists"})
            else:
                my_user = User.objects.create_user(uname, email, pass1)
                my_user.save()
                return redirect('login')

    return render(request, 'signup.html')
# from allauth.socialaccount.models import SocialAccount

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login

def LoginPage(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Valid credentials, log in the user
            login(request, user)
            return redirect('predict')  # Replace 'predict' with the URL name of the desired destination
        else:
            # Invalid credentials, pass an error message to the template
            error_message = "Invalid username or password."
            return render(request, 'login.html', {'error_message': error_message})

    return render(request, 'login.html')


# def LoginPage(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         pass1 = request.POST.get('pass')
#         user = authenticate(request, username=username, password=pass1)
#         if user is not None:
#             login(request, user)
#             return redirect('predict')
#         else:
#             return HttpResponse("Username or Password is incorrect!!!")

#     return render(request, 'login.html')


def LogoutPage(request):
    logout(request)
    return redirect('login')

# from .decorators import prevent_logged_in


from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .forms import PasswordResetForm, SetPasswordForm
from random import randint

User = get_user_model()


# @login_required(login_url='login')
def forgot_password(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            users = User.objects.filter(email=email)
            user_count = users.count()

            if user_count == 0:
                messages.error(request, 'User with the provided email address does not exist.')
            elif user_count == 1:
                user = users.first()
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                reset_link = request.build_absolute_uri(f"/reset-password/{email}/{uid}/{token}/")

                otp = generate_otp()

                request.session['otp'] = otp
                request.session['reset_email'] = email

                send_otp_email(email, otp)

                messages.success(request, 'OTP has been sent to your email. Please enter it to reset your password.')
                return redirect('otp_verification')
            else:
                messages.error(request, 'Multiple users found with the provided email address. Please contact support.')

            return redirect('forgot_password')
    else:
        form = PasswordResetForm()

    return render(request, 'forget_password.html', {'form': form})


# @login_required(login_url='login')
def send_otp_email(email, otp):
    subject = 'OTP Verification'
    message = f'Your OTP for password reset is: {otp}'
    email_from = 'your_email@example.com'
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)


# @login_required(login_url='login')
def generate_otp():
    return str(randint(100000, 999999))


# @login_required(login_url='login')
def otp_verification(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')

        if 'otp' in request.session and 'reset_email' in request.session:
            otp = request.session['otp']
            email = request.session['reset_email']

            if entered_otp == otp:
                return redirect('reset_password', email=email)
            else:
                messages.error(request, 'Invalid OTP. Please try again.')

    return render(request, 'otp_verification.html')


# @login_required(login_url='login')
def reset_password(request, email):
    if 'reset_email' in request.session and email == request.session['reset_email']:
        user = User.objects.filter(email=email).first()

        if user:
            if request.method == 'POST':
                form = SetPasswordForm(user, request.POST)

                if form.is_valid():
                    form.save()
                    messages.success(request, 'Your password has been reset successfully. You can now login with your new password.')
                    return redirect('login')
            else:
                form = SetPasswordForm(user)

            return render(request, 'reset_password.html', {'form': form})
    else:
        messages.error(request, 'Invalid password reset link.')

    return redirect('forgot_password')







