from django import forms
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(label='OTP', max_length=6, widget=forms.TextInput(attrs={'autofocus': True}))

class CustomPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(label='Email', max_length=254, widget=forms.EmailInput(attrs={'autocomplete': 'email'}))

class CustomSetPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(label='New Password', widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}))
    new_password2 = forms.CharField(label='Confirm New Password', widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}))
