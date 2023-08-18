from django.urls import path,include
from app import views
from django.contrib.auth import views as auth_views
from django.contrib import admin
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.HomePage, name='home'),
    path('predict/', views.predict, name='predict'),
    path('signup/', views.SignupPage, name='signup'),
    path('login/', views.LoginPage, name='login'),
    path('logout/', views.LogoutPage, name='logout'),
    path('price/', views.prediction_view, name='price'),
    path('price/out/<str:predicted_price>/', views.output, name='output'),
    path('comparison/', views.comparison_view, name='comparison'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('otp-verification/', views.otp_verification, name='otp_verification'),
    path('reset-password/<str:email>/', views.reset_password, name='reset_password'),
    # path('accounts/', include('allauth.urls')),

]