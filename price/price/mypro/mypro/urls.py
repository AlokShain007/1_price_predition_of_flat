
# from django.urls import path
# from myapp import views
# from django.contrib.auth import views as auth_views
# from django.contrib import admin
# urlpatterns = [
#     path('admin/', admin.site.urls),
#     path('', views.HomePage, name='home'),
#     path('predict/', views.predict, name='predict'),
#     path('signup/', views.SignupPage, name='signup'),
#     path('login/', views.LoginPage, name='login'),
#     path('logout/', views.LogoutPage, name='logout'),
#     path('price/', views.prediction_view, name='price'),
#     path('price/out/<str:predicted_price>/', views.output, name='output'),
#     path('forgot-password/', views.forgot_password, name='forgot_password'),
#     path('otp-verification/', views.otp_verification, name='otp_verification'),
#     path('reset-password/<str:email>/', views.reset_password, name='reset_password'),
    

# ]
# from django.contrib import admin
# from django.urls import path
# from myapp.views import (
#     OutputView,
#     HomePageView,
#     PredictView,
#     PredictionView,
#     SignupView,
#     LoginView,
#     LogoutView,
#     ForgotPasswordView,
#     OtpVerificationView,
#     ResetPasswordView,
# )

# urlpatterns = [
#     path('admin/', admin.site.urls),
#     path('output/', OutputView.as_view(), name='output'),
#     path('', HomePageView.as_view(), name='home'),
#     path('predict/', PredictView.as_view(), name='predict'),
#     path('prediction/', PredictionView.as_view(), name='price'),
#     path('signup/', SignupView.as_view(), name='signup'),
#     path('login/', LoginView.as_view(), name='login'),
#     path('logout/', LogoutView.as_view(), name='logout'),
#     path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
#     path('otp-verification/', OtpVerificationView.as_view(), name='otp_verification'),
#     path('reset-password/<str:email>/', ResetPasswordView.as_view(), name='reset_password'),
# ]



from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.urls import path
# Create a schema view for Swagger documentation
schema_view = get_schema_view(
    openapi.Info(
        title="MyApp API",
        default_version='v1',
        description="API documentation for MyApp",
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="contact@example.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)


# In myapp.urls.py:
from django.urls import path,include
from myapp import views

urlpatterns = [
    path('output/', views.OutputView.as_view(), name='output'),
    path('home/', views.HomePageView.as_view(), name='home'),
    path('predict/', views.PredictView.as_view(), name='predict'),
    path('prediction/', views.PredictionView.as_view(), name='price'),
    path('signup/', views.SignupView.as_view(), name='signup'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('otp-verification/', views.OtpVerificationView.as_view(), name='otp_verification'),
    path('reset-password/<str:email>/', views.ResetPasswordView.as_view(), name='reset_password'),
    path('admin/', admin.site.urls),
    path('api/',include('app.urls')),
    # Other URL patterns
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

# Run your Django development server and navigate to the Swagger documentation URLs:
# Swagger UI: http://localhost:8000/api/docs/
# ReDoc: http://localhost:8000/api/redoc/
