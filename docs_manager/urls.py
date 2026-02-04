from django.contrib import admin
from django.urls import path
from .views import  UserLogin, UserReg,UserResetPassword,ResetPassCodeCheck,NewPassword,VerifyAccount,Dashboard, logout_view,send_code

urlpatterns = [
    path('',  UserLogin.as_view(), name="user_login"),
    path('create_acc',UserReg.as_view(),name="create_acc"),
    path('forgot_password', UserResetPassword.as_view(), name="forgot_password"),
    path('reset_pass',ResetPassCodeCheck.as_view(), name="reset_pass"),
    path('new_password',NewPassword.as_view(), name="new_password"),
    path('verify_code',VerifyAccount.as_view(),name="verify_code"),
    path('dashboard', Dashboard.as_view(), name="dashboard"),
    path('user_logout',logout_view,name="user_logout"),
    path('send_code',send_code,name="send_code")
]