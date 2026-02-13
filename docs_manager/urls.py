from django.contrib import admin
from django.urls import path
from .views import  (
    UserLogin, 
    UserReg,
    UserResetPassword,
    ResetPassCodeCheck,
    NewPassword,
    VerifyAccount,
    Dashboard, 
    logout_view,
    send_code,
    UserAccount,
    EditAccount,
    ChangeEmail,
    UserList,
    UserStats,
    DeleteUser,
    BanUser,
    UnBanUser,
    AddAccount
)

urlpatterns = [
    path('',  UserLogin.as_view(), name="user_login"),
    path('create_acc',UserReg.as_view(),name="create_acc"),
    path('forgot_password', UserResetPassword.as_view(), name="forgot_password"),
    path('reset_pass',ResetPassCodeCheck.as_view(), name="reset_pass"),
    path('new_password',NewPassword.as_view(), name="new_password"),
    path('verify_code',VerifyAccount.as_view(),name="verify_code"),
    path('dashboard', Dashboard.as_view(), name="dashboard"),
    path('user_logout',logout_view,name="user_logout"),
    path('send_code',send_code,name="send_code"),
    path('user_account', UserAccount.as_view(), name="user_account"),
    path('edit_account', EditAccount.as_view(),name="edit_account"),
    path('change_email', ChangeEmail.as_view(), name="change_email"),
    path('users_list',UserList.as_view(), name="users_list"),
    path('stats_account', UserStats.as_view(),name="stats_account"),
    path('delete_user', DeleteUser.as_view(), name="delete_user"),
    path('ban_user', BanUser.as_view(),name="ban_user"),
    path('unban_user', UnBanUser.as_view(), name="unban_user"),
    path('add_account', AddAccount.as_view(), name="add_account")
]