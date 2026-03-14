from django.contrib import admin
from django.urls import path
from .views import  (
    UserLogin, 
    UserReg,
    UserForgotPassword,
    ResetPassCodeCheck,
    NewPassword,
    VerifyAccount,
    Dashboard, 
    logout_view,
    UserAccount,
    EditAccount,
    ChangeEmail,
    UserList,
    UserStats,
    DeleteUser,
    BanUser,
    UnBanUser,
    AddAccount,
    ChangePassword,
    reset_password,
    UserSubscription,
    change_profile_pic,
    MdDocsList,
    download_doc,
    MdDocsPublicList,
    ShowDocDetails,
    share_doc,
    unshare_doc,
    delete_doc,
    EditMdDocInfos,
    BannedAccount,
    VerifyCode,
    SendVerifCode,
    VerifiedSuccess,
    RegistrationSuccess,
    VerifyCodeForgotPass,
    ChangeProfilePic
)

urlpatterns = [
    path('',  UserLogin.as_view(), name="user_login"),
    path('create_acc',UserReg.as_view(),name="create_acc"),
    path('verify_account',VerifyAccount.as_view(),name="verify_account"),
    path('banned_account',BannedAccount.as_view(),name="banned_account"),
    path('send_verif_code',SendVerifCode.as_view(),name="send_verif_code"),
    path('verified_success',VerifiedSuccess.as_view(),name="verified_success"),
    path('registration_success', RegistrationSuccess.as_view(), name="registration_success"),
    path('forgot_password', UserForgotPassword.as_view(), name="forgot_password"),
    path('verify_code',VerifyCode.as_view(),name="verify_code"),
    path('verify_code_forgot_pass',VerifyCodeForgotPass.as_view(),name="verify_code_forgot_pass"),
    path('new_password',NewPassword.as_view(), name="new_password"),
    path('edit_account', EditAccount.as_view(),name="edit_account"),
    path('user_account', UserAccount.as_view(), name="user_account"),
    path('edit_account', EditAccount.as_view(),name="edit_account"),
    path('dashboard', Dashboard.as_view(), name="dashboard"),
    path('change_password', ChangePassword.as_view(), name="change_password"),
    path('change_profile_pic', ChangeProfilePic.as_view(), name="change_profile_pic"),
    




    
    path('reset_pass',ResetPassCodeCheck.as_view(), name="reset_pass"),

    
    
    path('user_logout',logout_view,name="user_logout"),
    
    
    path('change_email', ChangeEmail.as_view(), name="change_email"),
    path('users_list',UserList.as_view(), name="users_list"),
    path('stats_account', UserStats.as_view(),name="stats_account"),
    path('delete_user', DeleteUser.as_view(), name="delete_user"),
    path('ban_user', BanUser.as_view(),name="ban_user"),
    path('unban_user', UnBanUser.as_view(), name="unban_user"),
    path('add_account', AddAccount.as_view(), name="add_account"),
    
    path('reset_password', reset_password, name="reset_password"),
    path('subscription',UserSubscription.as_view(), name="subscription"),
    path("change_profile_pic",change_profile_pic, name="change_profile_pic"),
    path('mddocs_list', MdDocsList.as_view(), name="mddocs_list"),
    path('download_md_doc',download_doc, name="download_md_doc"),
    path('public_docs', MdDocsPublicList.as_view(), name="public_docs"),
    path('show_document', ShowDocDetails.as_view(), name="show_document"),
    path('share_doc', share_doc, name="share_doc"),
    path('unshare_doc', unshare_doc, name="unshare_doc"),
    path('delete_doc',delete_doc,name="delete_doc"),
    path('edit_doc_infos', EditMdDocInfos.as_view(), name="edit_doc_infos")
]