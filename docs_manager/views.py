from django.shortcuts import render,redirect
from django.contrib.auth import logout
from django.views import View
from django.contrib import messages
from .models import *
import re
import string
import random
from django.contrib.auth.models import User
from django.core.mail import send_mail
from datetime import timedelta
from django.utils import timezone
from django.conf import settings

from django.contrib.auth.mixins import LoginRequiredMixin

from django.core.paginator import Paginator
from django.http import FileResponse, Http404
import os
#-------------
from .tools import *
#-------------

#========Fix Fat View, implement tools functions list=====================
#11/03/2026
#-------------------------------------------------------------------------
class GenericAccessChecking(View):

    #verifiy user accesss
    def dispatch(self, request, *args, **kwargs):
        if check_user_access(request.user) != -1:
            if check_user_access(request.user) == -2:
                return redirect("verify_account")
            elif check_user_access(request.user) == -3:
                return redirect("banned_account")
            elif request.user.check_password("12345678"):
                return redirect("change_password")

        return super().dispatch(request, *args, **kwargs)


class UserLogin(GenericAccessChecking,View):

    def get(self, request):
        data={}  
        if request.user.is_authenticated:
            return redirect("dashboard")          
        #user are not connect but trying to connect, we con auto fill inputs with last input
        if "user_id" in request.session.keys():
            data["user_id"]=request.session['user_id']
        if "user_pwd" in request.session.keys():
            data["user_pwd"]=request.session['user_pwd']
        return render(request, 'main_tmpl/pages/login.html',data)


    def post(self, request):
        next_url=request.GET.dict().get("next",None)
        data=request.POST.dict()
        u_login=login_user(data,request)
        request.session['user_id']=data['identifiant']
        request.session['user_pwd']=data['password']

        if u_login['logged']:
            return redirect(request.GET.dict().get('next') if request.GET.dict().get('next',None) else "dashboard")
        messages.error(request,u_login['message'])
        return redirect("user_login")


class UserReg(View):

    def get(self, request):
        return render(request, "main_tmpl/pages/register.html")
    
    def post(self,request):
        data=request.POST.dict()
        check_data=checking_user_data(data)
        if check_data['success']:
            if create_user_account(request,data) != -1:
                #redirect to verify account
                return redirect("registration_success")
            else:
                messages.error(request, "Ops! quelque chose a mal tourner, reessayer")
        else:
            messages.error(request, check_data['message'])

        return render(request, "main_tmpl/pages/register.html",data)

class BannedAccount(LoginRequiredMixin,View):

    def get(self,request):
        #si on arrive a cette page alors que l'utilisateur n'es pas bani ce que il ya un souci
        if not BannedUsers.objects.filter(user_id=request.user.username).exists():
            return redirect('dashboard')
        return render(request, "main_tmpl/pages/banned_account.html")

class VerifyAccount(LoginRequiredMixin, View):

    def get(sefl, request):
        #si on arrive a cette page alors que l'utilisateur est deja verifier ce que il ya un souci
        if VerifiedUser.objects.filter(user_id=request.user.username).exists():
            return redirect('dashboard')
        data={
            "email":hide_email_part(request.user.email)
        }
        data['is_email']=False
        if data['email'] != -1:
            data['is_email']=True
        return render(request, "main_tmpl/pages/verify_account.html",data)

class VerifyCode(LoginRequiredMixin,View):

    def get(sefl, request):

        return render(request, "main_tmpl/pages/verify_code.html")
    
    def post(self, request):
        check_code=check_verif_code(request.user,request.POST.dict())
        if check_code == 0:
            verify_user(request.user)
            return redirect('verified_success')

        elif check_code == -1:
            messages.error(request, "Vous avez fourni un code erronee")
        elif check_code == -2:
            messages.error(request, "Ce code est deja expiree, click sur renvoyer le code")

        return render(request, "main_tmpl/pages/verify_code.html")

class SendVerifCode(LoginRequiredMixin, View):

    def get(self,request):
        next_url=request.GET.dict().get("next",None)
        if send_verification_code(request.user) == -1:
            messages.error(request,"Erreur, nous n'avons pas pu envoyer le code, verifier votre connexion internet")
            return redirect("verify_account")
        if next_url:
            return redirect(next_url)
        return redirect("verify_code")

class VerifiedSuccess(LoginRequiredMixin, View):

    def get(self,request):
        return render(request, "main_tmpl/pages/verified_success.html")

class RegistrationSuccess(LoginRequiredMixin, View):

    def get(self,request):
        data={
            "user":request.user
        }
        return render(request, "main_tmpl/pages/registration_success.html",data)


class ChangePassword(LoginRequiredMixin,View):

    def get(self, request):
        data={
            "user":request.user
        }        
        return render(request, 'main_tmpl/pages/change_password.html',data)
    
    def post(self, request):
        data=request.POST.dict()
        change_pwd=change_user_password(request.user, data)
        if change_pwd == -1:
            messages.error(request, "Ancien mot de passe incorrect!")
        elif change_pwd == -2:
            messages.error(request, "Mot de passe trop faible, doit etre minimum 6 caractere, melanger des lettres, des chiffres et des symboles")
        elif change_pwd == -3:
            messages.error(request, "Le mot de passe et confirme pass doivent etre identique!")
        elif change_pwd == 0:
            data['is_changed']=True
            #messages.success(request,"votre mot de passe a etait modifier avec success vous pouvez vous connecter avec votre nouveau mot de passe")
        
        return render(request, 'main_tmpl/pages/change_password.html',data)

class UserForgotPassword(View):

    def get(self, request):

        return render(request, 'main_tmpl/pages/forgot_pass.html')
    
    def post(self, request):
        data=request.POST.dict()
        check_email=check_user_email(data)
        if check_email == -1:
            messages.error(request, "Veuillez inserer une adresse email valide svp!")
        elif check_email == -2:
            messages.error(request, "Aucun utilisateur trouver avec cette adresse email!")
        elif check_email == 0:
            user=User.objects.get(email=data['email'])
            send_verification_code(user)
            request.session['email']=data['email']
            return redirect('verify_code_forgot_pass')

        return render(request, 'main_tmpl/pages/forgot_pass.html',data)

class VerifyCodeForgotPass(View):

    def get(sefl, request):
        return render(request, "main_tmpl/pages/verify_code_forgot_pass.html")
    
    def post(self, request):
        user=User.objects.get(email=request.session['email'])
        check_code=check_verif_code(user,request.POST.dict())

        if check_code == 0:
            request.session['email_verified']=True
            return redirect("new_password")
        elif check_code == -1:
            messages.error(request, "Vous avez fourni un code erronee")
        elif check_code == -2:
            messages.error(request, "Ce code est deja expiree, click sur renvoyer le code")
        return redirect("verify_code_forgot_pass")

class NewPassword(View):

    def get(self, request):
        if "email_verified" not in request.session.keys() or not request.session['email_verified']:
            return redirect("forgot_password")
        return render(request, 'main_tmpl/pages/new_password.html')
    
    def post(self,request):
        if "email_verified" not in request.session.keys() or not request.session['email_verified']:
            return redirect("forgot_password")
        data=request.POST.dict()
        user=User.objects.get(email=request.session['email'])
        set_new_pwd=set_user_password(user,data)

        if set_new_pwd == -1:
            messages.error(request, "Le mot de passe doit etre superieur ou egale a 6 caracteres, melanger les lettre, chiffres et symbole.")
        elif set_new_pwd == -2:
            messages.error(request, "Le mot de passe et confirm mot de passe doivent etre identique")
        elif set_new_pwd == 0:
            data['is_set']=True
            data['user']=user

        return render(request, 'main_tmpl/pages/new_password.html',data)

class Dashboard(GenericAccessChecking,LoginRequiredMixin, View):

    def get(self,request):
        data={
            "user":request.user
        }
        data['current_page']="dashboard"
        if not data['user'].is_active:
            return redirect("user_logout")
        request.session['user_id']=data['user'].username
        data['docs']=MdDocs.objects.all()
        return render(request, "main_tmpl/dashboard.html",data)

class EditAccount(GenericAccessChecking,LoginRequiredMixin, View):

    def get(self, request):
        data={
            "user":request.user
        }
        return render(request, 'main_tmpl/pages/edit_account.html',data)
    

    def post(self, request):
        data=request.POST.dict()
        edit_res=edit_user_info(request.user, request.POST.dict())
        if edit_res == -1:
            messages.error(request,"Le nom ou prenom invalide, ne doit contenir que des lettres alpabetique.")
        elif edit_res == -2:
            messages.error(request, "Date de naissance invalide, format correct dd/mm/yyyy exemple : 02/12/2002")
        elif edit_res == -3:
            messages.error(request, "Date de naissance indique un age trop bas, minimum requis 12 ans (Eleve du lycee)")
        else:
            messages.info(request, edit_res)
        return render(request, 'main_tmpl/pages/edit_account.html',data)

class ChangeProfilePic(GenericAccessChecking,LoginRequiredMixin, View):

    def get(self,request):
        data={
            "user":request.user
        }
        return render(request, 'main_tmpl/pages/change_profile_pic.html',data)
    
    def post(self, request):
        user=request.user
        if request.FILES['photo']:
            #checking images
            user.profile_pic.photo=request.FILES['photo']
            user.profile_pic.save()
            messages.success(request,"Photo de profile modifier avec success!")
        return redirect("change_profile_pic")

#=======================END=======================================================



    
class ResetPassCodeCheck(View):   

    def get(self, request):
        print(request.session)
        return render(request, 'main_tmpl/pages/forgot_pass_verify_code.html')

    def post(self, request):
        data={
            "code":request.POST.dict().get("code")
        }
        if not "user_id" in request.session.keys() or not User.objects.filter(username=request.session['user_id']).exists():
            messages.error(request, "Votre sesion a expirer veuillez recommencer!")
            return redirect("reset_pass")
        
        data['user']=User.objects.get(username=request.session['user_id'])

        if data['code']:
            try:
                check_code=VerificationCode.objects.filter(user=data['user'], code=data['code']).latest('created_at')
                if check_code.is_valid():
                    return redirect("new_password")
                data['expiry_code']=True
                messages.error(request, "Le delai pour ce code est deja exprirer!")
                return render(request, 'main_tmpl/pages/forgot_pass_verify_code.html',data)
            except VerificationCode.DoesNotExist:
                messages.error(request, "Ce code est invalide!")
        else:
            messages.error(request, "Veuillez inserer un code valide svp!")
        return render(request, 'main_tmpl/pages/forgot_pass_verify_code.html',data)


class UserAccount(LoginRequiredMixin, View):

    def get(self,request):
        data={
            "user":request.user
        }
        if request.GET.dict().get("user_id",None):
            try:
                data['user']=User.objects.get(username=request.GET.dict().get("user_id",None))
            except:
                data['user']=request.user
        return render(request, 'main_tmpl/pages/user_account.html', data)


class UserStats(LoginRequiredMixin,View):

    def get(self,request):
        data={
            "user":request.user
        }
        if request.GET.dict().get("user_id",None):
            try:
                data['user']=User.objects.get(username=request.GET.dict().get("user_id"))
            except:
                pass
        data['nbr_students']=35
        data['nbr_books']=2
        data['nbr_docs']=10
        data['nbr_classes']=0
        
        return render(request, 'main_tmpl/pages/stats_account.html', data)

class ChangeEmail(LoginRequiredMixin, View):

    def get(self, request):
        try:
            data={
                "user":User.objects.get(username=request.session['user_id'])
            }
        except:
            messages.error(request, "Ops! desolee quelque chose a mal tournee reessayer!")
            return redirect("edit_account")
        if "email" in request.session.keys():
            data['user'].email=request.session['email']
            data['user'].is_active=False
            data['user'].save()
            send_verification_code(data['user'], title="ICARTABLE, Code de verification de votre compte")
        return redirect("verify_code")

#-------ADMIN--------
class UserList(LoginRequiredMixin, View):

    def get(self, request):
        nbr_per_page=10
        
        data={
            "users":[user for user in User.objects.all().order_by('-date_joined') if user != request.user],
            "nbr_page":int(User.objects.all().count()/nbr_per_page),
            "current_p":int(request.GET.dict().get('page') if 'page' in request.GET.dict().keys() else 1),
            "current_url":request.build_absolute_uri(),
            "nbr_users":User.objects.count(),
            "nbr_male":0,
            "nbr_female":3,
            "other_gender":2
        }
        data['nbr_male']=len(data['users'])
        

        if "srch_wd" in request.GET.dict().keys():
            data["srch_wd"]=request.GET.dict().get("srch_wd")
            data['is_srch']=True
            data['users']=[]
            for user in User.objects.all():
                if user.username == data["srch_wd"] or user.first_name == data["srch_wd"] or user.last_name == data["srch_wd"] or user.email == data["srch_wd"]:
                    data['users'].append(user)

        if "filter" in request.GET.dict().keys():
            data['filter_wd']=request.GET.dict().get("filter")
            data['is_filter']=True
            data['users']=[]
            for user in User.objects.all():
                if user == request.user:
                    continue
                tot_days_since_reg=(timezone.now() - user.date_joined).days
                if data['filter_wd'] == "teacher" and user.is_staff and not user.is_superuser:
                    data['users'].append(user)
                elif data['filter_wd'] == "student" and not user.is_superuser and not user.is_staff:
                    data['users'].append(user)
                elif data['filter_wd'] == "reg_today" and tot_days_since_reg <= 1 :
                    data['users'].append(user)
                elif data['filter_wd'] == "reg_this_week" and tot_days_since_reg <= 7 :
                    data['users'].append(user)
                elif data['filter_wd'] == "reg_this_mth" and tot_days_since_reg <= 31 :
                    data['users'].append(user)
                elif data['filter_wd'] == "admin" and user.is_superuser :
                    data['users'].append(user)
                elif data['filter_wd'] == "active" and user.is_active :
                    data['users'].append(user)
                elif data['filter_wd'] == "inactive" and not user.is_active :
                    data['users'].append(user)

            data['fltr_wd']=data['filter_wd']
            if data['filter_wd'] == "teacher":
                data['filter_wd']="Professeur"
            elif data['filter_wd'] == "student":
                data['filter_wd']="Eleve"
            elif data['filter_wd'] == "reg_today":
                data['filter_wd']="Inscrit aujourdhui"
            elif data['filter_wd'] == "reg_this_week":
                data['filter_wd']="Inscrit cette semaine"
            elif data['filter_wd'] == "reg_this_mth":
                data['filter_wd']="Inscrit ce mois-ci"

            #paginer la liste de users
        paginator=Paginator(data['users'], nbr_per_page)
        data['users']=paginator.get_page(data['current_p'])

        data['del_user_id']=request.GET.dict().get('del_user_id', None)
        if data['del_user_id'] and User.objects.filter(username=data['del_user_id']).exists():
            data['del_user']=User.objects.get(username=data['del_user_id'])
            data['ask_for_delete']=True if "action" in request.GET.dict().keys() and request.GET.dict().get("action") == "delete"  else False
            data['ban_user']=True if "action" in request.GET.dict().keys() and request.GET.dict().get("action") == "banir"  else False
            data['unban_user']=True if "action" in request.GET.dict().keys() and request.GET.dict().get("action") == "unbanir"  else False
            data['reset_pass']=True if "action" in request.GET.dict().keys() and request.GET.dict().get("action") == "reset_pass"  else False
                   
        return render(request, 'main_tmpl/pages/users_list.html',data)

#-----------------------

class MdDocsList(LoginRequiredMixin, View):

    def get(self, request):
        nbr_per_page=10
        user=request.user
        
        data={
            "docs":[doc for doc in user.user_docs.all()],
            "nbr_page":int(User.objects.all().count()/nbr_per_page),
            "current_p":int(request.GET.dict().get('page') if 'page' in request.GET.dict().keys() else 1),
            "current_url":request.build_absolute_uri(),
            "nbr_male":0,
            "nbr_female":3,
            "other_gender":2
        }
        

        if "srch_wd" in request.GET.dict().keys():
            data["srch_wd"]=request.GET.dict().get("srch_wd")
            data['is_srch']=True
            data['docs']=[]
            for doc in user.user_docs.all():
                if  data["srch_wd"].lower() in doc.title.lower() or data["srch_wd"] == doc.ref:# or user.first_name == data["srch_wd"] or user.last_name == data["srch_wd"] or user.email == data["srch_wd"]:
                    data['docs'].append(doc)

        if "filter" in request.GET.dict().keys():
            data['filter_wd']=request.GET.dict().get("filter")
            data['is_filter']=True
            data['docs']=[]
            for doc in user.user_docs.all():
                tot_days_since_add=(timezone.now() - doc.date_add).days
                if data['filter_wd'] == "shared" and doc.is_public:
                    data['docs'].append(doc)
                elif data['filter_wd'] == "unshared" and not doc.is_public:
                    data['docs'].append(doc)
                elif data['filter_wd'] == "reg_today" and doc.date_add.date() > timezone.now().date():#tot_days_since_add <= 1 :
                    data['docs'].append(doc)
                elif data['filter_wd'] == "reg_this_week" and tot_days_since_add <= 7 :
                    data['docs'].append(doc)
                elif data['filter_wd'] == "reg_this_mth" and tot_days_since_add <= 31 :
                    data['docs'].append(doc)

            #paginer la liste de users
        paginator=Paginator(data['docs'], nbr_per_page)
        data['docs']=paginator.get_page(data['current_p'])  
        return render(request, 'main_tmpl/pages/mddocs_list.html',data)


class MdDocsPublicList(LoginRequiredMixin, View):

    def get(self, request):
        nbr_per_page=10
        user=request.user
        
        data={
            "docs":[doc for doc in MdDocs.objects.filter(is_public=True) if doc.user != request.user],
            "nbr_page":int(User.objects.all().count()/nbr_per_page),
            "current_p":int(request.GET.dict().get('page') if 'page' in request.GET.dict().keys() else 1),
            "current_url":request.build_absolute_uri(),
            "nbr_male":0,
            "nbr_female":3,
            "other_gender":2,
            'is_public':True
        }
        

        if "srch_wd" in request.GET.dict().keys():
            data["srch_wd"]=request.GET.dict().get("srch_wd")
            data['is_srch']=True
            data['docs']=[]
            for doc in MdDocs.objects.filter(is_public=True):
                if  data["srch_wd"].lower() in doc.title.lower() or data["srch_wd"] == doc.ref:# or user.first_name == data["srch_wd"] or user.last_name == data["srch_wd"] or user.email == data["srch_wd"]:
                    data['docs'].append(doc)

        if "filter" in request.GET.dict().keys():
            data['filter_wd']=request.GET.dict().get("filter")
            data['is_filter']=True
            data['docs']=[]
            for doc in MdDocs.objects.filter(is_public=True):
                tot_days_since_add=(timezone.now() - doc.date_add).days
                if data['filter_wd'] == "shared" and doc.is_public:
                    data['docs'].append(doc)
                elif data['filter_wd'] == "unshared" and not doc.is_public:
                    data['docs'].append(doc)
                elif data['filter_wd'] == "reg_today" and doc.date_add.date() > timezone.now().date():#tot_days_since_add <= 1 :
                    data['docs'].append(doc)
                elif data['filter_wd'] == "reg_this_week" and tot_days_since_add <= 7 :
                    data['docs'].append(doc)
                elif data['filter_wd'] == "reg_this_mth" and tot_days_since_add <= 31 :
                    data['docs'].append(doc)

            #paginer la liste de users
        paginator=Paginator(data['docs'], nbr_per_page)
        data['docs']=paginator.get_page(data['current_p'])  
        return render(request, 'main_tmpl/pages/public_doc.html',data)


class ShowDocDetails(LoginRequiredMixin, View):

    def get(self,request):
        try:
            doc=MdDocs.objects.get(ref=request.GET.dict().get("doc_ref", None))
        except:
            messages.error(request, "Ce document n'existe pas /plus")
            if "next" in request.GET.dict().keys():
                return redirect(request.GET.dict().get("next"))
            else:
                return redirect("mddocs_list")
                
        data={
            "user":request.user,
            "doc":doc

        }
        if doc.user != request.user:
            #is a public doc
            data['docs']=[doc_ for doc_ in MdDocs.objects.filter(is_public=True) if doc_.user != request.user and doc_ != doc]
            data['is_public_doc']=True

        if doc.user == request.user:
            #ismy doc
            data['docs']=[doc_ for doc_ in MdDocs.objects.filter(user=request.user) if doc_ != doc]
            data['is_public_doc']=False

        return render(request, 'main_tmpl/pages/show_document.html',data) 
    
    def post(self,request):
        doc_ref=request.POST.dict().get("doc_ref",None)
        doc_title=request.POST.dict().get("doc_title",None)
        doc_share=request.POST.dict().get("partage",None)

        try:
            doc=MdDocs.objects.get(ref=doc_ref)
            if doc.user != request.user:
                messages.error(request, "Seul le proprietaire de ce document peut le modifier")
                return redirect(f"/show_document?doc_ref={doc_ref}")
            if len(doc_title ) >= 3 and doc_title != doc.title:
                doc.title=doc_title
                doc.save()
                messages.success(request, "Le titre du document a etait modifier avec success!")
            if doc.is_public and doc_share == "no":
                doc.is_public=False
                messages.success(request, "Le partager en public a etait desactiver")

            if not doc.is_public and doc_share == "yes":
                doc.is_public=True
                messages.success(request, "Le document est maintenant partager avec le public!")
            doc.save()
                
        except:
            messages.error(request,"Ops! nous ne parvenons pas a recuperer ce document")

        return redirect(f"/show_document?doc_ref={doc_ref}")

class DeleteUser(LoginRequiredMixin, View):
    def get(self, request):
        try:
            if not request.user.is_superuser:
                messages.error(request, "Seul un admin peu supprimer un compte!")
            else:
                User.objects.get(username=request.GET.dict().get("user_id", None)).delete()
            
        except:
            pass
        return redirect("users_list")

class BanUser(LoginRequiredMixin, View):
    def get(self, request):
        try:
            user=User.objects.get(username=request.GET.dict().get("user_id", None))
            user.is_active=False
            user.save()
            BannedUser(user_id=user.username).save()
        except:
            pass
        return redirect("users_list")

class UnBanUser(LoginRequiredMixin, View):
    def get(self, request):
        try:
            user=User.objects.get(username=request.GET.dict().get("user_id", None))
            user.is_active=True
            user.save()
            BannedUser.objects.filter(user_id=user.username).delete()
        except:
            pass
        return redirect("users_list")

class AddAccount(LoginRequiredMixin,View):

    def get(self, request):
        data={}
        return render(request, 'main_tmpl/pages/add_account.html',data)
    
    def post(self,request):
        data={
            "first_name":request.POST.dict().get("first_name",None),
            "last_name":request.POST.dict().get("last_name",None),
            "email":request.POST.dict().get("email",None),
            "type_acc":request.POST.dict().get("type_acc",None),
            "password":"12345678"
        }
        #seul un compte prof ou admin peuvent ajouter des compte
        if not request.user.is_staff and not request.user.is_superuser:
            messages.error(request, "Seul un adminastreur ou un professeur peuvent ajouter des comptes!")
            return render(request, 'main_tmpl/pages/add_account.html',data)

        #seul un admin peu ajouter un compte professeur----------------------------
        if data['type_acc'] == 'staff' and not request.user.is_superuser:
            messages.error(request, "Seul un adminastreur peut ajouter des comptes professeur!")
            return render(request, 'main_tmpl/pages/add_account.html',data)
        
        #verifier si le compte existe pas deja
        if User.objects.filter(email=data['email']).exists():
            messages.error(request, "Il existe deja un compte avec cette adresse email!")
            return render(request, 'main_tmpl/pages/add_account.html',data)

        
        user_id=userid_code_generator()
        while User.objects.filter(username=user_id).exists():
            user_id=userid_code_generator()

        is_staff=True if data['type_acc'] == "staff" else False
        #les compte eleve n'ont pas besoin de verifier email.
        is_active=True if data['type_acc'] != "staff" else False

        user=User.objects.create_user(username=f"U{user_id}", first_name=data['first_name'], last_name=data['last_name'], email=data['email'],password=data['password'],is_active=is_active, is_staff=is_staff)
        UserProfilePic(user=user).save()
        messages.success(request, f"Compte creer avec success, IDENTIFIANT : {user.username} MOT DE PASSE : 12345678  l'utilisateur devra changer le mot de passe lors de sa premiere connexion.")
        return render(request, 'main_tmpl/pages/add_account.html',data)




class UserSubscription(LoginRequiredMixin, View):
    
    def get(self,request):
        data={
            "user":request.user
        }
        return render(request, 'main_tmpl/pages/subscriptions.html',data)

def change_profile_pic(request):
    if not request.user.is_authenticated:
        messages.error(request, "Vous devez etre connecte pour modifier votre photo de profile!")
        return redirect("edit_account")
    
    if "user_id" in request.POST.dict().keys() and User.objects.filter(username=request.POST.dict().get('user_id')).exists():
        user=User.objects.get(username=request.POST.dict().get('user_id'))
    else:
        messages.error(request,"utilisateur non reconnu!")
        return redirect("edit_account")

    if request.method == "POST":
        file=request.FILES['photo']
        user_profile_pic=user.profile_pic if UserProfilePic.objects.filter(user=user).exists() else None
        if user_profile_pic is None:
            UserProfilePic(user=user, photo=file).save()
            messages.success(request, "Votre photo de profile a etait modifier avec success")
        else:
            user_profile_pic.photo=file
            user_profile_pic.save()
            messages.success(request, "Votre photo de profile a etait modifier avec success")
    else:
        messages.erro(request,"Vous devez soumetre une requete POST pour modifier une photo de profile") 
    return redirect(f"/edit_account?user_id={user.username}")



def reset_password(request):
    user_id=request.GET.dict().get("user_id",None)
    if not request.user.is_superuser:
        messages.error(request, "Seul un admin peut reinitialiser un mot de passe!")
    else:
        if user_id:
            try:
                user=User.objects.get(username=user_id)
                user.set_password("12345678")
                user.save()
                messages.success(request, "Mot de passe reinitialiser avec success!")
            except:
                messages.error(request, "compte utilisateur introuvable!")
    return redirect("users_list")



def download_doc(request):
    doc_ref=request.GET.dict().get("doc_ref",None)
    if doc_ref:
        try:
            doc=MdDocs.objects.get(ref=doc_ref)
        except:
            pass
    if doc:
        response=FileResponse(doc.doc.open('rb'))
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(doc.doc.name)}"'
        return response
        
        
    if "next" in request.GET.dict.get("next",None):
        return redirect(request.GET.dict().get("next"))
    else:
        return redirect("mddocs_list")

def share_doc(request):
    next_p=request.GET.dict().get("next", None)
    if request.user.is_authenticated:
        #must be owner
        code_ref=request.GET.dict().get("doc_ref", None)
        try:
            doc=MdDocs.objects.get(ref=code_ref)
            if doc.user == request.user:
                doc.is_public=True
                doc.save()
                messages.success(request, "Reussi le document est maintenant partager avec le public")
                return redirect(f"/show_document?doc_ref={doc.ref}")
            else:
                messages.error(request, "Seul le proprietaire peut partager le fichier dans le domaine public")
        except:
            messages.error(request, "doc ref manquant ou impossible de retrouver le fichier")
    else:
        messages.error(request, "vous devez etre connecter pour partager le doc!")
    return redirect(next_p if next_p else "mddocs_list")

def unshare_doc(request):
    next_p=request.GET.dict().get("next", None)
    if request.user.is_authenticated:
        #must be owner
        code_ref=request.GET.dict().get("doc_ref", None)
        try:
            doc=MdDocs.objects.get(ref=code_ref)
            if doc.user == request.user:
                doc.is_public=False
                doc.save()
                messages.success(request, "Reussi, le document n'es plus accessible en public")
                return redirect(f"/show_document?doc_ref={doc.ref}")
            else:
                messages.error(request, "Seul le proprietaire peut partager le fichier dans le domaine public")
        except Exception as exc:
            print(exc)
            messages.error(request, "doc ref manquant ou impossible de retrouver le fichier")
    else:
        messages.error(request, "vous devez etre connecter pour partager le doc!")
    return redirect(next_p if next_p else "mddocs_list")


def logout_view(request):
    logout(request)
    return redirect("user_login")

#------------25/02/2026===============================
#=====================================================
def delete_doc(request):
    next_url=request.GET.dict().get("next",None)
    doc_ref=request.GET.dict().get("doc_ref",None)
    if request.method == "GET":
        if request.user.is_authenticated:
            try:
                doc=MdDocs.objects.get(ref=doc_ref)
                if doc.user == request.user:
                    doc.delete()
                else:
                    messages.error(request,"Seul le proprietaire peu supprimer ce document")
                    return redirect(f"/show_document?doc_ref={doc_ref}")
                return redirect("mddocs_list")
            except Exception as exc:
                print(exc)
                messages.error(request,"Ops! Quelque chose s'est mal passer")
                return redirect(f"/show_document?doc_ref={doc_ref}")
        else:
            return redirect("user_login")
    else:
        messages.error(request, "Method not allowed")
        return redirect(f"/show_document?doc_ref={doc_ref}")

class EditMdDocInfos(LoginRequiredMixin, View):

    def get(self, request):
        try:
            doc=MdDocs.objects.get(ref=request.GET.dict().get("doc_ref", None))
        except:
            messages.error(request, "Ce document n'existe pas /plus")
            if "next" in request.GET.dict().keys():
                return redirect(request.GET.dict().get("next"))
            else:
                return redirect("mddocs_list")
                
        data={
            "user":request.user,
            "doc":doc

        }

        return render(request, 'main_tmpl/pages/edit_document_infos.html',data)
    
    def post(self,request):
        doc_ref=request.POST.dict().get("doc_ref",None)
        doc_title=request.POST.dict().get("doc_title",None)
        doc_share=request.POST.dict().get("partage",None)
        share=None

        try:
            doc=MdDocs.objects.get(ref=doc_ref)
            if doc.user != request.user:
                messages.error(request, "Seul le proprietaire de ce document peut le modifier")
                return redirect(f"/show_document?doc_ref={doc_ref}")
            if len(doc_title ) >= 3 and doc_title != doc.title:
                doc.title=doc_title
                doc.save()
                messages.success(request, "Le titre du document a etait modifier avec success!")
            
            if doc_share == "no" and doc.is_public:
                share=False
                messages.success(request, "Le partager en public a etait desactiver")
            elif doc_share == "yes" and not doc.is_public:
                share=True
                messages.success(request, "Le document est maintenant partager avec le public!")
            if share is not None:
                doc.is_public=share
                doc.save()

                
        except Exception as exc:
            print(exc)
            messages.error(request,"Ops! nous ne parvenons pas a recuperer ce document")

        return redirect(f"/show_document?doc_ref={doc_ref}")
