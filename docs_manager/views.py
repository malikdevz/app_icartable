from django.shortcuts import render,redirect
from django.contrib.auth import authenticate
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
from django.contrib.auth import logout, login
from django.contrib.auth.mixins import LoginRequiredMixin

def send_verification_code(user, title="ICARTABLE!"):
    # Générer un code à 6 chiffres
    code = ''.join(random.choices(string.digits, k=6))
    expires_at = timezone.now() + timedelta(minutes=10)  # expire après 10 min

    VerificationCode.objects.create(user=user, code=code, expires_at=expires_at)

    send_mail(title,f"Hello {user.first_name}, votre code de confirmation est: {code}. valable pour 10 minutes",settings.EMAIL_HOST_USER,[user.email],fail_silently=False)



def userid_code_generator():
    caracteres = string.ascii_uppercase + string.digits
    return ''.join(random.choice(caracteres) for _ in range(6))

#Outils
def email_valide(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_password(password):
    # Étape 1 : Vérifier la longueur
    if len(password) < 6:
        return False
    
    # Étape 2 : Vérifier les types de caractères
    a_lettre = any(c.isalpha() for c in password)
    a_chiffre = any(c.isdigit() for c in password)
    # On vérifie si le caractère est dans la liste des symboles (!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)
    a_symbole = any(c in string.punctuation for c in password)
    
    # Le mot de passe est valide seulement si TOUTES les conditions sont vraies
    return a_lettre and a_chiffre and a_symbole



class UserLogin(View):

    def get(self, request):
        if request.user.is_authenticated and request.user.is_active:
            return redirect("dashboard")
        return render(request, 'main_tmpl/pages/login.html')
    
    def post(self, request):
        data=request.POST.dict()
        if data['identifiant'] and User.objects.filter(username=data['identifiant']).exists():
            user=User.objects.get(username=data['identifiant'])
            request.session['user_id']=user.username
            if not user.is_active:
                send_verification_code(user, title="ICARTABLE! Code de verification") 
                return redirect("verify_code")


        user = authenticate(username=data['identifiant'], password=data['password'])
        if user is not None:
            login(request,user)
            request.session['identifiant']=data['identifiant']
            if request.GET.dict().get("next"):
                return redirect(request.GET.dict().get("next"))
            return redirect("dashboard")
        messages.error(request, "Password et/ou Identifiant invalide!")
        return redirect("user_login")


class UserReg(View):

    def get(self, request):
        return render(request, "main_tmpl/pages/register.html")
    
    def post(self,request):
        user_data={}
        data=request.POST.dict()
        first_name=data.get("first_name", None)
        last_name=data.get("last_name", None)
        email=data.get("email", None)
        password=data.get("password", None)
        confirm_pass=data.get("confirm_pass", None)
        type_acc=data.get("type_acc", None)

        #processing data
        if not first_name.isalpha() or not last_name.isalpha():
            messages.error(request, "Nom et/ou Prenom contient des caracteres non autoriser")
            return render(request, "main_tmpl/pages/register.html",data)
        
        if not email_valide(email):
            messages.error(request, "vous devez renseignez une adresse email valide")
            return render(request, "main_tmpl/pages/register.html",data)
        
        if not password == confirm_pass:
            messages.error(request, "Le password et confirm pass doivent etre identique")
            return render(request, "main_tmpl/pages/register.html",data)
        
        if not check_password(password):
            messages.error(request, "Le mot de passe doit etre superieur ou egale a 6 caracteres, vous devez melanger les lettre, chiffres et caracteres speciaux pour un mot de passe solide.")
            return render(request, "main_tmpl/pages/register.html",data)
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Cette adresse email est deja utiliser pour un autre compte")
            return render(request, "main_tmpl/pages/register.html",data)

        user_id=userid_code_generator()
        while User.objects.filter(username=user_id).exists():
            user_id=userid_code_generator()
        #type de compte
        is_staff=True if type_acc == "staff" else False

        user=User.objects.create_user(username=f"U{user_id}", password=password, email=email,first_name=first_name, last_name=last_name, is_staff=is_staff,is_active=False)
        data['user']=user
        request.session['user_id']=user.username
        request.session['is_reg']=True
        send_verification_code(user, title="ICARTABLE, Code de verification de votre compte")
        return redirect("verify_code")


class VerifyAccount(View):

    def get(sefl, request):
        return render(request, "main_tmpl/pages/verify_code.html")
    
    def post(self, request):
        data={
            "code":request.POST.dict().get("code"),
            "user":User.objects.get(username=request.session['user_id']) if 'user_id' in request.session.keys() and User.objects.filter(username=request.session['user_id']).exists() else None
        }
        if not data['user']:
            messages.error(request, "Utilisateur non reconnu, etes vous connecter ?")
            return render(request, "main_tmpl/pages/verify_code.html",data)

        if data['code']:
            try:
                check_code=check_code=VerificationCode.objects.filter(user=data['user'], code=data['code']).latest('created_at')
                if check_code.is_valid():
                    data['user'].is_active=True
                    data['user'].save()
                    data['activated']=True
                    return render(request, "main_tmpl/pages/verify_code.html",data)
                data['expiry_code']=True
                messages.error(request, "Le delai pour ce code est deja exprirer!")
            except VerificationCode.DoesNotExist:
                messages.error(request, "Ce code est invalide!")
        return render(request, "main_tmpl/pages/verify_code.html",data)


class UserResetPassword(View):

    def get(self, request):

        return render(request, 'main_tmpl/pages/forgot_pass.html')
    
    def post(self, request):
        data={
            "email":request.POST.dict().get('email', None)
        }

        if not email_valide(data['email']):
            messages.error(request, "Veuillez inserer une adresse email valide svp!")
            return render(request, 'main_tmpl/pages/forgot_pass.html',data)

        if not User.objects.filter(email=data['email']).exists():
            messages.error(request, "Aucun utilisateur trouve avec cette adresse email!")
            return render(request, 'main_tmpl/pages/forgot_pass.html',data)
        user=User.objects.get(email=data['email'])
        request.session['user_id']=user.username
        send_verification_code(user, title="ICARTABLE! Code de verification")

        return redirect("reset_pass")
    
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

        

class NewPassword(View):

    def get(self, request):

        return render(request, 'main_tmpl/pages/new_password.html')
    
    def post(self,request):
        data={
            "password":request.POST.dict().get('password'),
            "confirm_password":request.POST.dict().get('confirm_pass')
        }
        if not data['password'] == data['confirm_password']:
            messages.error(request, "Le password et confirm pass doivent etre identique")
        if not check_password(data['password']):
            messages.error(request, "Le mot de passe doit etre superieur ou egale a 6 caracteres, vous devez melanger les lettre, chiffres et caracteres speciaux pour un mot de passe solide.")
        if not "user_id" in request.session.keys():
            messages.error(request,"Votre session a expirer, veuillez recommencer!")
        
        try:
            user=User.objects.get(username=request.session['user_id'])
            user.set_password(data['password'])
            user.save()
            data['is_done']=True
            data['user']=user
        except:
            messages.error(request,"Votre session a expirer, veuillez recommencer!")

        return render(request, 'main_tmpl/pages/new_password.html',data)


class Dashboard(LoginRequiredMixin, View):

    def get(self,request):
        data={
            "user":request.user
        }
        if not data['user'].is_active:
            return redirect("user_logout")
        request.session['user_id']=data['user'].username
        return render(request, "main_tmpl/dashboard.html",data)


class UserAccount(LoginRequiredMixin, View):

    def get(self,request):
        data={
            "user":request.user
        }
        return render(request, 'main_tmpl/pages/user_account.html', data)

class EditAccount(LoginRequiredMixin, View):

    def get(self, request):
        return render(request, 'main_tmpl/pages/edit_account.html')
    

    def post(self, request):
        fdbck=False
        data={
            "first_name":request.POST.dict().get("first_name",None),
            "last_name":request.POST.dict().get("last_name", None),
            "identifiant":request.POST.dict().get("identifiant", None),
            "email": request.POST.dict().get("email", None)
        }
        
        try:
            user=User.objects.get(username=data['identifiant'])
            data['user']=user

            if data['email'] and user.email != data['email']:
                if email_valide(data['email']):
                    if User.objects.filter(email=data['email']).exists():
                        messages.error(request, "Cette adresse email est deja associer a un compte")
                        return render(request, 'main_tmpl/pages/edit_account.html',data)
                    else:
                        #change email warning
                        data['confirm_change_email']=True
                        request.session['email']=data['email']
                else:
                    messages.error(request, "Veuillez inserer une adresse email valide svp!")
                    return render(request, 'main_tmpl/pages/edit_account.html',data)

            if data['first_name'] and user.first_name != data['first_name']:
                user.first_name=data['first_name']
                user.save()
                messages.success(request, "Nom modifier avec success ")
            if data['last_name'] and data['last_name'] != user.last_name:
                user.last_name=data['last_name']
                user.save() 
                messages.success(request, "Prenom modifier avec success ")
        except Exception as exc:
            messages.error(request, "Cette utilisateur n'existe plus!")
        return render(request, 'main_tmpl/pages/edit_account.html',data)

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
        data={
            "users":User.objects.all()
        }
        return render(request, 'main_tmpl/pages/users_list.html',data)

#-----------------------



def send_code(request):
    next_url=request.GET.dict().get("next")
    if "user_id" in request.session.keys():
        user=User.objects.get(username=request.session['user_id'])
    else:
        if request.user.is_authenticated:
            user=request.user
    send_verification_code(user, title="ICARTABLE! Code de verification")
    messages.success(request, "Envoyer Ok!")
    if next_url:
        return redirect(next_url)
    return redirect("verify_code")

def logout_view(request):
    logout(request)
    return redirect("user_login")