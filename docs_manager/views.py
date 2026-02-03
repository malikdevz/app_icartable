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

        return render(request, 'main_tmpl/pages/login.html')
    
    def post(self, request):
        data=request.POST.dict()
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
        data={
            'is_success':True
        }

        return render(request, "main_tmpl/pages/register.html",data)
    
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


class UserResetPassword(View):

    def get(self, request):

        return render(request, 'docs_tmpl/forgot_pass.html')
    
    def post(self, request):
        email=request.POST.dict().get('email', None)
        if not email_valide(email):
            messages.error(request, "Veuillez inserer une adresse email valide svp!")
            return render(request, 'docs_tmpl/forgot_pass.html',{"email":email})
        return redirect("reset_pass")
    
class ResetPassCodeCheck(View):

    def get(self, request):

        return render(request, 'docs_tmpl/check_rest_code.html')
    
    def post(self, request):

        return redirect("new_password")

class NewPassword(View):

    def get(self, request):

        return render(request, 'docs_tmpl/new_password.html')
    
    def post(self,request):
        data={'change_successs':True}
        return render(request, 'docs_tmpl/new_password.html',data)


class VerifyAccount(View):

    def get(self, request):
        data={}
        code=request.POST.get("code",None)
        if not request.session['user_id']:
            messages.error(request, "Vous devez etre connectez pour verifier votre compte!")
            return render(request, "docs_tmpl/verify_code.html")
        user=User.objects.get(username=request.session['user_id'])
        if user.is_active:
            #messages.success(request, "Bravo! votre compte est verifiez! vous pouvez profitez de nos services.")
            data['code_verif']=True

        return render(request, "docs_tmpl/verify_code.html",data)
    
    def post(self, request):
        data={}
        code=request.POST.get("code",None)
        if not request.session['user_id']:
            messages.error(request, "Vous devez etre connectez pour verifier votre compte!")
            return render(request, "docs_tmpl/verify_code.html")
        user=User.objects.get(username=request.session['user_id'])
        if user.is_active:
            messages.success(request, "Bravo! votre compte est verifiez! vous pouvez profitez de nos services.")
            return render(request, "docs_tmpl/verify_code.html")
        if not code:
            messages.error(request, "Veuillez inserer le code svp!")
            return render(request, "docs_tmpl/verify_code.html")
        try:
            check_code=VerificationCode.objects.filter(user=user, code=code).latest('created_at')
        except VerificationCode.DoesNotExist:
            messages.error(request, "Code invalide!, vous avez inserer un code invalide.")
            return render(request, "docs_tmpl/verify_code.html")
        if not check_code.is_valid():
            data['code_expiry']=True
            messages.error(request, "Code expire, vous avez depasser le delai de 10 minutes.")
            return render(request, "docs_tmpl/verify_code.html")
        else:
            #we activate this account
            try:
                user=User.objects.get(username=request.session['user_id'])
                user.is_active=True
                user.save()
            except User.DoesNotExist:
                messages.error(request, "Ce compte utilisateur n'existe pas/plus, veuillez vous reconnecter!")
                return render(request, "docs_tmpl/verify_code.html")
        data['code_verif']=True
        if request.session['is_reg']:
            data['user_identifiant']=request.session['user_id']
        messages.success(request, "Bravo!, code verifier avec success!")
        return render(request, "docs_tmpl/verify_code.html",data)


class Dashboard(LoginRequiredMixin, View):

    def get(self,request):
        data={}
        user=request.user
        data['user_id']=user.username
        data['first_name']=user.first_name
        data['last_name']=user.last_name
        return render(request, "main_tmpl/dashboard.html",data)


def logout_view(request):
    logout(request)
    return redirect("user_login")