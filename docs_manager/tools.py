from django.contrib.auth import authenticate
from django.contrib.auth import logout, login
from django.contrib.auth.models import User
from .models import BannedUsers,VerifiedUser,VerificationCode
from django.utils import timezone
import random
import string
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings



def check_user_access(user):
    """check user access
    return  -1 user desconnected, 
            -2 user is not verified, 
            -3 user are banned, 
            0 user is loged
    """
    if user.is_authenticated:
        #chech if user are verified
        if not VerifiedUser.objects.filter(user_id=user.username).exists():
            return -2
        #check if user are banned
        elif BannedUsers.objects.filter(user_id=user.username).exists():
            return -3
        return 0
    return -1

        

#login users
def login_user(data,request):
    user = authenticate(username=data['identifiant'], password=data['password'])
    if user is not None:
        login(request,user)
        request.session['identifiant']=user.username
        return {'logged':True, 'message':'Connexion etabli!','user':user}
    user=user=User.objects.filter(username=data['identifiant']).first()
    if user is None:
        return {'logged':False, 'message':f'Aucun compte trouver pour {data['identifiant']}','user':user}

    return {'logged':False, 'message':'Mot de passe incorrect!','user':user}

#hide a part of email
def hide_email_part(email):
    if '@' not in email:
        return -1
    name,domain=email.split("@")
    show_digit=3#afficher que le deux premier lettre de l'email
    if len(name) <= show_digit:
        #rien a masquer
        return email
    hidden_part = name[:show_digit] + '*' * (len(name) - show_digit)
    return f"{hidden_part}@{domain}"


#send verification code
def send_verification_code(user, title="Icartable App,Code de verification"):
    # Générer un code à 6 chiffres
    code = ''.join(random.choices(string.digits, k=6))
    expires_at = timezone.now() + timedelta(minutes=5)  # expire après 5 min

    VerificationCode.objects.create(user=user, code=code, expires_at=expires_at)
    try:
        send_mail(title,f"Votre code de verification est {code}.",settings.EMAIL_HOST_USER,[user.email],fail_silently=False)
    except:
        return -1

#chech le code de verification
def check_verif_code(user,data):
    """verifie le code de verification fourni par l'utilisateur
    retourne -1 = code invalide
             -2=  code expirer
             0= code valide
    """
    code=data.get("code",None)
    if not code:
        return -1
    try:
        check_code=VerificationCode.objects.get(user=user, code=code)
        if check_code.is_valid():
            check_code.delete()
            return 0
        else:
            check_code.delete()
            return -2
    except VerificationCode.DoesNotExist:
        return -1

#verifiez l'utilisateur
def verify_user(user):
    if not VerifiedUser.objects.filter(user_id=user.username).exists():
        VerifiedUser(user_id=user.username).save()
    return 0

#retirer la verification a un user
def unverify_user(user):
    try:
        VerifiedUser.objects.get(user_id=user.username).delete()
    except:
        pass
    return 0