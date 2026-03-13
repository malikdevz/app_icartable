from django.contrib.auth import authenticate
from django.contrib.auth import logout, login
from django.contrib.auth.models import User
from .models import BannedUsers,VerifiedUser,VerificationCode,UserInformations
from django.utils import timezone
import random
import string
import re
from datetime import timedelta
from datetime import datetime
from django.core.mail import send_mail
from django.conf import settings


def check_and_format_date(date_string):
    """
    Convertit une chaîne 'dd/mm/yyyy' en objet date.
    Exemple valide : 03/11/1990
    """
    try:
        date_obj = datetime.strptime(date_string, "%d/%m/%Y").date()
        return date_obj
    except:
        return None

def userid_code_generator():
    caracteres = string.ascii_uppercase + string.digits
    return ''.join(random.choice(caracteres) for _ in range(6))

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

def email_valide(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_user_access(user):
    """check user access
    return  -1 user desconnected, 
            -2 user is not verified, 
            -3 user are banned, 
            0 user is loged
    """
    if user.is_authenticated:
        #check if user are banned
        if BannedUsers.objects.filter(user_id=user.username).exists():
            return -3
        #chech if user are verified
        elif not VerifiedUser.objects.filter(user_id=user.username).exists():
            return -2
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

def checking_user_data(data):
    if not data['first_name'].isalpha() or not data['last_name'].isalpha():
        return {"success":False, "message":"Le nom et le prenom ne doit contenir que des lettres alphabetique"}
    
    if not email_valide(data['email']):
        return {"success":False, "message":"Adresse email invalide"}
    
    if not data['password'] == data['confirm_pass']:
        return {"success":False, "message":"Le mot de passe  et confirmer mot de passe doivent etre identique"}
    
    if not check_password(data['password']):
        return {"success":False, "message":"Mot de passe doit etre superieur ou egale a 6 caractere, melanger chiffre, lettres, et symboles exemple: skoub43@# (n'utiliser pas celui ci, c'est juste un exemple)"}
    
    if User.objects.filter(email=data['email']).exists():
        return {"success":False, "message":"Cette adresse email est deja utiliser par un autre compte"}
    
    if not check_and_format_date(data['date_naissance']):
        return {"success":False, "message":"Date naissance format invalide. Utilisez dd/mm/yyyy (ex: 03/11/1990)"}

    return {"success":True, "message":"all is okay"}

def create_user_account(request,data):
    """create user
    return -1 if something wrong
            user if all okay
    """
    #generate user identifiant
    user_id=userid_code_generator()
    while User.objects.filter(username=user_id).exists():
        user_id=userid_code_generator()

    #type de compte
    is_staff=True if data['type_acc'] == "staff" else False
    #create user
    user=User.objects.create_user(username=f"U{user_id}", password=data['password'], email=data['email'],first_name=data['first_name'], last_name=data['last_name'], is_staff=is_staff,is_active=True)
    login_res = authenticate(username=user.username, password=data['password'])

    if login_res is not None:
        if not UserInformations.objects.filter(user=user).exists():
            user_info=UserInformations(user=user)
            user_info.save()

            if check_and_format_date(data['date_naissance']):
                user_info.date_naissance=check_and_format_date(data['date_naissance'])

            if data['sex']:
                user_info.sex=data['sex']
            user_info.save() 

        login(request, login_res)
        request.session['user_id']=user.username
        return user
    return -1

def change_user_password(user, data):
    """this fonction will change user password
    return -1 if old password incorrect
           -2 if weak new password
           -3 password and confirm new password didnt match
    """
    if not user.check_password(data['password']):
        return -1
    """if not check_password(data['new_pass']):
        return -2"""
    if data['new_pass'] != data['confirm_pass']:
        return -3
    user.set_password(data['new_pass'])
    user.save()
    return 0

def check_user_email(data):
    """Verifie l'email de l'utilisateur
    return -1 si le format de l'email est invalide
           -2 si aucun utilisateur trouver avec cette email
           0 si l'email est valide et qu'il appartient a un utilisateur
    """
    if not email_valide(data.get("email",None)):
        return -1
    if not User.objects.filter(email=data['email']).exists():
        return -2
    return 0

def set_user_password(user,data):
    """Reinitilaise le mot de passe de l'utilisateur
    return -1 si le mot de passe est faible
           -2 si le mot de passe et confirm pass sont pas identique
           0 si le mot de passe de l'utilisateur a etait modifier avec success
    """
    if not check_password(data['new_pass']):
        return -1
    if data['new_pass'] != data['confirm_pass']:
        return -2
    user.set_password(data['new_pass'])
    user.save()
    return 0
    
