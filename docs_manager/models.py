from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.text import slugify
import os
import random
import string
from pathlib import Path
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError

def validate_images_size(value):
    max_size = 1 * 1024 * 1024  # 2MB
    if value.size > max_size:
        raise ValidationError("La taille maximale est 1MB.")

def validate_videos_size(value):
    max_size = 10 * 1024 * 1024  # 10MB
    if value.size > max_size:
        raise ValidationError("La taille maximale est 10MB.")

def validate_audio_size(value):
    max_size = 5 * 1024 * 1024  # 5MB
    if value.size > max_size:
        raise ValidationError("La taille maximale est 5MB.")

def validate_divers_size(value):
    max_size = 20 * 1024 * 1024  # 20MB
    if value.size > max_size:
        raise ValidationError("La taille maximale est 20MB.")

def user_directory_path(instance, filename):
    folder_name=slugify(instance.user.username)
    folder_name=f"user_{folder_name}_folder"
    ext = filename.split('.')[-1]  # récupérer extension
    new_filename = f"{slugify(instance.title)}.{ext}"

    return os.path.join(folder_name,instance.ref,new_filename)

def attached_images_dir(instance, filename):
    root=slugify(f"user_{instance.doc.user.username}_folder")
    doc_folder=os.path.join(root, instance.doc.ref)
    return os.path.join(doc_folder, "images",filename)

def attached_videos_dir(instance, filename):
    root=slugify(f"user_{instance.doc.user.username}_folder")
    doc_folder=os.path.join(root, instance.doc.ref)
    return os.path.join(doc_folder, "videos",filename)

def attached_audio_dir(instance, filename):
    root=slugify(f"user_{instance.doc.user.username}_folder")
    doc_folder=os.path.join(root, instance.doc.ref)
    return os.path.join(doc_folder, "audio",filename)

def attached_divers_dir(instance, filename):
    root=slugify(f"user_{instance.doc.user.username}_folder")
    doc_folder=os.path.join(root, instance.doc.ref)
    return os.path.join(doc_folder, "divers",filename)

def generate_doc_ref(model_class):
    while True:
        code_ref="".join(random.choices(string.ascii_uppercase, k=6))
        if not model_class.objects.filter(ref=code_ref).exists():
            return f"md{code_ref}".lower()

class VerificationCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_valid(self):
        return timezone.now() < self.expires_at
    
    def __str__(self):
        return f"{self.user.username}, {self.user.email}, {self.code}"


class BannedUser(models.Model):
    date_add=models.DateTimeField(auto_now_add=True)
    user_id=models.CharField(max_length=50)

    def __str__(self):
        return self.user_id

class UserProfilePic(models.Model):
    date_add=models.DateTimeField(auto_now_add=True)
    photo=models.ImageField(upload_to="users_profile_pics", default="users_profile_pics/default.jpg")
    user=models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile_pic")

    def __str__(self):
        return self.photo.url

class MdDocs(models.Model):
    date_add=models.DateTimeField(auto_now_add=True)
    title=models.CharField(max_length=200)
    ref=models.CharField(max_length=10, unique=True, editable=False)
    doc=models.FileField(upload_to=user_directory_path)
    is_public=models.BooleanField(default=False)
    user=models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_docs")

    def __str__(self):
        return self.title
    
    def save(self,*args, **kwargs):
        if not self.ref:
            self.ref=generate_doc_ref(MdDocs)
        super().save(*args, **kwargs)

    @property
    def doc_name(self):
        return os.path.basename(self.doc.name)

class MdDocsAttachedImages(models.Model):
    date_add=models.DateTimeField(auto_now_add=True)
    doc=models.ForeignKey(MdDocs, on_delete=models.CASCADE, related_name="docs_images")
    photo=models.ImageField(upload_to=attached_images_dir, validators=[
            FileExtensionValidator(
                allowed_extensions=['jpg', 'jpeg', 'png','webp']
            ),
            validate_images_size
        ])
    
    def __str__(self):
        return f"{self.doc.ref}-{self.photo.url}"

class MdDocsAttachedVideos(models.Model):
    date_add=models.DateTimeField(auto_now_add=True)
    doc=models.ForeignKey(MdDocs, on_delete=models.CASCADE, related_name="docs_videos")
    video=models.FileField(upload_to=attached_videos_dir, validators=[
            FileExtensionValidator(
                allowed_extensions=['mp4', 'mkv', 'mpg']
            ),
            validate_videos_size
        ])
    
    def __str__(self):
        return f"{self.doc.ref}-{self.video.url}"

class MdDocsAttachedAudio(models.Model):
    date_add=models.DateTimeField(auto_now_add=True)
    doc=models.ForeignKey(MdDocs, on_delete=models.CASCADE, related_name="docs_audio")
    audio=models.FileField(upload_to=attached_audio_dir, validators=[
            FileExtensionValidator(
                allowed_extensions=['mp3', 'acc','wav']
            ),
            validate_audio_size
        ])
    
    def __str__(self):
        return f"{self.doc.ref}-{self.audio.url}"

class MdDocsAttachedDivers(models.Model):
    date_add=models.DateTimeField(auto_now_add=True)
    doc=models.ForeignKey(MdDocs, on_delete=models.CASCADE, related_name="docs_divers")
    file=models.FileField(upload_to=attached_divers_dir, validators=[
            FileExtensionValidator(
                allowed_extensions=['pdf','ggb','zip']
            ),
            validate_divers_size
        ])
    
    def __str__(self):
        return f"{self.doc.ref}-{self.file.url}"

