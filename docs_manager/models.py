from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

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
