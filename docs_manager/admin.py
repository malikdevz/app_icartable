from django.contrib import admin
from .models import (
    VerificationCode,
    UserProfilePic,
    MdDocs,
    MdDocsAttachedImages,
    MdDocsAttachedDivers,
    MdDocsAttachedAudio,
    MdDocsAttachedVideos
)

admin.site.register(VerificationCode)
admin.site.register(UserProfilePic)
admin.site.register(MdDocs)
admin.site.register(MdDocsAttachedImages)
admin.site.register(MdDocsAttachedDivers)
admin.site.register(MdDocsAttachedAudio)
admin.site.register(MdDocsAttachedVideos)
