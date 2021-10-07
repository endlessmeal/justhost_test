from django.db import models


class Abuses(models.Model):
    ref = models.CharField(max_length=10, null=False, unique=True)
    status = models.CharField(max_length=10, null=False)
    created = models.DateTimeField(max_length=10, null=False, auto_now=True)
    domains = models.TextField(null=True, blank=True, default=None)
    ip = models.GenericIPAddressField()
    description = models.TextField(null=False)
