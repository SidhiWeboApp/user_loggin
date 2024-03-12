from django.db import models

# Create your models here.
class Testing(models.Model):
    field1 = models.CharField(max_length=100, null=True, blank=True)