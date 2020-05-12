from django.db import models

from .consts import *


class User(models.Model):
    username = models.CharField(max_length=USERNAME_LEN_MAX, unique=True)
    password = models.CharField(max_length=PASSWORD_LEN_MAX_REAL)

class Session(models.Model):
    """Browser session ID"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    uuid = models.CharField(max_length=UUID_LEN_MAX)

class Timer(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    t_start = models.DateTimeField('When timer was reset')