# Generated by Django 3.0.6 on 2020-05-11 01:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('timer', '0003_auto_20200510_2201'),
    ]

    operations = [
        migrations.AlterField(
            model_name='session',
            name='uuid',
            field=models.CharField(max_length=36),
        ),
        migrations.AlterField(
            model_name='user',
            name='password',
            field=models.CharField(max_length=64),
        ),
    ]