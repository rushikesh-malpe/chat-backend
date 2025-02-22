# Generated by Django 5.1.2 on 2024-10-18 10:18

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Users",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                ("email", models.EmailField(max_length=254, unique=True)),
                ("otp", models.CharField(blank=True, max_length=6)),
                ("cts", models.DateTimeField(auto_now_add=True)),
                ("uts", models.DateTimeField(auto_now=True)),
                ("first_name", models.CharField(blank=True, max_length=30, null=True)),
                ("last_name", models.CharField(blank=True, max_length=30, null=True)),
                ("address", models.TextField(blank=True, null=True)),
                ("phone_number", models.TextField(blank=True, null=True)),
                ("profile_url", models.TextField(blank=True, null=True)),
            ],
            options={
                "db_table": "users",
            },
        ),
    ]
