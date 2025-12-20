from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('normal_users', '0004_passwordresetsession'),
    ]

    operations = [
        migrations.AddField(
            model_name='normaluser',
            name='public_username',
            field=models.CharField(max_length=50, unique=True, null=True, blank=True),
        ),
        migrations.AddField(
            model_name='normaluser',
            name='avatar_url',
            field=models.URLField(null=True, blank=True),
        ),
    ]
