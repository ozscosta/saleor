# Generated by Django 3.2.13 on 2022-06-06 13:28

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import saleor.thumbnail.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("product", "0170_rewrite_digitalcontenturl_orderline_relation"),
    ]

    operations = [
        migrations.CreateModel(
            name="Thumbnail",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("image", models.ImageField(upload_to="thumbnails")),
                (
                    "size",
                    models.PositiveIntegerField(
                        validators=[saleor.thumbnail.models.validate_thumbnail_size]
                    ),
                ),
                (
                    "format",
                    models.CharField(
                        blank=True,
                        choices=[("webp", "WebP"), ("avif", "AVIF")],
                        max_length=32,
                        null=True,
                    ),
                ),
                (
                    "category",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="thumbnails",
                        to="product.category",
                    ),
                ),
                (
                    "collection",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="thumbnails",
                        to="product.collection",
                    ),
                ),
                (
                    "product_media",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="thumbnails",
                        to="product.productmedia",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="thumbnails",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]