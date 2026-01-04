from django.core.management.base import BaseCommand
from django.db import transaction
from normal_users.models import NormalUser, PostItem, PostVersion
from normal_users.utils import normalize_media_url
import json

class Command(BaseCommand):
    help = "Normalize media URLs in DB to relative paths (strip protocol+host)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Do not write changes, just print what would change",
        )

    def handle(self, *args, **options):
        dry_run = options.get("dry_run", False)
        changed = 0
        with transaction.atomic():
            # 1) NormalUser.avatar_url
            for u in NormalUser.objects.all().only("id", "avatar_url"):
                new = normalize_media_url(u.avatar_url)
                if new and new != u.avatar_url:
                    self.stdout.write(f"NormalUser#{u.id} avatar_url: {u.avatar_url} -> {new}")
                    changed += 1
                    if not dry_run:
                        u.avatar_url = new
                        u.save(update_fields=["avatar_url"])

            # 2) PostItem.file_url
            for it in PostItem.objects.all().only("id", "file_url"):
                new = normalize_media_url(it.file_url)
                if new and new != it.file_url:
                    self.stdout.write(f"PostItem#{it.id} file_url: {it.file_url} -> {new}")
                    changed += 1
                    if not dry_run:
                        it.file_url = new
                        it.save(update_fields=["file_url"])

            # 3) PostVersion.items_json snapshots
            for pv in PostVersion.objects.all().only("id", "items_json"):
                try:
                    snap = json.loads(pv.items_json or "[]")
                except Exception:
                    snap = []
                updated = False
                for it in snap:
                    if "file_url" in it:
                        new = normalize_media_url(it.get("file_url"))
                        if new and new != it.get("file_url"):
                            it["file_url"] = new
                            updated = True
                if updated:
                    changed += 1
                    self.stdout.write(f"PostVersion#{pv.id} items_json normalized")
                    if not dry_run:
                        pv.items_json = json.dumps(snap)
                        pv.save(update_fields=["items_json"])

            if dry_run:
                self.stdout.write(self.style.WARNING(f"DRY RUN: {changed} changes would be applied."))
            else:
                self.stdout.write(self.style.SUCCESS(f"Normalization complete. {changed} changes applied."))
