"""Idempotent startup seed. Run once on container boot (see docker-compose)."""
from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models import User, Asset
from app.models.common import Role, Criticality


def seed() -> None:
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.email == settings.SEED_ADMIN_EMAIL).first():
            db.add(
                User(
                    name="Default Admin",
                    email=settings.SEED_ADMIN_EMAIL,
                    password_hash=hash_password(settings.SEED_ADMIN_PASSWORD),
                    role=Role.ADMINISTRATOR,
                )
            )
            print(f"[seed] created admin {settings.SEED_ADMIN_EMAIL}")

        if not db.query(Asset).filter(Asset.hostname == "UBUNTU-SERVER-01").first():
            db.add(
                Asset(
                    hostname="UBUNTU-SERVER-01",
                    os="Ubuntu 22.04",
                    ip="192.168.56.20",
                    owner="lab",
                    environment="lab",
                    criticality=Criticality.HIGH,
                    agent_status="online",
                )
            )
            print("[seed] created sample asset UBUNTU-SERVER-01")

        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    if settings.SEED_ON_STARTUP:
        seed()
    else:
        print("[seed] SEED_ON_STARTUP is false; skipping")
