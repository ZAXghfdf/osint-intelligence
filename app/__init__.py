from . import database


def bootstrap() -> None:
    database.migrate()
    _ensure_admin()


def _ensure_admin() -> None:
    row = database.query_one("SELECT COUNT(*) AS c FROM users")
    if row and row["c"] == 0:
        from . import auth
        username = "admin"
        password = "ChangeMe_Admin1"
        auth.create_user(username, password, "admin", "admin@localhost", "Platform Admin")
        print("=" * 60)
        print("تم إنشاء مستخدم مسؤول افتراضي:")
        print(f"  المستخدم: {username}")
        print(f"  كلمة المرور: {password}")
        print("  غيّرها فورًا بعد أول تسجيل دخول.")
        print("=" * 60)
