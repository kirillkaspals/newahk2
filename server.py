import os
import sqlite3
import threading
import time
from functools import wraps
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
import requests
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "super-secret-key-change-in-production")

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


def get_db_connection():
    if DATABASE_URL:
        import psycopg2

        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect("licenses.db")


def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    # Таблица ключей
    c.execute(
        "CREATE TABLE IF NOT EXISTS keys (key VARCHAR(255) PRIMARY KEY,"
        " is_active INTEGER)"
    )

    # Таблица администратора
    c.execute(
        "CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY,"
        " password_hash VARCHAR(255))"
    )

    # Создание пароля по умолчанию (admin123), если база пустая
    c.execute("SELECT COUNT(*) FROM admin")
    row = c.fetchone()
    if row[0] == 0:
        default_hash = generate_password_hash("admin123")
        if DATABASE_URL:
            c.execute(
                "INSERT INTO admin (id, password_hash) VALUES (1, %s)",
                (default_hash,),
            )
        else:
            c.execute(
                "INSERT INTO admin (id, password_hash) VALUES (1, ?)",
                (default_hash,),
            )

    conn.commit()
    conn.close()


def verify_admin_password(password):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM admin WHERE id = 1")
    row = c.fetchone()
    conn.close()
    if row:
        return check_password_hash(row[0], password)
    return False


def update_admin_password(new_password):
    conn = get_db_connection()
    c = conn.cursor()
    new_hash = generate_password_hash(new_password)
    param = "%s" if DATABASE_URL else "?"
    c.execute(f"UPDATE admin SET password_hash = {param} WHERE id = 1", (new_hash,))
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Фоновый самопинг
def start_self_ping():
    def ping_loop():
        time.sleep(10)  # Даём серверу запуститься
        port = int(os.getenv("PORT", 5000))
        external_url = os.getenv("RENDER_EXTERNAL_URL")

        if external_url:
            ping_url = f"{external_url.rstrip('/')}/ping"
        else:
            ping_url = f"http://127.0.0.1:{port}/ping"

        while True:
            try:
                requests.get(ping_url, timeout=10)
                print(f"[Self-Ping] Успешный запрос к {ping_url}")
            except Exception as e:
                print(f"[Self-Ping] Ошибка запроса: {e}")
            time.sleep(300)  # 5 минут

    thread = threading.Thread(target=ping_loop, daemon=True)
    thread.start()


@app.route("/ping")
def ping():
    return jsonify({"status": "alive", "timestamp": time.time()}), 200


@app.route("/")
def home():
    return redirect(url_for("admin_panel"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if verify_admin_password(password):
            session["logged_in"] = True
            return redirect(url_for("admin_panel"))
        else:
            error = "Неверный пароль"

    html_login = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Авторизация | Панель Управления</title>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
            body { background: #1e1e2e; color: #cdd6f4; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
            .login-card { background: #2b2b3b; border: 1px solid #313244; padding: 40px; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }
            h2 { color: #89b4fa; text-align: center; margin-bottom: 25px; font-weight: 600; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 8px; font-size: 14px; color: #a6adc8; }
            input[type="password"] { width: 100%; padding: 12px; background: #181825; border: 1px solid #45475a; border-radius: 6px; color: #cdd6f4; font-size: 15px; outline: none; transition: border-color 0.2s; }
            input[type="password"]:focus { border-color: #89b4fa; }
            button { width: 100%; padding: 12px; background: #89b4fa; border: none; border-radius: 6px; color: #11111b; font-size: 15px; font-weight: bold; cursor: pointer; transition: background 0.2s; }
            button:hover { background: #b4befe; }
            .error { background: #f38ba8; color: #11111b; padding: 10px; border-radius: 6px; font-size: 14px; margin-bottom: 20px; text-align: center; font-weight: 600; }
        </style>
    </head>
    <body>
        <div class="login-card">
            <h2>Вход в Панель</h2>
            {% if error %}
                <div class="error">{{ error }}</div>
            {% endif %}
            <form method="POST">
                <div class="form-group">
                    <label>Пароль Администратора</label>
                    <input type="password" name="password" placeholder="Введите пароль" required autofocus>
                </div>
                <button type="submit">Войти</button>
            </form>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_login, error=error)


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_panel():
    conn = get_db_connection()
    c = conn.cursor()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add":
            new_key = request.form.get("key", "").strip()
            if new_key:
                if DATABASE_URL:
                    c.execute(
                        "INSERT INTO keys (key, is_active) VALUES (%s, 1) ON CONFLICT (key) DO UPDATE SET is_active = 1",
                        (new_key,),
                    )
                else:
                    c.execute(
                        "INSERT OR REPLACE INTO keys (key, is_active) VALUES (?, 1)",
                        (new_key,),
                    )
                flash("Ключ успешно добавлен", "success")

        elif action == "delete":
            key_to_del = request.form.get("key", "").strip()
            if key_to_del:
                param = "%s" if DATABASE_URL else "?"
                c.execute(f"DELETE FROM keys WHERE key = {param}", (key_to_del,))
                flash("Ключ удален", "warning")

        elif action == "change_password":
            current_pass = request.form.get("current_password", "")
            new_pass = request.form.get("new_password", "")

            if verify_admin_password(current_pass):
                if len(new_pass) >= 4:
                    update_admin_password(new_pass)
                    flash("Пароль успешно изменён", "success")
                else:
                    flash("Новый пароль должен быть не короче 4 символов", "error")
            else:
                flash("Неверный текущий пароль", "error")

        conn.commit()

    c.execute("SELECT key, is_active FROM keys")
    keys = c.fetchall()
    conn.close()

    html_admin = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Панель Администратора</title>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
            body { background: #1e1e2e; color: #cdd6f4; padding: 30px 15px; }
            .container { max-width: 750px; margin: 0 auto; }
            
            .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; background: #2b2b3b; padding: 20px; border-radius: 12px; border: 1px solid #313244; }
            .header h2 { color: #89b4fa; font-size: 22px; }
            .btn-logout { background: #f38ba8; color: #11111b; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 14px; }
            .btn-logout:hover { background: #eba0ac; }

            .card { background: #2b2b3b; padding: 25px; border-radius: 12px; border: 1px solid #313244; margin-bottom: 25px; }
            .card h3 { color: #cba6f7; margin-bottom: 15px; font-size: 18px; border-bottom: 1px solid #45475a; padding-bottom: 8px; }

            .form-row { display: flex; gap: 10px; }
            input[type="text"], input[type="password"] { flex: 1; padding: 12px; background: #181825; border: 1px solid #45475a; border-radius: 6px; color: #cdd6f4; font-size: 14px; outline: none; }
            input[type="text"]:focus, input[type="password"]:focus { border-color: #89b4fa; }

            button.btn-primary { padding: 12px 20px; background: #a6e3a1; color: #11111b; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
            button.btn-primary:hover { background: #94e2d5; }

            .key-list { list-style: none; }
            .key-item { background: #181825; border: 1px solid #313244; margin-bottom: 10px; padding: 12px 18px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
            .key-text { font-family: 'Consolas', monospace; font-size: 15px; font-weight: bold; color: #f9e2af; }
            
            .badge { padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; }
            .badge-active { background: rgba(166, 227, 161, 0.2); color: #a6e3a1; }
            
            .btn-del { background: #f38ba8; color: #11111b; border: none; border-radius: 6px; padding: 6px 12px; font-weight: bold; cursor: pointer; font-size: 13px; }
            .btn-del:hover { background: #eba0ac; }

            .alerts { margin-bottom: 20px; }
            .alert { padding: 12px; border-radius: 6px; margin-bottom: 10px; font-size: 14px; font-weight: 600; }
            .alert-success { background: #a6e3a1; color: #11111b; }
            .alert-warning { background: #f9e2af; color: #11111b; }
            .alert-error { background: #f38ba8; color: #11111b; }

            .pass-grid { display: grid; grid-template-columns: 1fr 1fr auto; gap: 10px; }
            @media (max-width: 600px) {
                .pass-grid, .form-row { flex-direction: column; grid-template-columns: 1fr; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Панель Управления Ключами</h2>
                <a href="{{ url_for('logout') }}" class="btn-logout">Выйти</a>
            </div>

            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <div class="alerts">
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                    </div>
                {% endif %}
            {% endwith %}

            <!-- Добавление ключа -->
            <div class="card">
                <h3>Выдать новый доступ</h3>
                <form method="POST" class="form-row">
                    <input type="text" name="key" placeholder="Введите лицензионный ключ" required>
                    <button type="submit" name="action" value="add" class="btn-primary">Выдать доступ</button>
                </form>
            </div>

            <!-- Список ключей -->
            <div class="card">
                <h3>Активные ключи ({{ keys|length }})</h3>
                <ul class="key-list">
                {% for key, active in keys %}
                    <li class="key-item">
                        <div>
                            <span class="key-text">{{ key }}</span>
                            <span class="badge badge-active" style="margin-left: 10px;">{{ 'Активен' if active else 'Заблокирован' }}</span>
                        </div>
                        <form method="POST" style="margin: 0;">
                            <input type="hidden" name="key" value="{{ key }}">
                            <button type="submit" name="action" value="delete" class="btn-del">Удалить</button>
                        </form>
                    </li>
                {% else %}
                    <li style="color: #a6adc8; text-align: center; padding: 10px;">Ключи пока не добавлены</li>
                {% endfor %}
                </ul>
            </div>

            <!-- Смена пароля -->
            <div class="card">
                <h3>Безопасность (Смена пароля)</h3>
                <form method="POST" class="pass-grid">
                    <input type="password" name="current_password" placeholder="Текущий пароль" required>
                    <input type="password" name="new_password" placeholder="Новый пароль" required>
                    <button type="submit" name="action" value="change_password" class="btn-primary" style="background: #89b4fa;">Сохранить</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_admin, keys=keys)


@app.route("/api/verify", methods=["POST"])
def verify_key():
    data = request.json or {}
    key = data.get("key", "").strip()

    conn = get_db_connection()
    c = conn.cursor()
    param = "%s" if DATABASE_URL else "?"
    c.execute(f"SELECT is_active FROM keys WHERE key = {param}", (key,))
    row = c.fetchone()
    conn.close()

    if row and row[0] == 1:
        return jsonify({"status": "ok", "message": "Доступ разрешен"})
    return jsonify(
        {"status": "error", "message": "Неверный или неактивный ключ"}
    ), 403


init_db()
start_self_ping()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
