import os
import sqlite3
from flask import Flask, jsonify, redirect, render_template_string, request

app = Flask(__name__)

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
    c.execute("CREATE TABLE IF NOT EXISTS keys (key VARCHAR(255) PRIMARY KEY, is_active INTEGER)")
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return redirect("/admin")

@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    conn = get_db_connection()
    c = conn.cursor()

    if request.method == "POST":
        new_key = request.form.get("key", "").strip()
        action = request.form.get("action")

        if action == "add" and new_key:
            if DATABASE_URL:
                c.execute(
                    "INSERT INTO keys (key, is_active) VALUES (%s, 1) ON CONFLICT (key) DO UPDATE SET is_active = 1",
                    (new_key,)
                )
            else:
                c.execute("INSERT OR REPLACE INTO keys (key, is_active) VALUES (?, 1)", (new_key,))
        elif action == "delete" and new_key:
            param = "%s" if DATABASE_URL else "?"
            c.execute(f"DELETE FROM keys WHERE key = {param}", (new_key,))

        conn.commit()

    c.execute("SELECT key, is_active FROM keys")
    keys = c.fetchall()
    conn.close()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Панель Администратора</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f9; }
            .container { max-width: 600px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            input[type="text"] { width: 65%; padding: 8px; font-size: 14px; }
            button { padding: 8px 15px; font-size: 14px; cursor: pointer; }
            ul { list-style: none; padding: 0; }
            li { background: #eee; margin: 5px 0; padding: 10px; display: flex; justify-content: space-between; align-items: center; }
            .btn-del { background: #ff4d4d; color: white; border: none; border-radius: 4px; padding: 5px 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Панель Управления Ключами</h2>
            <form method="POST">
                <input type="text" name="key" placeholder="Введите новый ключ" required>
                <button type="submit" name="action" value="add">Выдать доступ</button>
            </form>
            <h3>Активные ключи:</h3>
            <ul>
            {% for key, active in keys %}
                <li>
                    <span><b>{{ key }}</b> — {{ 'Активен' if active else 'Заблокирован' }}</span>
                    <form method="POST" style="margin: 0;">
                        <input type="hidden" name="key" value="{{ key }}">
                        <button type="submit" name="action" value="delete" class="btn-del">Удалить</button>
                    </form>
                </li>
            {% endfor %}
            </ul>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, keys=keys)

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
    return jsonify({"status": "error", "message": "Неверный или неактивный ключ"}), 403

init_db()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)