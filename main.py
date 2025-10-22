# main.py
from flask import Flask, request, render_template, redirect, url_for, session, flash
import hashlib
import sqlite3
from functools import wraps
import random

DB_URI = "file:memdb1?mode=memory&cache=shared"
app = Flask(__name__, template_folder='html')
app.secret_key = "01234567890abcdefghijklmnopqrstuvwxyz"  # 看看這東西，不要在真實環境使用

# init and hold master connection（shared in-memory DB）
master_conn = sqlite3.connect(DB_URI, uri=True, check_same_thread=False)
master_conn.row_factory = sqlite3.Row
def init_db():
    cur = master_conn.cursor()
    cur.execute('''
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        phone TEXT,
        midterm REAL CHECK(midterm >= 0 AND midterm <= 100),
        final REAL CHECK(final >= 0 AND final <= 100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    ''')
    cur.execute('DELETE FROM users')
    cur.executemany('''
      INSERT INTO users (username, password_hash, phone, midterm, final)
      VALUES (?, ?, ?, ?, ?)
    ''', [
        ('Alice', hashlib.md5('alice'.encode('utf-8')).hexdigest(), '123-456-7890', 85, 60),
        ('Bob', hashlib.md5('bob'.encode('utf-8')).hexdigest(), '234-567-8901', 100, 98),
        ('Charles', hashlib.md5('charles'.encode('utf-8')).hexdigest(), '345-678-9012', 77, 80),
        ('David', hashlib.md5('david'.encode('utf-8')).hexdigest(), '456-789-0123', 65, 56),
        ('user888', hashlib.md5(f'{str(random.random())}'.encode('utf-8')).hexdigest(), '', 32, 40) # 直接複製我也沒轍，只好給一個隨機密碼了
    ])
    master_conn.commit()

init_db()

# 有漏洞版，直接將參數拼接到 SQL 字串中
def verify_user_vuln(username, raw_password):
    cur = master_conn.cursor()
    pw_hash = hashlib.md5(raw_password.encode('utf-8')).hexdigest()

    # SQLi
    query = "SELECT id, username FROM users WHERE username = '" + username + "' AND password_hash = '" + pw_hash + "';"
    print(query)
    cur.execute(query)
    row = cur.fetchone()
    if not row:
        return row, False
    return row, True

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash("請先登入。")
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

# login page
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user, f1 = verify_user_vuln(username, password)
        if f1:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash("登入成功。")
            next_url = request.args.get('next') or url_for('user')
            return redirect(next_url)
        else:
            flash("帳號或密碼錯誤。")
    return render_template('login.html')

# 登出
@app.route('/logout')
def logout():
    session.clear()
    flash("已登出。")
    return redirect(url_for('login'))

# 受保護頁面
@app.route('/user')
@login_required
def user():
    cur = master_conn.cursor()
    cur.execute("SELECT id, username, phone, midterm, final, created_at FROM users WHERE id = ?", (session['user_id'],))
    user = cur.fetchone()
    return render_template('user.html', user=user)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('user'))
    return redirect(url_for('login'))

@app.route('/edit_phone', methods=['GET', 'POST'])
@login_required
# 漏洞版，直接將參數拼接到 SQL 字串中
def edit_phone():
    cur = master_conn.cursor()
    user_id = session.get('user_id')

    if request.method == 'POST':
        new_phone = request.form.get('phone', '').strip()
        try:
            query = (
                "UPDATE users SET phone = '" + str(new_phone) +
                "' WHERE id = '" + str(user_id) + "';"
            )
            cur.execute(query)
            master_conn.commit()
            flash("電話已更新。")
            return redirect(url_for('user'))
        except Exception as e:
            master_conn.rollback()
            flash("更新失敗：" + str(e))
            return render_template('edit_phone.html', phone=new_phone)

    cur.execute("SELECT phone FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    phone = row['phone'] if row and 'phone' in row.keys() else ''
    return render_template('edit_phone.html', phone=phone)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)
