from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = "your-secret-key-123"  # 可以稍后更改

# 配置
MEMBERSHIP_PRICE = "29.9"
ADMIN_EMAIL = "your-email@example.com"

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  email TEXT UNIQUE,
                  password TEXT,
                  paid INTEGER DEFAULT 0,
                  payment_date TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS pending_payments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  email TEXT,
                  payment_proof TEXT,
                  submitted_date TEXT,
                  status TEXT DEFAULT 'pending')''')
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('register'))
        return f(*args, **kwargs)
    return decorated_function

def payment_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('register'))
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT paid FROM users WHERE username=?", (session['user'],))
        user = c.fetchone()
        conn.close()
        
        if not user or user[0] != 1:
            return redirect(url_for('payment_manual'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not username or not email or not password:
            return render_template('register.html', error="请填写所有字段")
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                     (username, email, password))
            conn.commit()
            conn.close()
            
            session['user'] = username
            session['email'] = email
            return redirect(url_for('payment_manual'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="用户名或邮箱已存在")
    
    return render_template('register.html')

# ========== 在这里添加登录路由 ==========
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 简单的验证
        if not username or not password:
            return render_template('login.html', error="请填写用户名和密码")
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user'] = username
            session['email'] = user[2]  # 邮箱字段
            # 检查是否已支付
            if user[4] == 1:  # paid字段
                return redirect(url_for('members'))
            else:
                return redirect(url_for('payment_manual'))
        else:
            return render_template('login.html', error="用户名或密码错误")
    
    return render_template('login.html')
# ========== 登录路由结束 ==========

@app.route('/payment-manual')
@login_required
def payment_manual():
    return render_template('payment_manual.html', 
                          price=MEMBERSHIP_PRICE,
                          admin_email=ADMIN_EMAIL)

@app.route('/submit-payment-proof', methods=['POST'])
@login_required
def submit_payment_proof():
    if request.method == 'POST':
        payment_proof = request.form['payment_proof']
        
        if not payment_proof:
            return render_template('payment_manual.html', 
                                 error="请提供支付凭证",
                                 price=MEMBERSHIP_PRICE,
                                 admin_email=ADMIN_EMAIL)
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO pending_payments (username, email, payment_proof, submitted_date) VALUES (?, ?, ?, ?)",
                 (session['user'], session['email'], payment_proof, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        return render_template('payment_submitted.html')
    
    return redirect(url_for('payment_manual'))

@app.route('/admin/verify-payments')
def admin_verify_payments():
    admin_password = request.args.get('password')
    if admin_password != "admin123":  # 简单密码验证
        return "未授权访问", 401
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM pending_payments WHERE status='pending' ORDER BY submitted_date DESC")
    pending_payments = c.fetchall()
    conn.close()
    
    return render_template('admin_verify.html', payments=pending_payments)

@app.route('/admin/approve-payment/<int:payment_id>')
def admin_approve_payment(payment_id):
    admin_password = request.args.get('password')
    if admin_password != "admin123":
        return "未授权访问", 401
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute("SELECT username FROM pending_payments WHERE id=?", (payment_id,))
    payment = c.fetchone()
    
    if payment:
        username = payment[0]
        c.execute("UPDATE users SET paid=1, payment_date=? WHERE username=?",
                 (datetime.now().isoformat(), username))
        c.execute("UPDATE pending_payments SET status='approved' WHERE id=?", (payment_id,))
        conn.commit()
    
    conn.close()
    return redirect(f"/admin/verify-payments?password={admin_password}")

@app.route('/admin/reject-payment/<int:payment_id>')
def admin_reject_payment(payment_id):
    admin_password = request.args.get('password')
    if admin_password != "admin123":
        return "未授权访问", 401
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE pending_payments SET status='rejected' WHERE id=?", (payment_id,))
    conn.commit()
    conn.close()
    return redirect(f"/admin/verify-payments?password={admin_password}")

@app.route('/members')
@payment_required
def members():
    return render_template('members.html')

@app.route('/check-payment-status')
@login_required
def check_payment_status():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT paid FROM users WHERE username=?", (session['user'],))
    user = c.fetchone()
    conn.close()
    
    if user and user[0] == 1:
        return redirect(url_for('members'))
    else:
        return render_template('payment_pending.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('email', None)
    return redirect(url_for('index'))

# ========== 会员专属内容路由 ==========
@app.route('/members')
@payment_required
def member_content():
    content_list = [
        {'type': 'video', 'title': '村口情报处#1', 'url': '/static/member/videos/video1.mp4', 'description': '村口的人言可畏'},
        {'type': 'image', 'title': '精选资料图#1', 'url': '/static/member/images/resource1.jpg', 'description': '高清示意图解，帮助你更好地理解知识点。'},
        {'type': 'article', 'title': '深度解析文章#1', 'content': '这里是你的第一篇深度文章的完整内容...', 'description': '透彻分析核心问题，提供实用解决方案。'}
    ]
    return render_template('member_content.html', contents=content_list)
# ========== 会员内容路由结束 ==========

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)