from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import flash, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc


app = Flask(__name__)
app.secret_key = "your-secret-key-123"  # 可以稍后更改
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ============ 3. 数据模型定义（带类型提示） ============
class User(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(80), unique=True, nullable=False)
    email: str = db.Column(db.String(120), unique=True, nullable=False)
    password: str = db.Column(db.String(200), nullable=False)
    is_admin: bool = db.Column(db.Boolean, default=False)
    create_time: datetime = db.Column(db.DateTime, default=datetime.now)

# 添加缺失的模型定义
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text)
    answered = db.Column(db.Boolean, default=False)
    create_time = db.Column(db.DateTime, default=datetime.now)
    answer_time = db.Column(db.DateTime)
    
    user = db.relationship('User', backref=db.backref('questions', lazy=True))

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    create_time = db.Column(db.DateTime, default=datetime.now)
    process_time = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    
    user = db.relationship('User', backref=db.backref('payments', lazy=True)) 

# ============ 管理员装饰器 ============
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('请先登录管理员账号')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


# 配置
MEMBERSHIP_PRICE = "29.9"
ADMIN_EMAIL = "your-email@example.com"

def init_sqlite_db():
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

# ============ 新增的管理员路由 ============

# 设为管理员
@app.route('/admin/make-admin/<int:user_id>', methods=['POST'])
@admin_required
def make_admin(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    
    return jsonify({'success': True, 'message': '用户已设为管理员'})

# 删除用户
@app.route('/admin/delete-user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    # 防止删除自己
    if user_id == session.get('user_id'):
        return jsonify({'success': False, 'message': '不能删除自己的账户'})
    
    user = User.query.get_or_404(user_id)
    
    # 防止删除最后一个管理员
    if user.is_admin:
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count <= 1:
            return jsonify({'success': False, 'message': '不能删除最后一个管理员'})
    
    # 删除用户相关的所有数据
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': '用户已删除'})

# 修改用户管理路由，传递当前时间
@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(desc(User.create_time)).all()  # type: ignore
    return render_template('admin_users.html', 
                         users=users, 
                         now=datetime.now(), 
                         timedelta=timedelta)  # 添加这个参数

# 模板过滤器
@app.template_filter('date_equal')
def date_equal_filter(dt, date_str):
    if isinstance(dt, datetime):
        return dt.date() == datetime.strptime(date_str, '%Y-%m-%d').date()
    return False

@app.template_filter('date_ge')
def date_ge_filter(dt, date_str):
    if isinstance(dt, datetime):
        return dt.date() >= datetime.strptime(date_str, '%Y-%m-%d').date()
    return False

# 管理员登录页面
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    # 如果已经登录，直接跳转到仪表板
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 验证管理员凭据
        if username == 'admin' and password == 'admin123':
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash('管理员登录成功！')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('管理员账号或密码错误')
    
    return render_template('admin_login.html')

# 管理员仪表板
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        # 获取统计数据（带错误处理）
        unanswered_count = Question.query.filter_by(answered=False).count()
        total_payments = Payment.query.count()
        pending_payments = Payment.query.filter_by(status='pending').count()
        total_users = User.query.count()
    except Exception as e:
        # 如果数据库查询失败（如表不存在），使用默认值
        print(f"数据库查询错误: {e}")
        unanswered_count = 0
        total_payments = 0
        pending_payments = 0
        total_users = 0
    
    return render_template('admin_dashboard.html',
                         unanswered_count=unanswered_count,
                         total_payments=total_payments,
                         pending_payments=pending_payments,
                         total_users=total_users)

# 管理员退出
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('已退出管理员账号')
    return redirect(url_for('admin_login'))

# 问题管理路由
@app.route('/admin/questions')
@admin_required
def admin_questions():
    questions = Question.query.order_by(Question.create_time.desc()).all()
    return render_template('admin_questions.html', questions=questions)

# 支付管理路由
@app.route('/admin/payments')
@admin_required
def admin_payments():
    payments = Payment.query.order_by(Payment.create_time.desc()).all()
    return render_template('admin_payments.html', payments=payments)

# 创建数据库表
def init_db():
    with app.app_context():
        db.create_all()
        print("=== 数据库表创建成功 ===")
        print("✓ user 表已创建")
        print("✓ question 表已创建")
        print("✓ payment 表已创建")
        
        # 检查表是否真的存在
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"=== 数据库中的表: {tables} ===")
    
    
# ============ 只保留一个启动块 ============
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
