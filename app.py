from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from typing import Optional, List  # 确保导入 List

# ============ 加载环境变量 ============
try:
    from dotenv import load_dotenv
    load_dotenv()  # 加载 .env 文件中的环境变量
    print("✅ 环境变量加载成功")
except ImportError:
    print("⚠️  python-dotenv 未安装，跳过环境变量加载")

# ============ 安全初始化应用 ============
app = Flask(__name__)

# 🔐 安全密钥配置 - 支持开发和生成环境
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    if os.environ.get("FLASK_ENV") == "production":
        raise ValueError("❌ SECRET_KEY environment variable is required for production")
    else:
        # 开发环境使用一个默认密钥（不要在生产环境使用！）
        app.secret_key = "dev-secret-key-for-local-development-only-123456"
        print("⚠️  使用开发环境密钥，生产环境请设置 SECRET_KEY 环境变量")

# ============ 安全数据库配置 ============
# 从环境变量获取数据库URL
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    # 开发环境回退到硬编码的数据库URL
    database_url = "postgresql://paid_user:zgevvYEGo2MaqkEjoC3LOdid5esaFSM7@dpg-d4dj33ndiees73ckpk3g-a.singapore-postgres.render.com/paid_website"
    print("⚠️  使用默认数据库URL，生产环境请设置 DATABASE_URL 环境变量")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,           # 5分钟回收连接
    'pool_pre_ping': True,         # 连接前检查
    'pool_size': 10,               # 连接池大小
    'max_overflow': 20,            # 最大溢出连接数
    'pool_timeout': 30,            # 获取连接超时时间
}

# 🔐 会话安全配置
app.config.update(
    SESSION_COOKIE_SECURE=True,      # 仅HTTPS传输
    SESSION_COOKIE_HTTPONLY=True,    # 防止XSS读取
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF保护
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)  # 会话1小时后过期
)

db = SQLAlchemy(app)

# ============ 配置常量 ============
MEMBERSHIP_PRICE = 99
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "942521233@qq.com")  # 从环境变量获取

# 默认的内容分类和模块（防止未定义错误），可以根据实际内容替换为数据库或配置加载
CONTENT_CATEGORIES = [
    {"id": 1, "name": "入门指南", "slug": "getting-started"},
    {"id": 2, "name": "高级技巧", "slug": "advanced"},
    {"id": 3, "name": "常见问题", "slug": "faq"}
]

CONTENT_MODULES = [
    {"id": 1, "category_id": 1, "title": "如何注册与登录", "content": "在此处添加内容摘要..."},
    {"id": 2, "category_id": 1, "title": "支付流程说明", "content": "在此处添加支付流程..."},
    {"id": 3, "category_id": 2, "title": "优化技巧", "content": "在此处添加高级技巧..."},
]

# ============ 数据模型（兼容版本） ============
class User(db.Model):
    __tablename__ = "user"
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now, nullable=False, index=True)
    
    # 关系
    payments = db.relationship('Payment', backref='user', lazy=True, cascade='all, delete-orphan')
    questions = db.relationship('Question', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __init__(self, username: str, email: str, password: str, is_admin: bool = False):
        self.username = username
        self.email = email
        self.password = password
        self.is_admin = is_admin

class Payment(db.Model):
    __tablename__ = "payment"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False, index=True)
    create_time = db.Column(db.DateTime, default=datetime.now, nullable=False, index=True)
    process_time = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    
    def __init__(self, user_id: int, amount: float, payment_method: str, 
                 status: str = 'pending', notes: Optional[str] = None):
        self.user_id = user_id
        self.amount = amount
        self.payment_method = payment_method
        self.status = status
        self.notes = notes

class Question(db.Model):
    __tablename__ = "question"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text)
    answered = db.Column(db.Boolean, default=False, nullable=False, index=True)
    create_time = db.Column(db.DateTime, default=datetime.now, nullable=False, index=True)
    answer_time = db.Column(db.DateTime)
    
    def __init__(self, user_id: int, content: str, answer: Optional[str] = None, 
                 answered: bool = False):
        self.user_id = user_id
        self.content = content
        self.answer = answer
        self.answered = answered

class PasswordReset(db.Model):
    """密码重置令牌模型"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    def __init__(self, user_id: int, token: str, expires_at: datetime):
        self.user_id = user_id
        self.token = token
        self.expires_at = expires_at

    def is_valid(self):
        """检查令牌是否有效"""
        return not self.used and self.expires_at > datetime.now()

# ============ 优化查询方法 ============

def get_pending_payments() -> List[Payment]:  # 现在 List 已导入
    """优化：获取待审核支付（使用索引）"""
    return db.session.query(Payment).filter_by(status='pending')\
                       .order_by(Payment.create_time.asc())\
                       .options(db.joinedload(Payment.user))\
                       .all()

def get_unanswered_questions() -> List[Question]:
    """优化：获取未回答问题（使用索引）"""
    return db.session.query(Question).filter_by(answered=False)\
                        .order_by(Question.create_time.asc())\
                        .options(db.joinedload(Question.user))\
                        .all()

def get_user_questions(user_id: int) -> List[Question]:
    """优化：获取用户问题列表"""
    return db.session.query(Question).filter_by(user_id=user_id)\
                        .order_by(Question.create_time.desc())\
                        .all()

# ============ 装饰器 ============
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('请先登录管理员账号', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def payment_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # 检查用户是否有已通过的支付
        approved_payment = Payment.query.filter_by(
            user_id=session['user_id'], 
            status='approved'
        ).first()
        
        if not approved_payment:
            flash('请先完成支付验证', 'warning')
            return redirect(url_for('payment_manual'))
        return f(*args, **kwargs)
    return decorated_function

# ============ 模板测试 ============
@app.template_test('date_equal')
def date_equal_test(dt, date_str_or_date):
    """日期相等判断测试"""
    if not isinstance(dt, datetime):
        return False
    
    # 处理 date_str_or_date 参数，可能是字符串或 date 对象
    if isinstance(date_str_or_date, str):
        # 如果是字符串，解析为日期
        compare_date = datetime.strptime(date_str_or_date, '%Y-%m-%d').date()
    else:
        # 如果已经是 date 对象，直接使用
        compare_date = date_str_or_date
    
    return dt.date() == compare_date

@app.template_test('date_ge')
def date_ge_test(dt, date_str_or_date):
    """日期大于等于判断测试"""
    if not isinstance(dt, datetime):
        return False
    
    # 处理 date_str_or_date 参数，可能是字符串或 date 对象
    if isinstance(date_str_or_date, str):
        # 如果是字符串，解析为日期
        compare_date = datetime.strptime(date_str_or_date, '%Y-%m-%d').date()
    else:
        # 如果已经是 date 对象，直接使用
        compare_date = date_str_or_date
    
    return dt.date() >= compare_date

# ============ 用户路由 ============
@app.route('/')
def index():
    """首页"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not all([username, email, password]):
            return render_template('register.html', error="请填写所有字段")
        
        # 检查用户是否已存在
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="用户名已存在")
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error="邮箱已被注册")
        
        try:
            new_user = User(
                username=username,
                email=email,
                password=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            
            # 设置会话
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['email'] = new_user.email
            
            flash('注册成功！请完成支付验证', 'success')
            return redirect(url_for('payment_manual'))
            
        except Exception as e:
            db.session.rollback()
            return render_template('register.html', error=f"注册失败: {str(e)}")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not all([username, password]):
            return render_template('login.html', error="请填写用户名和密码")
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            
            # 检查支付状态
            approved_payment = Payment.query.filter_by(
                user_id=user.id, 
                status='approved'
            ).first()
            
            if approved_payment:
                flash('登录成功！', 'success')
                return redirect(url_for('members'))
            else:
                flash('登录成功！请完成支付验证', 'info')
                return redirect(url_for('payment_manual'))
        else:
            return render_template('login.html', error="用户名或密码错误")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """用户退出"""
    session.clear()
    flash('已退出登录', 'info')
    return redirect(url_for('index'))

# ============ 密码管理路由 ============

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """修改密码（需要登录）"""
    if request.method == 'POST':
        # 确保从表单获得字符串，避免 None 传入 check_password_hash
        current_password = (request.form.get('current_password') or '').strip()
        new_password = (request.form.get('new_password') or '').strip()
        confirm_password = (request.form.get('confirm_password') or '').strip()
        
        # 获取当前用户
        user = User.query.get(session['user_id'])
        if not user:
            flash('用户不存在或已被删除，请重新登录', 'error')
            session.clear()
            return redirect(url_for('login'))
        
        # 验证当前密码（确保传入的都是 str）
        if not current_password or not check_password_hash(user.password, current_password):
            flash('当前密码错误', 'error')
            return render_template('change_password.html')
        
        # 验证新密码
        if new_password != confirm_password:
            flash('新密码与确认密码不一致', 'error')
            return render_template('change_password.html')
        
        if len(new_password or '') < 6:
            flash('密码长度至少6位', 'error')
            return render_template('change_password.html')
        
        try:
            # 更新密码
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('密码修改成功', 'success')
            return redirect(url_for('members'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'密码修改失败: {str(e)}', 'error')
    
    return render_template('change_password.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """忘记密码 - 请求重置"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('请输入注册邮箱', 'error')
            return render_template('forgot_password.html')
        
        # 查找用户
        user = User.query.filter_by(email=email).first()
        
        if user:
            try:
                # 生成重置令牌
                import secrets
                token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=1)  # 1小时有效
                
                # 删除用户之前的重置令牌
                PasswordReset.query.filter_by(user_id=user.id).delete()
                
                # 创建新的重置令牌
                reset_request = PasswordReset(
                    user_id=user.id,
                    token=token,
                    expires_at=expires_at
                )
                db.session.add(reset_request)
                db.session.commit()
                
                # 生成重置链接（生产环境应发送邮件）
                reset_url = url_for('reset_password', token=token, _external=True)
                
                # 暂时在控制台输出（生产环境应发送邮件）
                print(f"🔐 密码重置链接（用户: {user.email}）:")
                print(f"📧 {reset_url}")
                print(f"⏰ 有效期至: {expires_at.strftime('%Y-%m-%d %H:%M')}")
                
                flash('密码重置链接已生成（请在控制台查看）', 'success')
                
            except Exception as e:
                db.session.rollback()
                flash(f'重置请求失败: {str(e)}', 'error')
        else:
            # 即使邮箱不存在也显示成功，防止邮箱探测
            flash('如果该邮箱已注册，重置链接将发送到您的邮箱', 'info')
        
        return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """通过令牌重置密码"""
    # 验证令牌
    reset_request = PasswordReset.query.filter_by(token=token).first()
    
    if not reset_request:
        flash('重置链接无效或已过期', 'error')
        return redirect(url_for('forgot_password'))
    
    if not reset_request.is_valid():
        flash('重置链接已过期', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        # 确保从表单获得字符串，避免 None 传入 generate_password_hash
        new_password = (request.form.get('new_password') or '').strip()
        confirm_password = (request.form.get('confirm_password') or '').strip()
        
        # 验证密码
        if new_password != confirm_password:
            flash('密码与确认密码不一致', 'error')
            return render_template('reset_password.html', token=token)
        
        if len(new_password) < 6:
            flash('密码长度至少6位', 'error')
            return render_template('reset_password.html', token=token)
        
        try:
            # 更新用户密码
            user = User.query.get(reset_request.user_id)
            user.password = generate_password_hash(new_password)
            
            # 标记令牌为已使用
            reset_request.used = True
            db.session.commit()
            
            flash('密码重置成功，请使用新密码登录', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'密码重置失败: {str(e)}', 'error')
    
    return render_template('reset_password.html', token=token)

# ============ 支付相关路由 ============
@app.route('/payment-manual')
@login_required
def payment_manual():
    """手动支付页面"""
    return render_template('payment_manual.html', 
                          price=MEMBERSHIP_PRICE,
                          admin_email=ADMIN_EMAIL)

@app.route('/submit-payment-proof', methods=['POST'])
@login_required
def submit_payment_proof():
    """提交支付凭证"""
    payment_proof = request.form.get('payment_proof', '').strip()
    
    if not payment_proof:
        flash('请提供支付凭证', 'warning')
        return redirect(url_for('payment_manual'))
    
    try:
        new_payment = Payment(
            user_id=session['user_id'],
            amount=MEMBERSHIP_PRICE,
            payment_method='manual',
            status='pending',
            notes=f"支付凭证: {payment_proof}"
        )
        
        db.session.add(new_payment)
        db.session.commit()
        
        flash('支付凭证已提交，请等待管理员审核', 'success')
        return redirect(url_for('check_payment_status'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'提交失败: {str(e)}', 'error')
        return redirect(url_for('payment_manual'))

@app.route('/check-payment-status')
@login_required
def check_payment_status():
    """检查支付状态"""
    payments = Payment.query.filter_by(user_id=session['user_id'])\
                           .order_by(Payment.create_time.desc()).all()
    has_approved = any(p.status == 'approved' for p in payments)
    
    return render_template('payment_status.html', 
                         payments=payments,
                         has_approved_payment=has_approved,
                         price=MEMBERSHIP_PRICE)

# ============ 会员内容路由 ============
@app.route('/members')
@payment_required
def members():
    """会员专属内容页面"""
    return render_template('members.html')

# ============ 管理员路由 ============
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    """管理员登录 - 安全版本"""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not all([username, password]):
            flash('请填写用户名和密码', 'error')
            return render_template('admin_login.html')
        
        # 从数据库验证管理员
        admin_user = User.query.filter_by(username=username, is_admin=True).first()
        
        if admin_user and check_password_hash(admin_user.password, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash('管理员登录成功！', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('管理员账号或密码错误', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """管理员仪表板"""
    stats = {
        'unanswered_count': Question.query.filter_by(answered=False).count(),
        'total_payments': Payment.query.count(),
        'pending_payments': Payment.query.filter_by(status='pending').count(),
        'total_users': User.query.count()
    }
    
    return render_template('admin_dashboard.html', **stats) 

# ============ 专家问答路由 ============

@app.route('/submit-question', methods=['POST'])
@payment_required
def submit_question():
    """用户提交问题 - 修复版本"""
    try:
        # 同时支持表单数据和JSON数据
        if request.is_json:
            data = request.get_json()
            content = data.get('content', '').strip()
        else:
            content = request.form.get('content', '').strip()
        
        print(f"📝 收到问题提交: {content[:100]}...")  # 调试日志
        
        if not content:
            return jsonify({'success': False, 'message': '问题内容不能为空'})
        
        if len(content) < 5:
            return jsonify({'success': False, 'message': '问题内容太短，请详细描述'})
        
        new_question = Question(
            user_id=session['user_id'],
            content=content
        )
        
        db.session.add(new_question)
        db.session.commit()
        
        print(f"✅ 问题提交成功，ID: {new_question.id}")  # 调试日志
        return jsonify({'success': True, 'message': '问题提交成功！专家将在24小时内回复'})
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ 问题提交失败: {str(e)}")  # 错误日志
        return jsonify({'success': False, 'message': f'提交失败: {str(e)}'})

@app.route('/get-my-questions')
@payment_required
def get_my_questions():
    """获取用户自己的问题列表"""
    questions = Question.query.filter_by(user_id=session['user_id'])\
                             .order_by(Question.create_time.desc()).all()
    
    questions_data = []
    for q in questions:
        questions_data.append({
            'id': q.id,
            'content': q.content,
            'answer': q.answer,
            'answered': q.answered,
            'create_time': q.create_time.strftime('%Y-%m-%d %H:%M'),
            'answer_time': q.answer_time.strftime('%Y-%m-%d %H:%M') if q.answer_time else None
        })
    
    return jsonify({'success': True, 'questions': questions_data})

@app.route('/admin/answer-question/<int:question_id>', methods=['POST'])
@admin_required
def answer_question(question_id):
    """管理员回答问题 - 修复版本"""
    try:
        question = Question.query.get_or_404(question_id)
        
        # 检查请求数据
        if not request.is_json:
            return jsonify({'success': False, 'message': '请求必须是JSON格式'})
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': '无效的JSON数据'})
        
        answer_content = data.get('answer', '').strip()
        if not answer_content:
            return jsonify({'success': False, 'message': '回答内容不能为空'})
        
        # 更新问题
        question.answer = answer_content
        question.answered = True
        question.answer_time = datetime.now()
        
        db.session.commit()
        
        print(f"管理员已回答问题 ID: {question_id}")  # 调试日志
        
        return jsonify({'success': True, 'message': '回答提交成功'})
        
    except Exception as e:
        db.session.rollback()
        print(f"回答问题错误: {str(e)}")  # 调试日志
        return jsonify({'success': False, 'message': f'回答失败: {str(e)}'})

@app.route('/admin/payments')
@admin_required
def admin_payments():
    """支付管理 - 优化版本"""
    # 使用优化后的查询方法
    payments = db.session.query(Payment).order_by(Payment.create_time.desc())\
                           .options(db.joinedload(Payment.user))\
                           .all()
    return render_template('admin_payments.html', payments=payments)

@app.route('/admin/update-payment/<int:payment_id>', methods=['POST'])
@admin_required
def update_payment_status(payment_id):
    """更新支付状态"""
    payment = Payment.query.get_or_404(payment_id)
    new_status = request.form.get('status', '')
    
    payment.status = new_status
    payment.process_time = datetime.now()
    db.session.commit()
    
    flash(f'支付状态已更新为 {new_status}', 'success')
    return redirect(url_for('admin_payments'))

@app.route('/admin/users')
@admin_required
def admin_users():
    """用户管理"""
    try:
        users = User.query.order_by(User.create_time.desc()).all()
        return render_template('admin_users.html', 
                             users=users, 
                             now=datetime.now(), 
                             timedelta=timedelta)
    except Exception as e:
        flash(f'用户管理页面加载失败: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """删除用户"""
    try:
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
        Payment.query.filter_by(user_id=user_id).delete()
        Question.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': '用户已删除'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'})

# ============ 初始化应用 ============
def init_db():
    """初始化数据库 - PostgreSQL专用版本"""
    with app.app_context():
        try:
            print("🔄 开始初始化PostgreSQL数据库...")
            
            # 创建所有表
            db.create_all()
            print("✅ 数据库表创建完成")
            
            # 创建默认管理员账户
            admin_user = User.query.filter_by(username='huang').first()
            if not admin_user:
                admin_user = User(
                    username='huang',
                    email='942521233@qq.com',
                    password=generate_password_hash('112588'),
                    is_admin=True
                )
                db.session.add(admin_user)
                print("✅ 默认管理员账户已创建: huang / 112588")
            else:
                print("✅ 管理员账户已存在")
            
            # 创建测试用户（方便测试）
            test_user = User.query.filter_by(username='testuser').first()
            if not test_user:
                test_user = User(
                    username='testuser',
                    email='test@example.com',
                    password=generate_password_hash('test123'),
                    is_admin=False
                )
                db.session.add(test_user)
                print("✅ 测试用户已创建: testuser / test123")
            
            db.session.commit()
            print("🎉 PostgreSQL数据库初始化完成！")
            print("💾 用户数据现在将永久保存，不再因部署而丢失！")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ 数据库初始化错误: {str(e)}")
            
            # 如果是连接错误，提供具体建议
            if "connection" in str(e).lower():
                print("🔧 请检查PostgreSQL连接字符串和网络连接")
            elif "already exists" in str(e).lower():
                print("⚠️  表已存在，可以忽略此错误")
            else:
                raise

@app.route('/admin/make-admin/<int:user_id>', methods=['POST'])
@admin_required
def make_admin(user_id):
    """将用户设为管理员"""
    try:
        user = User.query.get_or_404(user_id)
        
        # 检查是否已经是管理员
        if user.is_admin:
            return jsonify({'success': False, 'message': '用户已经是管理员'})
        
        user.is_admin = True
        db.session.commit()
        
        return jsonify({'success': True, 'message': '用户已设为管理员'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'操作失败: {str(e)}'})

@app.route('/admin/questions')
@admin_required
def admin_questions():
    """问题管理 - 修复版本"""
    try:
        # 使用更明确的查询，确保正确加载用户关系
        questions = db.session.query(Question)\
                             .options(db.joinedload(Question.user))\
                             .order_by(Question.create_time.desc())\
                             .all()
        
        print(f"管理员查看问题: 找到 {len(questions)} 个问题")  # 调试日志
        
        return render_template('admin_questions.html', questions=questions)
        
    except Exception as e:
        print(f"管理员问题查询错误: {str(e)}")  # 调试日志
        flash(f'加载问题列表失败: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    """管理员退出"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('已退出管理员账号', 'info')
    return redirect(url_for('admin_login'))

@app.route('/terms')
def terms():
    """服务条款页面"""
    return render_template('terms.html', ADMIN_EMAIL=ADMIN_EMAIL)

@app.route('/privacy')
def privacy():
    """隐私政策页面"""
    return render_template('privacy.html', ADMIN_EMAIL=ADMIN_EMAIL) 

@app.route('/knowledge-base')
@payment_required
def knowledge_base():
    """知识库页面"""
    return render_template('knowledge_base.html', 
                         content_categories=CONTENT_CATEGORIES,
                         content_modules=CONTENT_MODULES)

# ============ 新增：债务计算器API ============
@app.route('/api/calculate-debt', methods=['POST'])
@login_required
def calculate_debt():
    """债务计算器API"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': '无效的请求数据'})
        
        total_debt = float(data.get('total_debt', 0))
        monthly_payment = float(data.get('monthly_payment', 0))
        interest_rate = float(data.get('interest_rate', 12))
        
        if total_debt <= 0 or monthly_payment <= 0:
            return jsonify({'success': False, 'message': '请输入有效的债务金额和月还款额'})
        
        # 计算还款计划
        monthly_rate = interest_rate / 100 / 12
        remaining_debt = total_debt
        months = 0
        total_interest = 0
        payment_plan = []
        
        # 计算还款月数
        while remaining_debt > 0 and months < 600:  # 限制最多50年
            interest = remaining_debt * monthly_rate
            principal = monthly_payment - interest
            
            if principal <= 0:
                return jsonify({
                    'success': False, 
                    'message': '月还款额不足以支付利息，请增加月还款额'
                })
            
            remaining_debt -= principal
            total_interest += interest
            months += 1
            
            # 记录每月还款详情
            payment_plan.append({
                'month': months,
                'principal': round(principal, 2),
                'interest': round(interest, 2),
                'remaining': round(max(remaining_debt, 0), 2)
            })
            
            if months >= 600:
                break
        
        years = months // 12
        remaining_months = months % 12
        
        # 生成建议
        advice = generate_debt_advice(total_debt, monthly_payment, months)
        
        return jsonify({
            'success': True,
            'result': {
                'total_debt': total_debt,
                'monthly_payment': monthly_payment,
                'total_months': months,
                'years': years,
                'remaining_months': remaining_months,
                'total_interest': round(total_interest, 2),
                'total_payment': round(total_debt + total_interest, 2),
                'advice': advice,
                'payment_plan': payment_plan[:12]  # 只返回前12个月的详细计划
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'计算失败: {str(e)}'})

def generate_debt_advice(total_debt, monthly_payment, months):
    """生成债务建议"""
    if months <= 12:
        return {
            'level': 'success',
            'title': '恭喜！还款计划很合理',
            'content': '您的还款计划很合理，坚持执行很快就能上岸！继续保持。',
            'suggestions': [
                '坚持当前还款计划',
                '建立紧急备用金',
                '学习理财知识预防再次负债'
            ]
        }
    elif months <= 36:
        return {
            'level': 'warning',
            'title': '还款计划可行，建议优化',
            'content': '还款计划可行，但周期较长。建议寻找增加收入的机会，加速还款进程。',
            'suggestions': [
                '寻找兼职或副业增加收入',
                '优化日常开支',
                '与债权人协商降低利率'
            ]
        }
    else:
        return {
            'level': 'danger',
            'title': '需要调整还款计划',
            'content': '还款周期较长，建议积极调整还款策略，避免长期负担。',
            'suggestions': [
                '与所有债权人协商还款方案',
                '寻求专业债务咨询服务',
                '制定严格的预算计划',
                '优先偿还高利率债务'
            ]
        }

# ============ 新增：获取用户进度 ============
@app.route('/api/user-progress')
@payment_required
def get_user_progress():
    """获取用户学习进度"""
    try:
        user_id = session['user_id']
        
        # 获取用户的学习数据（这里需要根据实际数据结构调整）
        completed_courses = 15  # 模拟数据
        completed_steps = 6     # 模拟数据
        in_progress_steps = 3   # 模拟数据
        
        # 计算总体进度
        total_progress = min(100, int((completed_steps / (completed_steps + in_progress_steps)) * 100))
        
        return jsonify({
            'success': True,
            'progress': {
                'total_progress': total_progress,
                'completed_courses': completed_courses,
                'completed_steps': completed_steps,
                'in_progress_steps': in_progress_steps,
                'pending_tasks': 2
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'获取进度失败: {str(e)}'})

# ============ 新增：工具箱内容API ============
@app.route('/api/tool-content/<tool_type>')
@payment_required
def get_tool_content(tool_type):
    """获取工具箱内容"""
    tools = {
        'harassment': {
            'title': '催收应对技巧',
            'content': """
                <h4>合法应对催收电话</h4>
                <ul>
                    <li><strong>保持冷静：</strong>不要与催收人员争吵</li>
                    <li><strong>录音取证：</strong>所有通话都要录音保存</li>
                    <li><strong>明确表达：</strong>表明还款意愿但暂时困难</li>
                    <li><strong>了解权利：</strong>催收不得骚扰家人朋友</li>
                    <li><strong>投诉渠道：</strong>遭遇违规催收可拨打12378投诉</li>
                </ul>
                <div class="alert alert-warning mt-3">
                    <strong>注意：</strong>如果催收人员威胁、辱骂或上门骚扰，立即向银保监会投诉。
                </div>
            """
        },
        'legal': {
            'title': '法律保护知识',
            'content': """
                <h4>你的合法权益</h4>
                <ul>
                    <li><strong>个人信息权：</strong>催收不得泄露你的债务信息</li>
                    <li><strong>休息权：</strong>晚上10点至早上8点不得催收</li>
                    <li><strong>名誉权：</strong>不得公开侮辱、诽谤</li>
                    <li><strong>协商权：</strong>有权要求协商还款方案</li>
                </ul>
                <h4 class="mt-4">常见违法行为</h4>
                <ul>
                    <li>爆通讯录、联系无关第三人</li>
                    <li>P图、发假律师函</li>
                    <li>上门骚扰、威胁</li>
                    <li>冒充公检法人员</li>
                </ul>
                <div class="alert alert-info mt-3">
                    <strong>维权方式：</strong>收集证据 → 向银保监会12378投诉 → 必要时报警
                </div>
            """
        },
        'psychological': {
            'title': '心理疏导方法',
            'content': """
                <h4>缓解债务焦虑</h4>
                <ul>
                    <li><strong>接受现实：</strong>债务是暂时困难，不是人生终点</li>
                    <li><strong>分解目标：</strong>将大目标分解为可执行的小步骤</li>
                    <li><strong>寻求支持：</strong>与家人沟通或加入支持群体</li>
                    <li><strong>保持运动：</strong>每天30分钟运动缓解压力</li>
                    <li><strong>正面思考：</strong>关注解决方案而非问题本身</li>
                </ul>
                <h4 class="mt-4">紧急心理支持</h4>
                <p>如果感到极度焦虑、抑郁或有自杀念头，请立即寻求专业帮助：</p>
                <ul>
                    <li>心理援助热线：12320</li>
                    <li>危机干预热线：800-810-1117</li>
                    <li>当地心理卫生中心</li>
                </ul>
            """
        }
    }
    
    tool = tools.get(tool_type)
    if tool:
        return jsonify({'success': True, 'tool': tool})
    else:
        return jsonify({'success': False, 'message': '工具不存在'})

# ============ 优化：问答功能 ============
@app.route('/api/submit-question', methods=['POST'])
@payment_required
def api_submit_question():
    """API版本的问题提交"""
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': '无效的请求数据'})
    
    content = data.get('content', '').strip()
    
    if not content:
        return jsonify({'success': False, 'message': '问题内容不能为空'})
    
    try:
        new_question = Question(
            user_id=session['user_id'],
            content=content
        )
        
        db.session.add(new_question)
        db.session.commit()
        
        return jsonify({'success': True, 'message': '问题提交成功！专家将在24小时内回复'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'提交失败: {str(e)}'})

@app.route('/api/my-questions')
@payment_required
def api_my_questions():
    """API版本的用户问题列表"""
    try:
        questions = Question.query.filter_by(user_id=session['user_id'])\
                                 .order_by(Question.create_time.desc()).all()
        
        questions_data = []
        for q in questions:
            questions_data.append({
                'id': q.id,
                'content': q.content,
                'answer': q.answer,
                'answered': q.answered,
                'create_time': q.create_time.strftime('%Y-%m-%d %H:%M'),
                'answer_time': q.answer_time.strftime('%Y-%m-%d %H:%M') if q.answer_time else None
            })
        
        return jsonify({'success': True, 'questions': questions_data})
    except Exception as e:
        return jsonify({'success': False, 'message': f'获取问题列表失败: {str(e)}'})

# ============ 新增：资源下载 ============
@app.route('/download/<resource_type>')
@payment_required
def download_resource(resource_type):
    """资源下载"""
    resources = {
        'debt-template': {
            'filename': '债务管理表格.xlsx',
            'description': '债务管理电子表格模板'
        },
        'negotiation-guide': {
            'filename': '协商话术指南.pdf',
            'description': '完整的协商话术指南'
        },
        'legal-rights': {
            'filename': '法律权益手册.pdf',
            'description': '债务相关法律权益手册'
        }
    }
    
    resource = resources.get(resource_type)
    if resource:
        # 这里应该返回实际的文件
        # 暂时返回成功消息
        flash(f'开始下载: {resource["description"]}', 'success')
        return jsonify({'success': True, 'message': f'开始下载 {resource["description"]}'})
    else:
        return jsonify({'success': False, 'message': '资源不存在'})
    
    # ============ 新增：调试路由 ============
@app.route('/debug/questions')
@admin_required
def debug_questions():
    """调试问题数据"""
    try:
        # 检查所有问题
        all_questions = Question.query.all()
        print(f"总问题数量: {len(all_questions)}")
        
        # 检查未回答问题
        unanswered = Question.query.filter_by(answered=False).all()
        print(f"未回答问题数量: {len(unanswered)}")
        
        # 检查用户关联
        for q in all_questions:
            user = User.query.get(q.user_id)
            print(f"问题ID: {q.id}, 用户ID: {q.user_id}, 用户名: {user.username if user else '用户不存在'}, 已回答: {q.answered}")
        
        return jsonify({
            'total_questions': len(all_questions),
            'unanswered_questions': len(unanswered),
            'questions': [
                {
                    'id': q.id,
                    'user_id': q.user_id,
                    'username': User.query.get(q.user_id).username if User.query.get(q.user_id) else 'Unknown',
                    'content': q.content[:50] + '...' if len(q.content) > 50 else q.content,
                    'answered': q.answered,
                    'create_time': q.create_time.strftime('%Y-%m-%d %H:%M')
                } for q in all_questions
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})
    
# ============ 启动应用 ============
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)