from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from typing import Optional

# ============ 初始化应用 ============
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-123")

# ============ 数据库配置 ============
# 使用您提供的PostgreSQL连接字符串
database_url = "postgresql://paid_user:zgevvYEGo2MaqkEjoC3LOdid5esaFSM7@dpg-d4dj33ndiees73ckpk3g-a.singapore-postgres.render.com/paid_website"

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}

db = SQLAlchemy(app)

# ============ 配置常量 ============
MEMBERSHIP_PRICE = 29.9
ADMIN_EMAIL = "admin@example.com"


# ============ 数据模型 ============
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    create_time = db.Column(db.DateTime, default=datetime.now)
    
    # 关系
    payments = db.relationship('Payment', backref='user', lazy=True)
    questions = db.relationship('Question', backref='user', lazy=True)
    
    def __init__(self, username: str, email: str, password: str, is_admin: bool = False):
        self.username = username
        self.email = email
        self.password = password
        self.is_admin = is_admin

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    create_time = db.Column(db.DateTime, default=datetime.now)
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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text)
    answered = db.Column(db.Boolean, default=False)
    create_time = db.Column(db.DateTime, default=datetime.now)
    answer_time = db.Column(db.DateTime)
    
    def __init__(self, user_id: int, content: str, answer: Optional[str] = None, 
                 answered: bool = False):
        self.user_id = user_id
        self.content = content
        self.answer = answer
        self.answered = answered

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
    """用户提交问题"""
    content = request.form.get('content', '').strip()
    
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
    """管理员回答问题"""
    question = Question.query.get_or_404(question_id)
    
    # 安全的 JSON 数据获取
    if not request.is_json:
        return jsonify({'success': False, 'message': '请求必须是JSON格式'})
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': '无效的JSON数据'})
    
    answer_content = data.get('answer', '').strip()
    
    if not answer_content:
        return jsonify({'success': False, 'message': '回答内容不能为空'})
    
    try:
        question.answer = answer_content
        question.answered = True
        question.answer_time = datetime.now()
        
        db.session.commit()
        return jsonify({'success': True, 'message': '回答提交成功'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'回答失败: {str(e)}'})

@app.route('/admin/payments')
@admin_required
def admin_payments():
    """支付管理"""
    payments = Payment.query.order_by(Payment.create_time.desc()).all()
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
    """问题管理"""
    questions = Question.query.order_by(Question.create_time.desc()).all()
    return render_template('admin_questions.html', questions=questions)

@app.route('/admin/logout')
def admin_logout():
    """管理员退出"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('已退出管理员账号', 'info')
    return redirect(url_for('admin_login'))




# ============ 启动应用 ============
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
