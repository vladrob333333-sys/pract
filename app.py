import os
import logging
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from functools import wraps
from flask_wtf.csrf import CSRFProtect

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# CSRF защита
csrf = CSRFProtect(app)

from database import db, User, Service, Task, TimeEntry, AuditLog, LoginAttempt, init_db

# Инициализация БД
with app.app_context():
    try:
        init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

# Вспомогательные функции
def log_audit(table_name, record_id, action, old_data=None, new_data=None):
    """Запись в журнал аудита"""
    user_id = session.get('user_id')
    ip = request.remote_addr
    try:
        audit = AuditLog(
            table_name=table_name,
            record_id=record_id,
            action=action,
            old_data=json.dumps(old_data, ensure_ascii=False) if old_data else None,
            new_data=json.dumps(new_data, ensure_ascii=False) if new_data else None,
            user_id=user_id,
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        logger.error(f"Audit log error: {e}")
        db.session.rollback()

def log_login_attempt(username, success):
    """Запись попытки входа"""
    ip = request.remote_addr
    try:
        attempt = LoginAttempt(username=username, ip_address=ip, success=success)
        db.session.add(attempt)
        db.session.commit()
    except Exception as e:
        logger.error(f"Login attempt log error: {e}")
        db.session.rollback()

# Декораторы для проверки ролей
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Требуется авторизация', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Требуется авторизация', 'warning')
                return redirect(url_for('login'))
            user = User.query.get(session['user_id'])
            if not user or user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    return role_required('admin')(f)

def operator_required(f):
    return role_required('admin', 'operator')(f)

def worker_required(f):
    return role_required('admin', 'worker')(f)

def client_required(f):
    return role_required('admin', 'client')(f)

# Проверка смены пароля при первом входе
@app.before_request
def check_password_change():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.password_change_required:
            # Разрешаем доступ только к странице смены пароля и выходу
            if request.endpoint not in ['change_password', 'logout', 'static']:
                flash('Необходимо сменить пароль', 'warning')
                return redirect(url_for('change_password'))

# Маршрут смены пароля
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        
        if not check_password_hash(user.password_hash, old_password):
            flash('Неверный текущий пароль', 'danger')
        elif new_password != confirm:
            flash('Новые пароли не совпадают', 'danger')
        elif len(new_password) < 6:
            flash('Пароль должен быть не менее 6 символов', 'danger')
        else:
            user.set_password(new_password)
            user.password_change_required = False
            db.session.commit()
            flash('Пароль успешно изменён', 'success')
            return redirect(url_for('index'))
    return render_template('change_password.html')

# Главная страница-презентация
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user.role == 'operator':
            return redirect(url_for('operator_dashboard'))
        elif user.role == 'worker':
            return redirect(url_for('worker_dashboard'))
        elif user.role == 'client':
            return redirect(url_for('client_dashboard'))
    return render_template('index.html')

# Аутентификация
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, is_active=True).first()
        success = False
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['full_name'] = user.full_name
            session.permanent = True
            success = True
            flash('Вход выполнен успешно', 'success')
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
        log_login_attempt(username, success)
        if success:
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

# Панель администратора
@app.route('/admin')
@admin_required
def admin_dashboard():
    stats = {
        'users': User.query.count(),
        'tasks': Task.query.count(),
        'services': Service.query.count(),
        'audit': AuditLog.query.count()
    }
    recent_audit = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('admin/dashboard.html', stats=stats, recent_audit=recent_audit)

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/create', methods=['POST'])
@admin_required
def create_user():
    try:
        user = User(
            username=request.form['username'],
            full_name=request.form['full_name'],
            role=request.form['role'],
            email=request.form.get('email'),
            phone=request.form.get('phone'),
            position=request.form.get('position') if request.form['role'] in ['operator', 'worker'] else None,
            department=request.form.get('department') if request.form['role'] in ['operator', 'worker'] else None,
            contract_number=request.form.get('contract_number') if request.form['role'] == 'client' else None,
            is_active=True,
            password_change_required=True
        )
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        log_audit('user', user.id, 'INSERT', new_data={'username': user.username, 'role': user.role})
        flash('Пользователь создан', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {e}")
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@admin_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    old_data = {'username': user.username, 'full_name': user.full_name, 'role': user.role, 'is_active': user.is_active}
    try:
        user.full_name = request.form['full_name']
        user.email = request.form.get('email')
        user.phone = request.form.get('phone')
        user.role = request.form['role']
        user.is_active = 'is_active' in request.form
        if request.form['role'] == 'client':
            user.contract_number = request.form.get('contract_number')
            user.position = None
            user.department = None
        else:
            user.contract_number = None
            user.position = request.form.get('position')
            user.department = request.form.get('department')
        if request.form.get('password'):
            user.set_password(request.form['password'])
            user.password_change_required = True
        db.session.commit()
        new_data = {'username': user.username, 'full_name': user.full_name, 'role': user.role, 'is_active': user.is_active}
        log_audit('user', user.id, 'UPDATE', old_data, new_data)
        flash('Данные обновлены', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user: {e}")
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session['user_id']:
        flash('Нельзя удалить себя', 'danger')
        return redirect(url_for('admin_users'))
    try:
        old_data = {'username': user.username}
        db.session.delete(user)
        db.session.commit()
        log_audit('user', user_id, 'DELETE', old_data=old_data)
        flash('Пользователь удалён', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user: {e}")
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/services')
@admin_required
def admin_services():
    services = Service.query.all()
    return render_template('admin/services.html', services=services)

@app.route('/admin/services/create', methods=['POST'])
@admin_required
def create_service():
    try:
        service = Service(
            name=request.form['name'],
            description=request.form.get('description'),
            price=float(request.form['price']) if request.form.get('price') else None,
            is_active='is_active' in request.form
        )
        db.session.add(service)
        db.session.commit()
        log_audit('service', service.id, 'INSERT', new_data={'name': service.name})
        flash('Услуга добавлена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('admin_services'))

@app.route('/admin/services/<int:service_id>/update', methods=['POST'])
@admin_required
def update_service(service_id):
    service = Service.query.get_or_404(service_id)
    try:
        service.name = request.form['name']
        service.description = request.form.get('description')
        service.price = float(request.form['price']) if request.form.get('price') else None
        service.is_active = 'is_active' in request.form
        db.session.commit()
        log_audit('service', service.id, 'UPDATE', new_data={'name': service.name})
        flash('Услуга обновлена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('admin_services'))

@app.route('/admin/audit')
@admin_required
def admin_audit():
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('admin/audit.html', logs=logs)

@app.route('/admin/login-attempts')
@admin_required
def admin_login_attempts():
    page = request.args.get('page', 1, type=int)
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('admin/login_attempts.html', attempts=attempts)

# Управление БД (бэкапы)
BACKUP_DIR = Path('backups')
BACKUP_DIR.mkdir(exist_ok=True)

@app.route('/admin/db')
@admin_required
def admin_db():
    backups = sorted(BACKUP_DIR.glob('*.db'), key=os.path.getmtime, reverse=True)
    return render_template('admin/db.html', backups=backups)

@app.route('/admin/db/backup', methods=['POST'])
@admin_required
def create_backup():
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = BACKUP_DIR / f'app_backup_{timestamp}.db'
        shutil.copy2('app.db', backup_path)
        flash(f'Бэкап создан: {backup_path.name}', 'success')
        log_audit('system', 0, 'BACKUP', new_data={'file': backup_path.name})
    except Exception as e:
        flash(f'Ошибка создания бэкапа: {str(e)}', 'danger')
    return redirect(url_for('admin_db'))

@app.route('/admin/db/restore/<path:filename>', methods=['POST'])
@admin_required
def restore_backup(filename):
    backup_path = BACKUP_DIR / filename
    if not backup_path.exists():
        flash('Файл не найден', 'danger')
        return redirect(url_for('admin_db'))
    try:
        # Закрываем все соединения с БД
        db.session.remove()
        db.engine.dispose()
        # Копируем файл бэкапа
        shutil.copy2(backup_path, 'app.db')
        flash('БД восстановлена. Перезапустите приложение для применения.', 'success')
        log_audit('system', 0, 'RESTORE', new_data={'file': filename})
    except Exception as e:
        flash(f'Ошибка восстановления: {str(e)}', 'danger')
    return redirect(url_for('admin_db'))

@app.route('/admin/tables')
@admin_required
def admin_tables():
    tables = {
        'users': User.query.count(),
        'services': Service.query.count(),
        'tasks': Task.query.count(),
        'time_entries': TimeEntry.query.count(),
        'audit_logs': AuditLog.query.count(),
        'login_attempts': LoginAttempt.query.count()
    }
    return render_template('admin/tables.html', tables=tables)

@app.route('/admin/table/<table_name>')
@admin_required
def view_table(table_name):
    model_map = {
        'users': User,
        'services': Service,
        'tasks': Task,
        'time_entries': TimeEntry,
        'audit_logs': AuditLog,
        'login_attempts': LoginAttempt
    }
    model = model_map.get(table_name)
    if not model:
        abort(404)
    records = model.query.all()
    columns = [c.name for c in model.__table__.columns]
    return render_template('admin/table_view.html', table_name=table_name, columns=columns, records=records)

# Панель оператора
@app.route('/operator')
@operator_required
def operator_dashboard():
    new_tasks = Task.query.filter_by(status='new').count()
    assigned_tasks = Task.query.filter_by(status='assigned').count()
    completed_tasks = Task.query.filter_by(status='completed').count()
    workers = User.query.filter_by(role='worker', is_active=True).all()
    recent_tasks = Task.query.order_by(Task.created_at.desc()).limit(10).all()
    return render_template('operator/dashboard.html',
                           new_tasks=new_tasks,
                           assigned_tasks=assigned_tasks,
                           completed_tasks=completed_tasks,
                           workers=workers,
                           recent_tasks=recent_tasks)

@app.route('/operator/tasks')
@operator_required
def operator_tasks():
    tasks = Task.query.order_by(Task.created_at.desc()).all()
    workers = User.query.filter_by(role='worker', is_active=True).all()
    clients = User.query.filter_by(role='client', is_active=True).all()
    services = Service.query.filter_by(is_active=True).all()
    return render_template('operator/tasks.html', tasks=tasks, workers=workers, clients=clients, services=services)

@app.route('/operator/tasks/create', methods=['POST'])
@operator_required
def operator_create_task():
    try:
        task = Task(
            title=request.form['title'],
            description=request.form['description'],
            address=request.form.get('address'),
            work_type=request.form.get('work_type'),
            priority=request.form.get('priority', 'normal'),
            status='new',
            created_by_id=session['user_id']
        )
        if request.form.get('client_id'):
            task.client_id = int(request.form['client_id'])
        if request.form.get('service_id'):
            task.service_id = int(request.form['service_id'])
        if request.form.get('deadline'):
            task.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        db.session.add(task)
        db.session.commit()
        log_audit('task', task.id, 'INSERT', new_data={'title': task.title})
        flash('Задача создана', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('operator_tasks'))

@app.route('/operator/tasks/<int:task_id>/assign', methods=['POST'])
@operator_required
def assign_task(task_id):
    task = Task.query.get_or_404(task_id)
    worker_id = request.form.get('worker_id')
    if not worker_id:
        flash('Выберите работника', 'danger')
        return redirect(url_for('operator_tasks'))
    try:
        task.assigned_to = int(worker_id)
        task.status = 'assigned'
        db.session.commit()
        log_audit('task', task.id, 'UPDATE', new_data={'assigned_to': worker_id, 'status': 'assigned'})
        flash('Задача назначена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('operator_tasks'))

@app.route('/operator/tasks/<int:task_id>/reject', methods=['POST'])
@operator_required
def reject_task(task_id):
    task = Task.query.get_or_404(task_id)
    try:
        task.status = 'rejected'
        db.session.commit()
        log_audit('task', task.id, 'UPDATE', new_data={'status': 'rejected'})
        flash('Задача отклонена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('operator_tasks'))

# Панель работника
@app.route('/worker')
@worker_required
def worker_dashboard():
    worker_id = session['user_id']
    assigned_tasks = Task.query.filter_by(assigned_to=worker_id, status='assigned').all()
    in_progress_tasks = Task.query.filter_by(assigned_to=worker_id, status='in_progress').all()
    completed_tasks = Task.query.filter_by(assigned_to=worker_id, status='completed').order_by(Task.completed_at.desc()).limit(10).all()
    return render_template('worker/dashboard.html',
                           assigned_tasks=assigned_tasks,
                           in_progress_tasks=in_progress_tasks,
                           completed_tasks=completed_tasks)

@app.route('/worker/tasks/<int:task_id>')
@worker_required
def worker_task_details(task_id):
    task = Task.query.get_or_404(task_id)
    if task.assigned_to != session['user_id']:
        abort(403)
    time_entries = TimeEntry.query.filter_by(task_id=task_id, worker_id=session['user_id']).order_by(TimeEntry.start_time.desc()).all()
    return render_template('worker/task_details.html', task=task, time_entries=time_entries)

@app.route('/worker/tasks/<int:task_id>/accept', methods=['POST'])
@worker_required
def worker_accept_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.assigned_to != session['user_id'] or task.status != 'assigned':
        flash('Невозможно принять эту задачу', 'danger')
        return redirect(url_for('worker_dashboard'))
    try:
        task.status = 'in_progress'
        db.session.commit()
        log_audit('task', task.id, 'UPDATE', new_data={'status': 'in_progress'})
        flash('Задача принята в работу', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('worker_dashboard'))

@app.route('/worker/tasks/<int:task_id>/reject', methods=['POST'])
@worker_required
def worker_reject_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.assigned_to != session['user_id'] or task.status != 'assigned':
        flash('Невозможно отклонить эту задачу', 'danger')
        return redirect(url_for('worker_dashboard'))
    try:
        task.status = 'rejected'
        task.assigned_to = None
        db.session.commit()
        log_audit('task', task.id, 'UPDATE', new_data={'status': 'rejected', 'assigned_to': None})
        flash('Задача отклонена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('worker_dashboard'))

@app.route('/worker/tasks/<int:task_id>/complete', methods=['POST'])
@worker_required
def worker_complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.assigned_to != session['user_id'] or task.status != 'in_progress':
        flash('Невозможно завершить эту задачу', 'danger')
        return redirect(url_for('worker_dashboard'))
    try:
        task.status = 'completed'
        task.completed_at = datetime.utcnow()
        db.session.commit()
        log_audit('task', task.id, 'UPDATE', new_data={'status': 'completed'})
        flash('Задача завершена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('worker_dashboard'))

@app.route('/worker/tasks/<int:task_id>/time/start', methods=['POST'])
@worker_required
def start_time_tracking(task_id):
    task = Task.query.get_or_404(task_id)
    if task.assigned_to != session['user_id'] or task.status != 'in_progress':
        return jsonify({'success': False, 'message': 'Невозможно начать отсчёт времени'})
    # Проверяем, нет ли уже активной записи
    active = TimeEntry.query.filter_by(worker_id=session['user_id'], end_time=None).first()
    if active:
        return jsonify({'success': False, 'message': 'Сначала завершите текущую запись'})
    try:
        entry = TimeEntry(
            task_id=task_id,
            worker_id=session['user_id'],
            start_time=datetime.utcnow(),
            description=request.form.get('description', '')
        )
        db.session.add(entry)
        db.session.commit()
        return jsonify({'success': True, 'time_entry_id': entry.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/worker/tasks/time/<int:time_entry_id>/stop', methods=['POST'])
@worker_required
def stop_time_tracking(time_entry_id):
    entry = TimeEntry.query.get_or_404(time_entry_id)
    if entry.worker_id != session['user_id']:
        return jsonify({'success': False, 'message': 'Доступ запрещён'})
    try:
        entry.end_time = datetime.utcnow()
        hours = (entry.end_time - entry.start_time).total_seconds() / 3600
        entry.hours_spent = round(hours, 2)
        db.session.commit()
        return jsonify({'success': True, 'hours_spent': entry.hours_spent})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

# Панель клиента
@app.route('/client')
@client_required
def client_dashboard():
    client_id = session['user_id']
    services = User.query.get(client_id).services
    tasks = Task.query.filter_by(client_id=client_id).order_by(Task.created_at.desc()).all()
    return render_template('client/dashboard.html', services=services, tasks=tasks)

@app.route('/client/tasks/create', methods=['POST'])
@client_required
def client_create_task():
    try:
        task = Task(
            title=request.form['title'],
            description=request.form['description'],
            status='new',
            created_by_id=session['user_id'],
            client_id=session['user_id'],
            service_id=int(request.form['service_id']) if request.form.get('service_id') else None
        )
        db.session.add(task)
        db.session.commit()
        log_audit('task', task.id, 'INSERT', new_data={'title': task.title, 'client_id': session['user_id']})
        flash('Заявка создана', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('client_dashboard'))

# API для статуса задачи (клиент)
@app.route('/api/task/<int:task_id>/status')
@login_required
def task_status(task_id):
    task = Task.query.get_or_404(task_id)
    if task.client_id != session['user_id'] and session.get('role') not in ['admin', 'operator']:
        abort(403)
    return jsonify({'status': task.status, 'created_at': task.created_at, 'completed_at': task.completed_at})

# Обработчики ошибок
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='Страница не найдена'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error='Внутренняя ошибка сервера'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error='Доступ запрещен'), 403

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
