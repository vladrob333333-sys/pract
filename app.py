from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import abort
from functools import wraps
import os
from datetime import datetime, timedelta
from database import db, Worker, Task, TimeEntry, init_db

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///instance/app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Инициализация базы данных
db.init_app(app)

with app.app_context():
    db.create_all()
    init_db()

# Декораторы для проверки прав доступа
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Требуется авторизация', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Требуется авторизация', 'warning')
            return redirect(url_for('login'))
        
        worker = Worker.query.get(session['user_id'])
        if not worker or not worker.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Маршруты аутентификации
@app.route('/')
def index():
    if 'user_id' in session:
        worker = Worker.query.get(session['user_id'])
        if worker.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('worker_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        worker = Worker.query.filter_by(username=username, is_active=True).first()
        
        if worker and check_password_hash(worker.password_hash, password):
            session['user_id'] = worker.id
            session['username'] = worker.username
            session['is_admin'] = worker.is_admin
            session['full_name'] = worker.full_name
            session.permanent = True
            
            flash('Вход выполнен успешно', 'success')
            
            if worker.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('worker_dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

# Панель администратора
@app.route('/admin')
@admin_required
def admin_dashboard():
    # Статистика для панели администратора
    total_tasks = Task.query.count()
    completed_tasks = Task.query.filter_by(status='completed').count()
    active_tasks = Task.query.filter(Task.status.in_(['assigned', 'in_progress'])).count()
    total_workers = Worker.query.filter_by(is_active=True).count()
    
    # Последние задачи
    recent_tasks = Task.query.order_by(Task.created_at.desc()).limit(10).all()
    
    # Задачи по статусам
    task_status_stats = db.session.query(
        Task.status, db.func.count(Task.id)
    ).group_by(Task.status).all()
    
    return render_template('admin_dashboard.html',
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks,
                         active_tasks=active_tasks,
                         total_workers=total_workers,
                         recent_tasks=recent_tasks,
                         task_status_stats=task_status_stats)

# Управление задачами (администратор)
@app.route('/admin/tasks')
@admin_required
def admin_tasks():
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    
    query = Task.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    tasks = query.order_by(Task.created_at.desc()).paginate(page=page, per_page=15)
    
    workers = Worker.query.filter_by(is_active=True).all()
    
    return render_template('admin_tasks.html', 
                         tasks=tasks, 
                         workers=workers,
                         status_filter=status_filter)

@app.route('/admin/tasks/create', methods=['POST'])
@admin_required
def create_task():
    try:
        task = Task(
            address=request.form['address'],
            work_type=request.form['work_type'],
            description=request.form['description'],
            priority=request.form.get('priority', 'normal'),
            created_by=session['full_name'],
            status='new'
        )
        
        if request.form.get('deadline'):
            task.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        
        db.session.add(task)
        db.session.commit()
        
        flash('Задача успешно создана', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при создании задачи: {str(e)}', 'danger')
    
    return redirect(url_for('admin_tasks'))

@app.route('/admin/tasks/<int:task_id>/update', methods=['POST'])
@admin_required
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    try:
        task.address = request.form['address']
        task.work_type = request.form['work_type']
        task.description = request.form['description']
        task.priority = request.form['priority']
        
        if request.form.get('assigned_to'):
            task.assigned_to = int(request.form['assigned_to'])
            task.status = 'assigned'
        else:
            task.assigned_to = None
        
        if request.form.get('deadline'):
            task.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        else:
            task.deadline = None
        
        db.session.commit()
        flash('Задача успешно обновлена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при обновлении задачи: {str(e)}', 'danger')
    
    return redirect(url_for('admin_tasks'))

@app.route('/admin/tasks/<int:task_id>/delete', methods=['POST'])
@admin_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    try:
        db.session.delete(task)
        db.session.commit()
        flash('Задача успешно удалена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении задачи: {str(e)}', 'danger')
    
    return redirect(url_for('admin_tasks'))

@app.route('/admin/tasks/<int:task_id>/change_status', methods=['POST'])
@admin_required
def change_task_status(task_id):
    task = Task.query.get_or_404(task_id)
    new_status = request.form['status']
    
    try:
        task.status = new_status
        
        if new_status == 'completed':
            task.completed_at = datetime.utcnow()
        
        db.session.commit()
        flash('Статус задачи обновлен', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    
    return redirect(url_for('admin_tasks'))

# Управление работниками (администратор)
@app.route('/admin/workers')
@admin_required
def admin_workers():
    workers = Worker.query.order_by(Worker.created_at.desc()).all()
    return render_template('admin_workers.html', workers=workers)

@app.route('/admin/workers/create', methods=['POST'])
@admin_required
def create_worker():
    try:
        username = request.form['username']
        
        # Проверка уникальности имени пользователя
        if Worker.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'danger')
            return redirect(url_for('admin_workers'))
        
        worker = Worker(
            username=username,
            full_name=request.form['full_name'],
            position=request.form['position'],
            department=request.form['department'],
            phone=request.form.get('phone', ''),
            email=request.form.get('email', ''),
            is_admin=request.form.get('is_admin') == 'on'
        )
        
        worker.set_password(request.form['password'])
        
        db.session.add(worker)
        db.session.commit()
        
        flash('Работник успешно добавлен', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при добавлении работника: {str(e)}', 'danger')
    
    return redirect(url_for('admin_workers'))

@app.route('/admin/workers/<int:worker_id>/update', methods=['POST'])
@admin_required
def update_worker(worker_id):
    worker = Worker.query.get_or_404(worker_id)
    
    try:
        worker.full_name = request.form['full_name']
        worker.position = request.form['position']
        worker.department = request.form['department']
        worker.phone = request.form.get('phone', '')
        worker.email = request.form.get('email', '')
        worker.is_active = request.form.get('is_active') == 'on'
        worker.is_admin = request.form.get('is_admin') == 'on'
        
        if request.form.get('password'):
            worker.set_password(request.form['password'])
        
        db.session.commit()
        flash('Данные работника обновлены', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при обновлении данных: {str(e)}', 'danger')
    
    return redirect(url_for('admin_workers'))

# Панель работника
@app.route('/worker')
@login_required
def worker_dashboard():
    worker_id = session['user_id']
    
    # Активные задачи работника
    active_tasks = Task.query.filter_by(
        assigned_to=worker_id,
        status='assigned'
    ).order_by(Task.deadline.asc()).all()
    
    # Задачи в работе
    in_progress_tasks = Task.query.filter_by(
        assigned_to=worker_id,
        status='in_progress'
    ).order_by(Task.deadline.asc()).all()
    
    # Завершенные задачи (последние 10)
    completed_tasks = Task.query.filter_by(
        assigned_to=worker_id,
        status='completed'
    ).order_by(Task.completed_at.desc()).limit(10).all()
    
    # Статистика по времени
    today = datetime.utcnow().date()
    week_start = today - timedelta(days=today.weekday())
    
    # Время за сегодня
    today_time = db.session.query(db.func.sum(TimeEntry.hours_spent)).filter(
        TimeEntry.worker_id == worker_id,
        db.func.date(TimeEntry.start_time) == today
    ).scalar() or 0
    
    # Время за неделю
    week_time = db.session.query(db.func.sum(TimeEntry.hours_spent)).filter(
        TimeEntry.worker_id == worker_id,
        db.func.date(TimeEntry.start_time) >= week_start
    ).scalar() or 0
    
    return render_template('worker_dashboard.html',
                         active_tasks=active_tasks,
                         in_progress_tasks=in_progress_tasks,
                         completed_tasks=completed_tasks,
                         today_time=today_time,
                         week_time=week_time)

@app.route('/worker/tasks/<int:task_id>')
@login_required
def task_details(task_id):
    task = Task.query.get_or_404(task_id)
    worker_id = session['user_id']
    
    # Проверка, что задача назначена текущему работнику
    if task.assigned_to != worker_id and not session.get('is_admin'):
        abort(403)
    
    # Временные записи для этой задачи
    time_entries = TimeEntry.query.filter_by(
        task_id=task_id,
        worker_id=worker_id
    ).order_by(TimeEntry.start_time.desc()).all()
    
    return render_template('task_details.html', 
                         task=task, 
                         time_entries=time_entries)

@app.route('/worker/tasks/<int:task_id>/accept', methods=['POST'])
@login_required
def accept_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.status != 'assigned' or task.assigned_to != session['user_id']:
        flash('Невозможно принять эту задачу', 'danger')
        return redirect(url_for('worker_dashboard'))
    
    try:
        task.status = 'in_progress'
        db.session.commit()
        flash('Задача принята в работу', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    
    return redirect(url_for('worker_dashboard'))

@app.route('/worker/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.assigned_to != session['user_id'] or task.status != 'in_progress':
        flash('Невозможно завершить эту задачу', 'danger')
        return redirect(url_for('worker_dashboard'))
    
    try:
        task.status = 'completed'
        task.completed_at = datetime.utcnow()
        
        # Завершение активной временной записи, если есть
        active_time_entry = TimeEntry.query.filter_by(
            task_id=task_id,
            worker_id=session['user_id'],
            end_time=None
        ).first()
        
        if active_time_entry:
            active_time_entry.end_time = datetime.utcnow()
            hours = (active_time_entry.end_time - active_time_entry.start_time).total_seconds() / 3600
            active_time_entry.hours_spent = round(hours, 2)
        
        db.session.commit()
        flash('Задача отмечена как выполненная', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    
    return redirect(url_for('worker_dashboard'))

@app.route('/worker/tasks/<int:task_id>/time/start', methods=['POST'])
@login_required
def start_time_tracking(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.assigned_to != session['user_id'] or task.status != 'in_progress':
        return jsonify({'success': False, 'message': 'Невозможно начать отсчет времени для этой задачи'})
    
    # Проверка, нет ли уже активной записи времени
    active_entry = TimeEntry.query.filter_by(
        worker_id=session['user_id'],
        end_time=None
    ).first()
    
    if active_entry:
        return jsonify({'success': False, 'message': 'Завершите текущую запись времени перед началом новой'})
    
    try:
        time_entry = TimeEntry(
            task_id=task_id,
            worker_id=session['user_id'],
            start_time=datetime.utcnow(),
            description=request.form.get('description', '')
        )
        
        db.session.add(time_entry)
        db.session.commit()
        
        return jsonify({'success': True, 'time_entry_id': time_entry.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/worker/tasks/time/<int:time_entry_id>/stop', methods=['POST'])
@login_required
def stop_time_tracking(time_entry_id):
    time_entry = TimeEntry.query.get_or_404(time_entry_id)
    
    if time_entry.worker_id != session['user_id']:
        return jsonify({'success': False, 'message': 'Доступ запрещен'})
    
    try:
        time_entry.end_time = datetime.utcnow()
        hours = (time_entry.end_time - time_entry.start_time).total_seconds() / 3600
        time_entry.hours_spent = round(hours, 2)
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'hours_spent': time_entry.hours_spent,
            'total_hours': get_total_task_hours(time_entry.task_id)
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

def get_total_task_hours(task_id):
    total = db.session.query(db.func.sum(TimeEntry.hours_spent)).filter_by(
        task_id=task_id
    ).scalar()
    return round(total or 0, 2)

# API для получения статистики
@app.route('/api/stats')
@login_required
def get_stats():
    worker_id = session['user_id']
    
    if session.get('is_admin'):
        # Статистика для администратора
        stats = {
            'total_tasks': Task.query.count(),
            'completed_tasks': Task.query.filter_by(status='completed').count(),
            'active_workers': Worker.query.filter_by(is_active=True).count()
        }
    else:
        # Статистика для работника
        today = datetime.utcnow().date()
        
        stats = {
            'assigned_tasks': Task.query.filter_by(assigned_to=worker_id, status='assigned').count(),
            'in_progress_tasks': Task.query.filter_by(assigned_to=worker_id, status='in_progress').count(),
            'today_hours': db.session.query(db.func.sum(TimeEntry.hours_spent)).filter(
                TimeEntry.worker_id == worker_id,
                db.func.date(TimeEntry.start_time) == today
            ).scalar() or 0
        }
    
    return jsonify(stats)

if __name__ == '__main__':
    app.run(debug=True)