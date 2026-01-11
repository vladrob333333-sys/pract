from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime

db = SQLAlchemy()

class Worker(db.Model):
    """Модель работника"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    tasks = db.relationship('Task', backref='assigned_worker', lazy=True)
    time_entries = db.relationship('TimeEntry', backref='worker', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class Task(db.Model):
    """Модель задачи/заявки"""
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(200), nullable=False)
    work_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, urgent
    status = db.Column(db.String(20), default='new')  # new, assigned, in_progress, completed, cancelled
    created_by = db.Column(db.String(100), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('worker.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deadline = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    time_entries = db.relationship('TimeEntry', backref='task', lazy=True, cascade='all, delete-orphan')

class TimeEntry(db.Model):
    """Модель учета времени выполнения"""
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    worker_id = db.Column(db.Integer, db.ForeignKey('worker.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime)
    hours_spent = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_db():
    """Инициализация базы данных с тестовыми данными"""
    db.create_all()
    
    # Создание администратора по умолчанию, если его нет
    if not Worker.query.filter_by(username='admin').first():
        admin = Worker(
            username='admin',
            full_name='Администратор Системы',
            position='Системный администратор',
            department='ИТ',
            email='admin@company.by',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Создание тестового работника
        worker = Worker(
            username='ivanov',
            full_name='Иванов Иван Иванович',
            position='Техник связи',
            department='Технический отдел',
            email='ivanov@company.by'
        )
        worker.set_password('worker123')
        db.session.add(worker)
        
        # Создание тестовых задач
        from datetime import datetime, timedelta
        
        tasks = [
            Task(
                address='г. Минск, ул. Ленина, 15',
                work_type='Ремонт линии связи',
                description='Замена поврежденного кабеля на участке от дома 15 до распределительного щита',
                priority='high',
                status='new',
                created_by='admin',
                deadline=datetime.utcnow() + timedelta(days=3)
            ),
            Task(
                address='г. Минск, пр. Независимости, 45',
                work_type='Подключение нового абонента',
                description='Подключение интернет-услуг для квартиры 45',
                priority='normal',
                status='assigned',
                created_by='admin',
                assigned_to=2,
                deadline=datetime.utcnow() + timedelta(days=5)
            )
        ]
        
        for task in tasks:
            db.session.add(task)
        
        db.session.commit()