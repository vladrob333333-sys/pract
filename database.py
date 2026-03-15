from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime
import json

db = SQLAlchemy()

# Вспомогательная таблица для связи клиентов и услуг
client_service = db.Table('client_service',
    db.Column('client_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('service_id', db.Integer, db.ForeignKey('service.id'), primary_key=True)
)

class User(db.Model):
    """Модель пользователя (админ, оператор, работник, клиент)"""
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='client')  # admin, operator, worker, client
    # Общие поля
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_change_required = db.Column(db.Boolean, default=False)  # для первого входа админа
    
    # Поля для клиента
    contract_number = db.Column(db.String(50), unique=True)  # номер договора
    services = db.relationship('Service', secondary=client_service, lazy='subquery',
                               backref=db.backref('clients', lazy=True))
    
    # Поля для работника/оператора
    position = db.Column(db.String(100))   # должность (для работников и операторов)
    department = db.Column(db.String(100)) # отдел
    
    # Связи
    created_tasks = db.relationship('Task', foreign_keys='Task.created_by_id', backref='creator', lazy=True)
    assigned_tasks = db.relationship('Task', foreign_keys='Task.assigned_to', backref='assignee', lazy=True)
    client_tasks = db.relationship('Task', foreign_keys='Task.client_id', backref='client', lazy=True)
    time_entries = db.relationship('TimeEntry', backref='worker', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class Service(db.Model):
    """Модель услуги (например, интернет, телефония, ТВ)"""
    __tablename__ = 'service'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    is_active = db.Column(db.Boolean, default=True)

class Task(db.Model):
    """Модель заявки"""
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    
    # Основные поля
    title = db.Column(db.String(200))  # краткое название
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='new')  # new, assigned, in_progress, completed, rejected, cancelled
    priority = db.Column(db.String(20), default='normal')
    
    # Связи
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # кто создал (оператор или клиент)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))  # работник, которому назначено
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'))    # клиент, если заявка от клиента
    service_id = db.Column(db.Integer, db.ForeignKey('service.id')) # услуга, к которой относится заявка (если применимо)
    
    # Детали для выездных задач
    address = db.Column(db.String(200))   # адрес выполнения (если требуется)
    work_type = db.Column(db.String(100)) # вид работ (для задач работникам)
    
    # Временные метки
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deadline = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Связи
    time_entries = db.relationship('TimeEntry', backref='task', lazy=True, cascade='all, delete-orphan')
    service = db.relationship('Service')

class TimeEntry(db.Model):
    """Учёт времени (для работников)"""
    __tablename__ = 'time_entry'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    worker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime)
    hours_spent = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    """Журнал аудита изменений в таблицах User и Task"""
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    table_name = db.Column(db.String(50), nullable=False)   # 'user', 'task'
    record_id = db.Column(db.Integer, nullable=False)       # id изменённой записи
    action = db.Column(db.String(10), nullable=False)       # 'INSERT', 'UPDATE', 'DELETE'
    old_data = db.Column(db.Text)                           # JSON строка со старыми значениями
    new_data = db.Column(db.Text)                           # JSON строка с новыми значениями
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # кто выполнил действие (может быть NULL для системы)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))                   # IPv4 или IPv6

class LoginAttempt(db.Model):
    """Журнал попыток входа"""
    __tablename__ = 'login_attempt'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45))
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def init_db():
    """Инициализация БД с тестовыми данными"""
    db.create_all()
    
    # Создание администратора по умолчанию, если его нет
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            full_name='Администратор Системы',
            role='admin',
            email='admin@company.by',
            position='Системный администратор',
            department='ИТ',
            password_change_required=True  # при первом входе потребуется смена пароля
        )
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Создание тестового оператора
        operator = User(
            username='operator',
            full_name='Петров Пётр Петрович',
            role='operator',
            email='operator@company.by',
            position='Старший оператор',
            department='Отдел обслуживания'
        )
        operator.set_password('operator123')
        db.session.add(operator)
        
        # Создание тестового работника
        worker = User(
            username='ivanov',
            full_name='Иванов Иван Иванович',
            role='worker',
            email='ivanov@company.by',
            position='Техник связи',
            department='Технический отдел'
        )
        worker.set_password('worker123')
        db.session.add(worker)
        
        # Создание тестового клиента
        client = User(
            username='client1',
            full_name='Сидоров Сидор Сидорович',
            role='client',
            email='client@example.com',
            phone='+375291234567',
            contract_number='Д-2024-001'
        )
        client.set_password('client123')
        db.session.add(client)
        
        # Создание услуг
        internet = Service(name='Интернет 100 Мбит/с', description='Безлимитный доступ в интернет', price=25.0)
        tv = Service(name='IPTV Базовый', description='50 каналов', price=15.0)
        phone = Service(name='Городской телефон', description='Безлимитный на городские номера', price=10.0)
        db.session.add_all([internet, tv, phone])
        db.session.commit()
        
        # Подключение услуг клиенту
        client.services.append(internet)
        client.services.append(tv)
        db.session.commit()
        
        # Создание тестовых задач
        from datetime import datetime, timedelta
        tasks = [
            Task(
                title='Ремонт линии связи',
                description='Замена поврежденного кабеля на участке от дома 15 до распределительного щита',
                address='г. Минск, ул. Ленина, 15',
                work_type='Ремонт линии связи',
                priority='high',
                status='new',
                created_by_id=operator.id,
                deadline=datetime.utcnow() + timedelta(days=3)
            ),
            Task(
                title='Подключение нового абонента',
                description='Подключение интернет-услуг для квартиры 45',
                address='г. Минск, пр. Независимости, 45',
                work_type='Подключение абонента',
                priority='normal',
                status='assigned',
                created_by_id=operator.id,
                assigned_to=worker.id,
                deadline=datetime.utcnow() + timedelta(days=5)
            ),
            Task(
                title='Заявка на отключение ТВ',
                description='Прошу отключить услугу IPTV, так как не пользуюсь',
                status='new',
                created_by_id=client.id,
                client_id=client.id,
                service_id=tv.id,
                priority='low'
            )
        ]
        for task in tasks:
            db.session.add(task)
        
        db.session.commit()
