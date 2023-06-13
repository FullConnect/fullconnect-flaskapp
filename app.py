from collections import defaultdict
from datetime import datetime
import uuid
import bcrypt
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, ValidationError, DataRequired, Email, EqualTo, Length
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from flask import Flask, abort, flash, render_template, request, redirect, session, url_for
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import Serializer
from werkzeug.security import generate_password_hash
from flask import abort, url_for, redirect, render_template
from flask_mail import Mail, Message
from flask_bootstrap import Bootstrap




app = Flask(__name__)


# app.config['SQLALCHEMY_DATABASE_URI']           = 'mysql+pymysql://root:a13gHvx068@db/mstech'
app.config['SQLALCHEMY_DATABASE_URI']           = 'mysql+pymysql://root:a13gHvx068.@localhost:3306/mstech'
db = SQLAlchemy(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']    = False
app.config['SQLALCHEMY_ENGINE_OPTIONS']         = {"pool_pre_ping": True}    
app.config['SECRET_KEY']                        = 'secretstring'


bootstrap = Bootstrap(app)


# настройки для Mail.ru
app.config['MAIL_SERVER']           = 'smtp.mail.ru'
app.config['MAIL_PORT']             = 465
app.config['MAIL_DEFAULT_SENDER']   = 'roman-kotkov.ru@mail.ru'
app.config['MAIL_USERNAME']         = 'roman-kotkov.ru@mail.ru'
app.config['MAIL_PASSWORD']         = 'L7cth91TPpKGM12wNrju'
app.config['MAIL_USE_TLS']          = False
app.config['MAIL_USE_SSL']          = True


mail = Mail(app)


def send_email(to, subject, template):
    msg = Message(subject, recipients = [to], body = template, sender = app.config["MAIL_USERNAME"])
    mail.send(msg)


# login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)




##################### Модели баз данных ####################


# Таблица пользователей
class User(db.Model, UserMixin):
    id              = db.Column(db.Integer, primary_key = True)
    first_name      = db.Column(db.String(50), nullable = False)
    last_name       = db.Column(db.String(50), nullable = False)
    email           = db.Column(db.String(50), unique = True, nullable = False)
    phone           = db.Column(db.String(12),  nullable = False)
    organization    = db.Column(db.String(100), nullable = True)
    password        = db.Column(db.String(255), unique = True, nullable = False)
    is_admin        = db.Column(db.Boolean, default=False)
    # UPDATE public."user" SET is_admin = True WHERE id = 8;

    def __repr__(self):
        return '<User {}>'.format(self.email)


    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


    def check_password(self, password):
            return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    

    def is_authenticated(self):
        return True


    def is_active(self):
        return True


    def is_anonymous(self):
        return False


    def get_id(self):
        return str(self.id)

    
    def get_reset_password_token(self):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'reset_password': self.id})


    @staticmethod
    def verify_reset_password_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            id = s.loads(token)['reset_password']
        except:
            return None
        return User.query.get(id)


# Таблица добавления категорий
class Category(db.Model):
    id_cat      = db.Column(db.Integer, primary_key=True)
    name_cat    = db.Column(db.String(100), nullable=False)
    paraments   = db.relationship('Paraments', backref='category', lazy=True)
    
    def __repr__(self):
        return f'<Category {self.id_cat}>'


# Таблица добавления параметров для измерительного прибора
class Paraments(db.Model):
    id           = db.Column(db.Integer, primary_key = True)
    id_paraments = db.Column(db.String(20), nullable = False, unique = False)
    param_descr  = db.Column(db.String(100), nullable = False, unique = False)
    category_id  = db.Column(db.Integer, db.ForeignKey('category.id_cat'))

    def __repr__(self):
        return f'<Paraments {self.id}>'

    
# Временная таблица корзина
class Cart(db.Model):
    id                          = db.Column(db.Integer, primary_key=True)
    basetype                    = db.Column(db.String(20))
    extend_basetype             = db.Column(db.String(20), nullable = False, unique = False)
    measuring_range             = db.Column(db.String(20), nullable = False, unique = False)
    exit_range                  = db.Column(db.String(20), nullable = False, unique = False)
    display                     = db.Column(db.String(20), nullable = False, unique = False)
    connection_process          = db.Column(db.String(20), nullable = False, unique = False)
    temperature_measured        = db.Column(db.String(20), nullable = False, unique = False)
    process_connection_material = db.Column(db.String(20), nullable = False, unique = False)
    electrical_connection       = db.Column(db.String(20), nullable = False, unique = False)
    typical_additions           = db.Column(db.String(20), nullable = False, unique = False)
    liquid                      = db.Column(db.String(20), nullable = False, unique = False)
    quantity                    = db.Column(db.Integer, nullable = False)



# Таблица заказанных товаров
class CheckoutItem(db.Model):
    id              = db.Column(db.Integer, primary_key = True)
    order_id        = db.Column(db.Integer, nullable=False, primary_key = False)
    first_name      = db.Column(db.String(50),  nullable = False)
    last_name       = db.Column(db.String(50),  nullable = False)
    email           = db.Column(db.String(50),  nullable = False)
    organization    = db.Column(db.String(100), nullable = False)
    phone           = db.Column(db.String(12),  nullable = False)
    device          = db.Column(db.String(50),  nullable = False)
    quantity        = db.Column(db.String(3),  nullable = False)
    date            = db.Column(db.DateTime, default = datetime.now)


# Таблица добавления категорий услуг
class ServiceCat(db.Model):
    id_serv_cat = db.Column(db.Integer, primary_key = True)
    name_serv_cat = db.Column(db.String(100), nullable=False)
    servicerecords = db.relationship('ServiceRecords', backref = 'servicecat', lazy=True)

    def __repr__(self):
        return f'<ServiceCat {self.id_serv_cat}>'


# Таблица записи услуг
class ServiceRecords(db.Model):
    id              = db.Column(db.Integer, primary_key = True)
    first_name      = db.Column(db.String(50), nullable = False)
    last_name       = db.Column(db.String(50), nullable = False)
    email           = db.Column(db.String(50), nullable = False)
    organization    = db.Column(db.String(100), nullable = False)
    phone           = db.Column(db.String(50), nullable = False)
    name_serv_cat     = db.Column(db.Integer, db.ForeignKey('service_cat.id_serv_cat'))
    data            = db.Column(db.String(20), nullable = False)
    commentary      = db.Column(db.String(100), nullable = True)

    def __repr__(self):
        return f'<ServiceRecords {self.id_service_rec}>'


#################### Таблицы закрыты ####################




##################### Формы ####################


# Форма регистрации
class RegisterForm(FlaskForm):
    first_name          = StringField(validators = [InputRequired(), Length(min = 2, max = 30)],            render_kw = {"placeholder": "Имя"})
    last_name           = StringField(validators = [InputRequired(), Length(min = 2, max = 30)],            render_kw = {"placeholder": "Фамилия"})
    email               = StringField(validators = [DataRequired(), Email(), Length(min = 6, max = 100)],   render_kw = {"placeholder": "Почта"})
    phone               = StringField(validators = [DataRequired()],                                        render_kw = {"placeholder": "Номер телефона"})
    organization        = StringField(validators = [DataRequired(), Length(min=2, max=50)],                 render_kw = {"placeholder": "Организация"})
    password            = PasswordField(validators = [InputRequired(), Length(min = 8, max = 255)],         render_kw = {"placeholder": "Пароль"})
    confirm_password    = PasswordField(validators = [EqualTo('password', message='Passwords must match')], render_kw = {"placeholder": "Повтор пароля"})
    submit              = SubmitField('ЗАРЕГИСТРИРОВАТЬСЯ')
    
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email = email.data).first()
        if existing_user_email:
            raise ValidationError('Эта почта уже используется')


# Форма авторизации
class LoginForm(FlaskForm):
    email      = StringField(validators   = [InputRequired(), Length(min = 6, max = 100)], render_kw = {"placeholder": "Почта"})
    password   = PasswordField(validators = [InputRequired(), Length(min = 8, max = 255)], render_kw = {"placeholder": "Пароль"})
    submit     = SubmitField('ВОЙТИ')


# Форма отправки письма на почту для изменения пароля
class RequestResetForm(FlaskForm):
    email = StringField('Почта', validators=[DataRequired(), Email()])
    submit = SubmitField('Сбросить пароль')

    def validate_email(self, email):
        user = User.query.filter_by(email = email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

# Форма восстановления пароля
class ResetPasswordForm(FlaskForm):
    password = PasswordField('Пароль', validators = [DataRequired(), Length(min=8, max=32)])
    confirm_password = PasswordField('Подтвердите пароль', validators = [DataRequired(), EqualTo('password')])
    submit = SubmitField('Сбросить пароль')



# Форма изменения данных в профиле
class EditProfileForm(FlaskForm):
    first_name          = StringField('Имя', validators = [DataRequired()])
    last_name           = StringField('Отчество', validators = [DataRequired()])
    email               = StringField('Почта', validators = [DataRequired(), Email()])
    phone               = StringField('Номер телефона', validators = [DataRequired()])
    organization        = StringField('Организация', validators = [DataRequired(), Length(min=2, max=50)])
    password            = PasswordField('Новый пароль')
    confirm_password    = PasswordField('Повтор пароля', validators = [EqualTo('password', message = 'Passwords must match')])
    submit              = SubmitField('Сохранить')


# Форма добавления категорий
class CategoryForm(FlaskForm):
    name_cat   = StringField(validators   = [InputRequired(), Length(min = 4, max = 50)], render_kw = {"placeholder": "Наименование категории"})
    submit = SubmitField('Добавить категорию')


# Форма добавления параметров
class ParamentsForm(FlaskForm):
    id_paraments = StringField(validators = [InputRequired(), Length(min = 1, max = 20)], render_kw = {"placeholder": "Номер"})
    param_descr  = StringField(validators = [InputRequired(), Length(min = 2, max = 100)], render_kw = {"placeholder": "Описание"})
    category_id  = SelectField('Сategory', choices = [(category.id_cat, category.name_cat) for category in Category.query.all()], validators = [DataRequired()])
    submit       = SubmitField('Добавить')


# Форма добавления товара в корзину
class AddToCartForm(FlaskForm):
    basetype                     =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 1],  validators = [DataRequired()])
    extend_basetype              =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 2],  validators = [DataRequired()])
    measuring_range              =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 3],  validators = [DataRequired()])
    exit_range                   =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 4],  validators = [DataRequired()])
    display                      =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 5],  validators = [DataRequired()])
    connection_process           =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 6],  validators = [DataRequired()])
    temperature_measured         =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 7],  validators = [DataRequired()])
    process_connection_material  =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 8],  validators = [DataRequired()])
    electrical_connection        =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 9],  validators = [DataRequired()])
    typical_additions            =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 10], validators = [DataRequired()])
    liquid                       =  SelectField('Paraments', choices = [(paraments.id_paraments, paraments.param_descr) for paraments in Paraments.query.all() if paraments.category_id == 11], validators = [DataRequired()])
    quantity                     =  IntegerField('Quantity')
    submit                       =  SubmitField('Добавить')

# Форма оформления заказа
class CheckoutForm(FlaskForm):
    first_name      = StringField('First Name')
    last_name       = StringField('Last Name')
    organization    = StringField('Organization')
    email           = StringField('Email', validators=[DataRequired(), Email()])
    phone           = StringField('Phone')
    submit          = SubmitField('Оформить заказ')


# Форма добавления сервиса
class AddServiceForm(FlaskForm):
    name_serv_cat   = StringField(validators   = [InputRequired(), Length(min = 4, max = 50)], render_kw = {"placeholder": "Наименование услуги"})
    submit          = SubmitField('Добавить услугу')


# Запись на услугу
class ServicerecordsForm(FlaskForm):
    first_name          = StringField('Имя', validators=[DataRequired()])
    last_name           = StringField('Фамилия', validators=[DataRequired()])
    email               = StringField('Email', validators=[DataRequired(), Email()])
    organization        = StringField('Организация', validators=[DataRequired()])
    phone               = StringField('Телефон', validators=[DataRequired()])
    name_serv_cat       = SelectField('Категория услуги', choices=[(service_cat.id_serv_cat, service_cat.name_serv_cat) for service_cat in ServiceCat.query.all()])
    data                = StringField('Дата', validators=[DataRequired()])
    commentary          = StringField('Комментарий')
    submit              = SubmitField('Добавить')


# Форма установки администратора
class SetAdminForm(FlaskForm):
    submit = SubmitField('Set as Admin', validators=[DataRequired()])


##################### Формы закрыты ####################


##################### Маршруты ####################


# Главная
@app.route('/', methods = ['GET', 'POST'])
@app.route('/index', methods = ['GET', 'POST'])
def index():
    total_quantity = 0
    if 'cart' in session:
        cart_items = session['cart']
        for cart_item in cart_items:
            total_quantity += cart_item['quantity']

    return render_template('index.html', title = 'Главная',  total_quantity = total_quantity)


# отправка сообщения-заявки
@app.route('/send_msg_company', methods = ['POST'])
def contact():
    if request.method == 'POST':
        name    = request.form['first_name'] # значение из поля имени
        phone   = request.form['telephone'] # значение из поля телефона
        text    = request.form['text'] # значение из поля сообщения
        msg     = Message('Сообщение от {}'.format(name), recipients = ['roman-kotkov.ru@mail.ru'], sender = app.config["MAIL_USERNAME"])
        msg.body = """
            Сообщение от {}
            Номер телефона: {}
            Вопрос:\n{}
            """.format(name, phone, text)
        mail.send(msg)
        return redirect(url_for('index'))


# Регистрация
@app.route('/registration', methods = ['GET', 'POST'])
def registration():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            new_user = User(first_name      = form.first_name.data,
                            last_name       = form.last_name.data,
                            email           = form.email.data,
                            phone           = form.phone.data,
                            organization    = form.organization.data,
                            password        = hashed_password
                        )            
            db.session.add(new_user)
            db.session.commit()

        return redirect(url_for('login'))
    else:
        flash('Пользователь с таким email уже существует.')

    return render_template('registration.html', form = form, title = 'Регистрация')


# Авторизация пользователя
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is None or not user.check_password(form.password.data):

            flash('Неверный email или пароль')

            return redirect(url_for('login'))
        
        login_user(user)

        return redirect(url_for('index'))
    
    return render_template('login.html', title = 'Авторизация', form = form)


# Выход из профиля
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# Письмо для восстановления пароля
def send_reset_email(user):
    token = user.get_reset_password_token()
    msg = Message('Сброс пароля', sender = 'roman-kotkov.ru@mail.ru', recipients = [user.email])
    msg.body = f''' 
    Для сброса пароля перейдите по ссылке:
    {url_for('reset_password_confirm', token = token, _external=True)}
    Если вы не запрашивали сброс пароля, то проигнорируйте это сообщение
    '''
    mail.send(msg)


# Страница с отправкой на почту запроса восстановления пароля
@app.route('/reset_password', methods = ['GET', 'POST'])
def reset_password():

    form = RequestResetForm()

    if form.validate_on_submit():

        user = User.query.filter_by(email = form.email.data).first()
        send_reset_email(user)

        flash('На указанный емайл была отправлена инструктция для восставноления пароля')

        return redirect(url_for('index'))
            
    return render_template('reset_password.html', title = 'Сброс пароля', form = form)


# Страница с восстановлением пароля
@app.route('/reset_password_confirm/<token>', methods = ['GET', 'POST'])
def reset_password_confirm(token):

    form = ResetPasswordForm()
    user = User.verify_reset_password_token(token)

    if not user:
        flash('Неправильный или устаревший токен, попробуйте еще раз')

        return redirect(url_for('reset_password'))  
    
    if form.validate_on_submit():  # Если форма введена и прошла валидацию

        if user:
            
            user.set_password(form.password.data)
            db.session.commit()
            logout_user()
            login_user(user)
            return redirect(url_for('login'))
        else:
            return 'Не удалось изменить пароль'      

    return render_template('reset_password_confirm.html', form = form, title = 'Сброс пароля', token = token)


# Профиль
@app.route('/profile', methods = ['GET', 'POST'])
@login_required
def profile():
    user_orders = CheckoutItem.query.filter_by(email = current_user.email).all()
    orders = defaultdict(list)
    for order in user_orders:
        orders[order.order_id].append(order)
    
    user_records = ServiceRecords.query.filter_by(email=current_user.email).all()
    records = defaultdict(list)
    for record in user_records:
        records[record.data].append(record)
        
    return render_template('profile.html', user = current_user, title = 'Профиль', user_orders = user_orders, orders = orders, records = records)


# Изменение данных профиля
@app.route('/edit_profile', methods = ['GET', 'POST'])
def edit_profile():
    form = EditProfileForm()

    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(id=session['user_id']).first()

        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.email = form.email.data
        user.phone = form.phone.data
        user.organization = form.organization.data

        if form.password.data:
            user.password = generate_password_hash(form.password.data)

        db.session.commit()

        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', form=form)


# Добавление товара в корзину
@app.route('/add-to-cart', methods = ['GET', 'POST'])
def add_to_cart():
    if 'cart' not in session:
        session['cart'] = []
    form = AddToCartForm()
    if request.method == 'POST' and form.validate_on_submit():
        item = {
            'basetype':                    form.basetype.data,
            'extend_basetype':             form.extend_basetype.data,
            'measuring_range':             form.measuring_range.data,
            'exit_range':                  form.exit_range.data,
            'display':                     form.display.data,
            'connection_process':          form.connection_process.data,
            'temperature_measured':        form.temperature_measured.data,
            'process_connection_material': form.process_connection_material.data,
            'electrical_connection':       form.electrical_connection.data,
            'typical_additions':           form.typical_additions.data,
            'liquid':                      form.liquid.data,
            'quantity':                    form.quantity.data
        }
        session['cart'].append(item)
        session['message'] = f'Товар добавлен в корзину'
        return redirect(url_for('cart'))
    
    return render_template('add-to-cart.html', form = form)


# Корзина
@app.route('/cart')
def cart():
    form = CheckoutForm()
    total_quantity = 0
    if 'cart' in session:
        cart_items = session['cart']
        for cart_item in cart_items:
            total_quantity += cart_item['quantity']

    return render_template('cart.html', cart_items = cart_items, total_quantity = total_quantity, form = form)


# Удаление товара из корзины
@app.route('/remove-from-cart', methods = ['POST'])
def remove_from_cart():
    item_id = int(request.form['item_id'])
    del session['cart'][item_id]

    session['message'] = 'Item removed from cart'

    return redirect(url_for('cart'))


# Заказы
@app.route('/orders')
def orders():
    orders = CheckoutItem.query.order_by(CheckoutItem.date.desc()).all()

    return render_template('orders.html', orders = orders)


# Детализация заказа
@app.route('/orders_details/<int:order_id>', methods = [  "GET", "POST"])
@login_required
def orders_details(order_id):
    order = CheckoutItem.query.filter_by(order_id = order_id, email = current_user.email).first()
    if not order: 
        abort(404)
    order_items = CheckoutItem.query.filter_by(order_id = order_id)

    return render_template('order_details.html', order = order, order_items = order_items, date_format = '%A, %B %d, %Y at %I:%M %p')


def generate_order_id():
    uuid_str = str(uuid.uuid4().int)[:6]
    return uuid_str


# Оформление заявки через корзину
@app.route('/checkout', methods = ["GET", "POST"])
def checkout():
    form = CheckoutForm()
    cart_items = session.get('cart', [])
    total_quantity = 0
    
    if current_user.is_authenticated:
        form.first_name.data    = current_user.first_name
        form.last_name.data     = current_user.last_name
        form.email.data         = current_user.email
        form.organization.data  = current_user.organization
        form.phone.data         = current_user.phone

    if form.validate_on_submit():
        order_id = generate_order_id()
        for item in cart_items:
            item_data = {
                'basetype':                     item['basetype'],
                'extend_basetype':              item.get('extend_basetype'),
                'measuring_range':              item['measuring_range'],
                'exit_range':                   item.get('exit_range'),
                'display':                      item.get('display'),
                'connection_process':           item.get('connection_process'),
                'temperature_measured':         item.get('temperature_measured'),
                'process_connection_material':  item.get('process_connection_material'),
                'electrical_connection':        item.get('electrical_connection'),
                'typical_additions':            item.get('typical_additions'),
                'liquid':                       item.get('liquid'),
            }
          

            device          = '-'.join(map(str, item_data.values()))
            total_quantity += item['quantity']
            checkout_data   = CheckoutItem(
                order_id        = order_id,
                first_name      = form.first_name.data,
                last_name       = form.last_name.data,
                email           = form.email.data,
                organization    = form.organization.data,
                phone           = form.phone.data,
                device          = device,
                quantity        = item['quantity']
            )
            
            db.session.add(checkout_data)
            db.session.commit()


            # Отправка письма
        msg_body  = f'Ваш заказ поступил в обработку\n'
        msg_body += f'Заказ номер {order_id}\n'
        msg_body += f'Ожидайте звонка мнеджера\n '

        send_email(form.email.data, f'Заказ номер {order_id}', msg_body)

        session.pop('cart', None)

        return redirect(url_for('index'))
    
    return render_template('cart.html', form = form, cart_items = cart_items, total_quantity = total_quantity)


# Оформление заказа + отправка на почту
@app.route('/about', methods = ['GET', 'POST'])
def about(): 
    return render_template('about.html', title = 'О нас')


# Оформление заказа + отправка на почту
@app.route('/service', methods = ['GET', 'POST'])
def service():
    form = ServicerecordsForm()
    if form.validate_on_submit():
        service_record = ServiceRecords(
            first_name      = form.first_name.data,
            last_name       = form.last_name.data,
            email           = form.email.data,
            organization    = form.organization.data,
            phone           = form.phone.data,
            name_serv_cat   = form.name_serv_cat.data,
            data            = form.data.data,
            commentary      = form.commentary.data
        )
        db.session.add(service_record)
        db.session.commit()

    
         # Отправка письма
        msg_body  = f'Ваш заказ на услугу поступил в обработку\n'
        msg_body += f'Ожидайте звонка мнеджера\n '

        send_email(form.email.data, f'Заказ услуги', msg_body)
        return redirect(url_for('index'))

    return render_template('service.html', title = 'Запись на услугу', form = form)

# Просмотр деталей заявки на услугу
@app.route('/service_details/<int:id>', methods=['GET', 'POST'])
@login_required
def service_details(id):
    record = ServiceRecords.query.filter_by(id = id, email = current_user.email).first()
    if not record:
        abort(404)
    record_items = CheckoutItem.query.filter_by(id = id)
    return render_template('service_details.html', record = record, record_items = record_items)


##################### Административная часть ####################


# Страница админа
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)

    return render_template('admin_dashboard.html', title = 'Административная часть')


# Установка роли администратора
@app.route('/set_admin/<int:id>')
def set_admin(id):
    user = User.query.get_or_404(id)
    form = SetAdminForm()

    if form.validate_on_submit():
        user.is_admin = True # здесь вы можете установить любое значение
        db.session.commit()
        return 'Пользователь теперь админ'
    return render_template('set_admin.html', form = form, user =  user)


# Добавление категории для параметров товара
@app.route('/admin/add_category', methods = ['GET', 'POST'])
def add_category():
    form = CategoryForm()
    if form.validate_on_submit():
        categories = Category(name_cat = form.name_cat.data)
        db.session.add(categories)
        db.session.commit()

    return render_template('add_category.html', form = form, title = 'Добавление категории')   


# Просмотр всех категорий
@app.route('/admin/view_category', endpoint = 'view_category')
def view_category():
    categories = Category.query.all()
    return render_template('view_category.html', categories = categories, title = 'Просмотр категорий')


# Добавление параметров для измерительных приборов в заввисимости от категории
@app.route('/admin/add_paraments', methods=['GET', 'POST'])
def add_paraments():
    form = ParamentsForm()
    if form.validate_on_submit():
        parameter = Paraments(id_paraments = form.id_paraments.data,
                              param_descr  = form.param_descr.data,
                              category_id  = form.category_id.data)
        db.session.add(parameter)
        db.session.commit()
        # flash('Параметр успешно добавлен!')
    return render_template('add_paraments.html', form = form, title = 'Добавление параметров')

# Просмотр всех категорий
@app.route('/admin/view_paraments', endpoint='view_paraments')
def view_category():
    parament = Paraments.query.order_by(Paraments.category_id.asc(), Paraments.id_paraments.asc()).all()

    return render_template('view_paraments.html', parament = parament, title = 'Просмотр параметров')


# Просмотр всех заказанных товаров
@app.route('/admin/checkout_item', methods = [  "GET", "POST"])
def checkout_item():
    checkout_items = CheckoutItem.query.all()
    return render_template('checkout_item.html', title = 'Просмотр всех заказаных товаров', checkout_items = checkout_items)


# Просмотр всех заказов
@app.route('/admin/admin_orders')
def admin_orders():
    orders = CheckoutItem.query.with_entities(CheckoutItem.order_id).distinct().all()

    return render_template('admin_orders.html', orders = orders)


# Детализация заказа для админа
@app.route('/admin/admin_orders_details/<int:order_id>', methods = [  "GET", "POST"])
@login_required
def admin_orders_details(order_id):
    order = CheckoutItem.query.filter_by(order_id = order_id).first()
    if not order: 
        abort(404)
    order_items = CheckoutItem.query.filter_by(order_id = order_id)

    return render_template('admin_orders_details.html', order = order, order_items = order_items, date_format = '%A, %B %d, %Y at %I:%M %p')


# Добавление услуги для параметров товара
@app.route('/admin/add_service', methods = ['GET', 'POST'])
def add_service():
    form = AddServiceForm()
    if form.validate_on_submit():
        services = ServiceCat(name_serv_cat = form.name_serv_cat.data)
        db.session.add(services)
        db.session.commit()

    return render_template('add_service.html', form = form, title = 'Добавление услуги')   


# Просмотр всех услуг 
@app.route('/admin/view_service', methods = ['GET', 'POST'])
def view_service():
    services = ServiceCat.query.all()
    return render_template('view_service.html', services = services, title = 'Просмотр всех услуг')




if __name__ == '__main__':
    db.create_all()
    app.run(debug = True, host = '0.0.0.0')