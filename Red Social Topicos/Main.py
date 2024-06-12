from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import LoginManager, login_required, current_user, login_user, logout_user, UserMixin
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import os
import secrets


# Configuración de la aplicación Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/proyectofinal'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Configuración del correo
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
mail = Mail(app)

# Inicialización de SQLAlchemy
db = SQLAlchemy(app)

# Inicialización del LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# Define los tipos de archivos permitidos
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Modelos
class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    followed_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255))
    fullname = db.Column(db.String(120))
    bio = db.Column(db.Text)
    gender = db.Column(db.String(10))
    dob = db.Column(db.Date, nullable=True)
    phone = db.Column(db.String(15))
    profile_picture = db.Column(db.String(255))
    
    # Relaciones de seguimiento
    followed = db.relationship(
        'User', secondary='follows',
        primaryjoin=(id == Follow.follower_id),
        secondaryjoin=(id == Follow.followed_id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic'
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_following(self, user):
        return self.followed.filter(Follow.followed_id == user.id).count() > 0

    def follow(self, user):
        if not self.is_following(user):
            follow = Follow(follower_id=self.id, followed_id=user.id)
            db.session.add(follow)

    def unfollow(self, user):
        if self.is_following(user):
            Follow.query.filter_by(
                follower_id=self.id,
                followed_id=user.id).delete()
    def followed_posts(self):
        return Post.query.join(
            Follow, (Follow.followed_id == Post.user_id)
        ).filter(
            Follow.follower_id == self.id
        ).order_by(
            Post.created_at.desc()
        )


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='posts', lazy=True)
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    image = db.Column(db.String(255))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='user_comments', lazy=True)

class MessageModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255))  # Nota: 'descripcion' cambiado a 'description'
    date_notification = db.Column(db.Date)  # Nota: 'fecha_notificacion' cambiado a 'date_notification'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Nota: 'id_usuario' cambiado a 'user_id'
    leida = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='notifications', lazy=True)

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='reset_tokens', lazy=True)

# Rutas y vistas

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/notifications', methods=['GET'])
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.date_notification.desc()).all()
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get(notification_id)
    if notification and notification.user_id == current_user.id:
        notification.leida = True
        db.session.commit()
    return redirect(url_for('notifications'))



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(20)
            reset_token = PasswordResetToken(token=token, user_id=user.id)
            db.session.add(reset_token)
            db.session.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message(subject='Password Reset Request', sender=os.environ.get('EMAIL_USER'), recipients=[email])
            msg.body = f'''Para restablecer tu contraseña, visita el siguiente enlace:
{reset_url}
Si no realizaste esta solicitud, por favor ignora este correo.
'''
            mail.send(msg)
            flash('Se ha enviado un correo con las instrucciones para restablecer tu contraseña.', 'info')
        else:
            flash('No se encontró una cuenta con ese correo.', 'warning')
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first_or_404()
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password == confirm_password:
            user = reset_token.user
            user.set_password(password)
            db.session.delete(reset_token)
            db.session.commit()
            flash('Tu contraseña ha sido actualizada!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Las contraseñas no coinciden.', 'danger')
    return render_template('reset_password.html', token=token)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Nombre de usuario o contraseña incorrectos.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        fullname = request.form['fullname']
        bio = request.form.get('bio')
        gender = request.form['gender']
        if gender == 'other':
            gender = request.form['other_gender']
        dob = request.form['dob']
        phone = request.form.get('phone')
        new_user = User(username=username, email=email, fullname=fullname, bio=bio, gender=gender, dob=dob, phone=phone)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Cuenta creada con éxito. Por favor, inicia sesión.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('home.html', posts=posts)

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    user = current_user
    fullname = user.fullname if user.fullname else ''
    bio = user.bio if user.bio else ''
    gender = user.gender if user.gender else ''
    dob = user.dob.strftime('%Y-%m-%d') if user.dob else ''
    phone = user.phone if user.phone else ''
    profile_picture = user.profile_picture if user.profile_picture else 'default.jpg'
    return render_template('profile.html', 
                           user=user,
                           fullname=fullname, 
                           bio=bio, 
                           gender=gender, 
                           dob=dob, 
                           phone=phone, 
                           profile_picture=profile_picture)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.fullname = request.form.get('fullname') or current_user.fullname
        current_user.bio = request.form.get('bio') or current_user.bio
        current_user.gender = request.form.get('gender') or current_user.gender
        dob = request.form.get('dob')
        if dob:
            current_user.dob = datetime.strptime(dob, '%Y-%m-%d')
        current_user.phone = request.form.get('phone') or current_user.phone
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.profile_picture = filename
        db.session.commit()
        flash('Perfil actualizado con éxito')
        return redirect(url_for('profile'))
    return render_template('edit_profile.html', user=current_user)

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        content = request.form['content']
        image_file = request.files.get('image')
        image_filename = None
        if image_file and allowed_file(image_file.filename):
            image_filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        post = Post(user_id=current_user.id, content=content, image=image_filename)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('create_post.html')

@app.route('/post/<int:post_id>', methods=['GET'])
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('view_post.html', post=post)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        post.content = request.form['content']
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form['content']
    comment = Comment(post_id=post_id, user_id=current_user.id, content=content)
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/follow/<int:user_id>', methods=['GET'])
@login_required
def follow(user_id):
    target_user = User.query.get_or_404(user_id)
    current_user.follow(target_user)
    return redirect(url_for('profile', user_id=user_id))

@app.route('/unfollow/<int:user_id>', methods=['GET'])
@login_required
def unfollow(user_id):
    user_to_unfollow = User.query.get_or_404(user_id)
    current_user.unfollow(user_to_unfollow)
    return redirect(url_for('profile', user_id=user_id))

@app.route('/send_message/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def send_message(receiver_id):
    if request.method == 'POST':
        content = request.form['content']
        message = MessageModel(sender_id=current_user.id, receiver_id=receiver_id, content=content)
        db.session.add(message)
        db.session.commit()
        return redirect(url_for('view_messages', user_id=receiver_id))
    messages = MessageModel.query.filter(
        ((MessageModel.sender_id == current_user.id) & (MessageModel.receiver_id == receiver_id)) |
        ((MessageModel.sender_id == receiver_id) & (MessageModel.receiver_id == current_user.id))
    ).order_by(MessageModel.created_at.asc()).all()
    return render_template('send_message.html', current_user=current_user, receiver_id=receiver_id, messages=messages)

@app.route('/view_messages/<int:user_id>', methods=['GET'])
@login_required
def view_messages(user_id):
    user = User.query.get_or_404(user_id)
    messages = MessageModel.query.filter(
        ((MessageModel.sender_id == current_user.id) & (MessageModel.receiver_id == user_id)) |
        ((MessageModel.sender_id == user_id) & (MessageModel.receiver_id == current_user.id))
    ).order_by(MessageModel.created_at.asc()).all()
    return render_template('view_messages.html', messages=messages, user=user, receiver_id=user_id)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        query = request.form['query']
        users = User.query.filter(User.username.ilike(f'%{query}%')).all()
        posts = Post.query.filter(Post.content.ilike(f'%{query}%')).all()
        return render_template('search_results.html', users=users, posts=posts, query=query, current_user=current_user)
    return render_template('search.html')

@app.route('/feed', methods=['GET'])
@login_required
def feed():
    posts = current_user.followed_posts().all()
    return render_template('feed.html', posts=posts)


from werkzeug.utils import secure_filename

@app.route('/like_post/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    if not like:
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(new_like)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo')
        return redirect(url_for('edit_profile'))
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        current_user.profile_picture = filename
        db.session.commit()
        flash('Imagen de perfil actualizada')
    return redirect(url_for('edit_profile'))

@app.route('/some_route')
def some_function():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('some_template.html', posts=posts)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

