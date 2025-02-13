# app.py
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github
import logging
from model import db, User, Course, reset_database, Message
import json
import httpx
import asyncio

app = Flask(__name__)
app.secret_key = 'your_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

with app.app_context():
    reset_database()

google_bp = make_google_blueprint(client_id='YOUR_GOOGLE_CLIENT_ID', client_secret='YOUR_GOOGLE_CLIENT_SECRET', redirect_to='google_login')
app.register_blueprint(google_bp, url_prefix='/google_login')

github_bp = make_github_blueprint(client_id='YOUR_GITHUB_CLIENT_ID', client_secret='YOUR_GITHUB_CLIENT_SECRET', redirect_to='github_login')
app.register_blueprint(github_bp, url_prefix='/github_login')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    all_courses = Course.query.all() 
    logging.info(f'Total courses retrieved: {len(all_courses)}')
    
    unique_course_types = set(course.course_type for course in all_courses)
    
    courses_by_type = {}
    for course in all_courses:
        if course.course_type not in courses_by_type:
            courses_by_type[course.course_type] = []
        courses_by_type[course.course_type].append(course)
    
    username = current_user.username if current_user.is_authenticated else 'زائر'
    
    return render_template('user/index.html', username=username, courses_by_type=courses_by_type, unique_course_types=unique_course_types)

@app.route('/user/about')
def about():
    return render_template('user/about.html')

@app.route('/user/contantgroup', methods=['GET', 'POST'])
@login_required
def contantgroup():
    if request.method == 'POST':
        message_content = request.form.get('message')
        user_id = current_user.id
        new_message = Message(user_id=user_id, content=message_content)

        db.session.add(new_message)
        db.session.commit()

      
        return redirect(url_for('contantgroup'))

    messages = Message.query.all() 
    return render_template('user/contantgroup.html', messages=messages)

@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.user_id == current_user.id:
        db.session.delete(message)
        db.session.commit()
    return redirect(url_for('contantgroup'))

@app.route('/admin/index')
def admin():
    return render_template('admin/index.html')

@app.route('/user/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            logging.info(f'User {username} logged in successfully.')
            return redirect(url_for('home'))
        else:
            logging.warning(f'Failed login attempt for username: {username}')
            flash('اسم المستخدم أو كلمة المرور غير صحيحة')
            return redirect(url_for('login'))

    return render_template('user/login.html')

@app.route('/user/login_pass', methods=['GET', 'POST'])
def login_pass():
    return render_template('user/login_pass.html')

@app.route('/user/profile')
@login_required 
def profile():
    user_data = {
        'username': current_user.username,
        'email': current_user.email,
        'join_date': current_user.created_at, 
        'likes_count': current_user.likes_count,
        'shares_count': current_user.shares_count,
    }
    
    return render_template('user/profileuserr.html', user_data=user_data)

@app.route('/user/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            message = 'كلمة المرور وتأكيد كلمة المرور غير متطابقتين'
            return render_template('user/register.html', message=message)

        if User.query.filter_by(username=username).first():
            message = 'اسم المستخدم موجود بالفعل'
            return render_template('user/register.html', message=message)

        if User.query.filter_by(email=email).first():
            message = 'البريد الإلكتروني موجود بالفعل'
            return render_template('user/register.html', message=message)

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()

        logging.info(f'New user registered: {username}')
        return redirect(url_for('login'))

    return render_template('user/register.html', message=message)

@app.route('/admin/add_course', methods=['GET', 'POST'])
def add_course():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        image_url = request.form['image_url']
        course_type = request.form['course_type']

        new_course = Course(title=title, description=description, image_url=image_url, course_type=course_type)
        db.session.add(new_course)  
        db.session.commit()  

        logging.info(f'New course added: {title}')
        return redirect(url_for('admin_courses')) 
    
    return render_template('admin/add_course.html')

@app.route('/admin/users')
def users():
    all_users = User.query.all()
    current_user_count = User.query.count()
    daily_counts = {}
    monthly_counts = {}
    yearly_counts = {}

    for user in all_users:
        date = user.created_at.date()
        month = user.created_at.strftime("%Y-%m")
        year = user.created_at.year

        if date in daily_counts:
            daily_counts[date] += 1
        else:
            daily_counts[date] = 1

        if month in monthly_counts:
            monthly_counts[month] += 1
        else:
            monthly_counts[month] = 1

        if year in yearly_counts:
            yearly_counts[year] += 1
        else:
            yearly_counts[year] = 1

    daily_labels = list(daily_counts.keys())
    daily_values = list(daily_counts.values())

    monthly_labels = list(monthly_counts.keys())
    monthly_values = list(monthly_counts.values())

    yearly_labels = list(yearly_counts.keys())
    yearly_values = list(yearly_counts.values())

    return render_template('admin/users.html', users=all_users, current_user_count=current_user_count, 
                           daily_labels=daily_labels, daily_values=daily_values,
                           monthly_labels=monthly_labels, monthly_values=monthly_values,
                           yearly_labels=yearly_labels, yearly_values=yearly_values)

@app.route('/admin/users/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        logging.info(f'User {user.username} deleted successfully.')
        return redirect(url_for('users')) 
    else:
        logging.warning(f'Tried to delete a non-existing user with ID: {user_id}.')
        return redirect(url_for('users')) 

@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get('/plus/v1/people/me')
    assert resp.ok, resp.text
    return f'Welcome, {resp.json()["displayName"]}!'

@app.route('/github_login')
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))
    resp = github.get('/user')
    assert resp.ok, resp.text
    return f'Welcome, {resp.json()["login"]}!'

@app.route('/user/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    logging.info(f'User {username} logged out successfully.')
    return redirect(url_for('home'))

@app.route('/admin/admin_courses')
def admin_courses():
    all_courses = Course.query.all()
    return render_template('admin/admin_courses.html', courses=all_courses)

@app.route('/user/courses')
@login_required
def user_courses():
    all_courses = Course.query.all()
    logging.info(f'Total courses retrieved: {len(all_courses)}') 
    courses_by_type = {}

    for course in all_courses:
        if course.course_type not in courses_by_type:
            courses_by_type[course.course_type] = []
        courses_by_type[course.course_type].append(course)

    return render_template('user/courses.html', courses_by_type=courses_by_type)

@app.route('/like/<int:course_id>', methods=['POST'])
def like_course(course_id):
    course = Course.query.get(course_id)
    if course:
        course.likes += 1 
        current_user.likes_count += 1 
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False), 404

@app.route('/admin/admin_courses/<int:course_id>', methods=['POST'])
def delete_course(course_id):
    course = Course.query.get(course_id)
    if course:
        db.session.delete(course)
        db.session.commit()
        logging.info(f'Course {course.title} deleted successfully.')
        return redirect(url_for('admin_courses'))
    else:
        logging.warning(f'Tried to delete a non-existing course with ID: {course_id}.')
        return redirect(url_for('admin_courses'))


API_KEY = 'AIzaSyCZVuenJfMv6I7uOdSm7zRRfmk2ety-GF0' 
API_URL = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={API_KEY}'

async def get_ai_response(user_input):
    data = {
        "contents": [
            {
                "parts": [
                    {
                        "text": user_input
                    }
                ]
            }
        ]
    }
    headers = {'Content-Type': 'application/json'}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(API_URL, headers=headers, data=json.dumps(data))
            response.raise_for_status()
            response_data = response.json()
            if 'candidates' in response_data and len(response_data['candidates']) > 0:
                content = response_data['candidates'][0].get('content', {})
                parts = content.get('parts', [])
                return parts[0].get('text', "لم أتمكن من الحصول على نص الرد.")
            else:
                return "لم أتمكن من الحصول على رد من الخادم."
    except Exception as e:
        logging.error(f"خطأ: {e}")
        return "حدث خطأ غير متوقع."

if __name__ == '__main__':
    app.run(debug=True)