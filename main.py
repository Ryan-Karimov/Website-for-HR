from datetime import timedelta, datetime
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from sqlalchemy import create_engine, text, exc
from passlib.hash import bcrypt
from forms import *
from config import *
import smtplib, uuid
from flask_mail import Mail
from flask_socketio import SocketIO, emit
from db import *


# Flask-ilovaning nusxasini yaratamiz
app = Flask(__name__)

# Ilova uchun maxfiy kodni o'rnatamiz
app.config['SECRET_KEY'] = secret_key

# JWT (JSON Web Tokens) uchun maxfiy kodni o'rnatamiz
app.config['JWT_SECRET_KEY'] = secret_key

# SMTP (Simple Mail Transfer Protocol) orqali xat yuborish uchun sozlamalar
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = from_email
app.config['MAIL_DEFAULT_SENDER'] = from_email
app.config['MAIL_PASSWORD'] = email_pass

# JWT-kirish tokenining ishlash muddatini belgilaymiz
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=10)

# Flask kengaytmalarini ishga tushiramiz
jwt = JWTManager(app)  # JWT tokenlarini boshqarish
mail = Mail(app)        # Pochta orqali xabar yuborish
socketio = SocketIO(app=app, engineio_logger=True, cors_allowed_origins="*", logger=True)  # WebSocket va Socket.IO
CORS(app, resources={r"/socket.io/*": {"origins": "*"}})  # WebSocket uchun CORS ga ruxsat beramiz
engine = create_engine(database)  # Ma'lumotlar bazasiga ulanishni yaratamiz
conn = engine.connect()  # Ma'lumotlar bazasi bilan aloqa o'rnatamiz


@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Methods'] = methods
    response.headers['Access-Control-Allow-Headers'] = headers
    return response




@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        new_user = request.json
        try:
            existing_user = conn.execute(text("SELECT username FROM user_data WHERE username = :username"), {'username': new_user['username']}).fetchone()
            if existing_user:
                error = "Bu foydalanuvchi nomi band. Iltimos, boshqa foydalanuvchi nomini tanlang."
                return error, 400
            
            existing_gmail = conn.execute(text("SELECT email FROM user_data WHERE email = :email"), {'email': new_user['email']}).fetchone()
            if existing_gmail:
                error = "Bu email band. Iltimos, boshqa elektron pochtadan foydalaning."
                return error, 400
            password = bcrypt.hash(new_user['password'])
            user = Users(username=new_user['username'],
                    email=new_user['email'],
                    password=new_user['password'])
            confirm_code = str(uuid.uuid4().int)[:6]
            stmt = text("INSERT INTO user_data (username, email, password, accepted, role, phone_number, approved, code) VALUES (:username, :email, :password, :accepted, :role, :phone_number, :approved, :code)")
            params = {'username': new_user['username'], 'email': new_user['email'], 'password': password, 'accepted': False, 'role': 'user', 'phone_number': [], 'approved': False, 'code': str(confirm_code)}
            a = conn.execute(stmt, params)
            conn.commit()
            message = f"Tasdiqlash kodi: {confirm_code}"
            send_email(sender=from_email, recipients=new_user['email'], message=message)
        except ValueError as e:
            error_message = str(e)
            return jsonify({'error': error_message}), 400
        except smtplib.SMTPAuthenticationError as e:
            return str(e)
    return jsonify({'message': 'Elektron pochta manzilingizga tasdiqlash kodi yuborildi!',
                    'username': new_user['username']}), 200

@app.route('/register_gmail', methods=['POST'])
def register_gmail():
    if request.method == 'POST':
        try:
            new_user = request.json
            # Проверка, существует ли пользователь с таким именем
            existing_user = conn.execute(text("SELECT username FROM user_data WHERE username = :username"), {'username': new_user['username']}).fetchone()
            if existing_user:
                error = "Bu foydalanuvchi nomi band. Iltimos, boshqa foydalanuvchi nomini tanlang."
                return error, 400
            
            # Хеширование пароля
            password = bcrypt.hash(new_user['id'])
            stmt = text("INSERT INTO user_data (username, email, password, accepted, role, phone_number, approved) VALUES (:username, :email, :password, :accepted, :role, :phone_number, :approved)")
            params = {'username': new_user['username'], 'email': new_user['email'], 'password': password, 'accepted': False, 'role': 'user', 'phone_number': [], 'approved': True}
            a = conn.execute(stmt, params)
            conn.commit()
        except exc.IntegrityError as e:
            conn.rollback()
            error_dict = e.__dict__['orig']
            if 'уникальности "email"' in str(error_dict):
                error = 'Bu email band. Iltimos, boshqa elektron pochtadan foydalaning.'
                return error, 400
    return "Ro'yxatdan o'tish muvaffaqiyatli yakunlandi"

attempt = 3

@app.route('/register/code', methods=['POST'])
def register_code():
    if request.method == 'POST':
        try:
            data = request.json
            print(data)
            data_db = text("SELECT * FROM user_data WHERE username=:username")
            result = conn.execute(data_db, {'username': data['username']})
            user = result.fetchone()
            if user:
                global attempt
                if attempt > 0:
                    if data['code'] == user.code:
                        stmt = text("UPDATE user_data SET approved=:approved, code=:code WHERE username=:username")
                        params = {'approved': True, 'code': None, 'username': data['username']}
                        conn.execute(stmt, params)
                        conn.commit()
                        attempt = 3
                        return 'Sizning e-mailingiz tasdiqlandi', 200 
                    elif data['code'] != user.code:
                        attempt -= 1
                    return f"Parol mos kelmadi. Sizda {attempt} ta urinish qoldi", 202
                elif attempt == 0:
                    stmt = text("DELETE FROM user_data WHERE username=:username")
                    params = {'username': data['username']}
                    conn.execute(stmt, params)
                    conn.commit()
                    attempt = 3
                    return 'Sizda urinishlar qolmadi. Iltimos, qayta registratsiya qiling', 400
        except exc.StatementError as e:
            conn.rollback()
            return str(e), 400
    return 'Foydalanuvchi topilmadi', 400
        


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        data = request.get_json(force=True)
        username = data.get('username')
        password = data.get('password')

        try:
            user_data = text("SELECT username, password, id, role, accepted FROM user_data WHERE username=:username")
            result = conn.execute(user_data, {'username': username})
            user = result.fetchone()
            if user is None:
                return jsonify({'message': 'Bunday foydalanuvchi nomi mavjud emas'}), 400
            is_valid = bcrypt.verify(password, user[1])
            if is_valid:
                if user[4] == True:
                    add_claims = check_token(user)
                    access_token = create_access_token(identity=add_claims)
                    return jsonify({
                        "message": "Login muvaffaqiyatli yakunlandi",
                        "id": user[2],
                        "role": user[3],
                        "accepted": user[4],
                        "token": access_token
                    }), 200
                return jsonify({
                            "message": 'Foydalanuvchi hali tasdiqlanmagan',
                            "accepted": user[4]
                }), 400
            else:
                return jsonify({'message': 'Foydalanuvchi nomi yoki parol noto\'g\'ri'}), 400
        except exc.StatementError as e:
            conn.rollback()
            return str(e), 400    


@app.route('/')
@jwt_required()
def hello_world():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        with engine.connect() as conn:
            query2 = text("SELECT COUNT(username) FROM user_data")
            result2 = conn.execute(query2)
            result_string = f"Ma'lumotlar omborida {result2.scalar()} ta foydalanuvchi mavjud."
            return result_string, 200


@app.route('/user/<id>', methods=['PATCH', 'GET', 'DELETE'])
@jwt_required()
def user_id(id: int):
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'GET':
            try:
                user = conn.execute(text(f"SELECT * FROM user_data WHERE id={id}")).fetchone()
                photo = change_aspect_ratio_and_encode(user.profile_photo, 16/9)
                skill = user.skills
                skills_list = skills(skill)
                resume = encode_to_base64(user.resume)
                user_data = {
                    "message": "Avtorizatsiya muvaffaqiyatli amalga oshirildi",
                    "fullname": user.fullname,
                    "username": user.username,
                    "email": user.email,
                    "date_birth": user.date_birth,
                    "phone_number": number(user.phone_number),
                    "address": user.address,
                    "profile_photo": photo,
                    "major": user.major,
                    "experience": user.experience,
                    "skills": skills_list,
                    "resume": resume
                }
                return jsonify(user_data), 200
            except exc.StatementError as e:
                conn.rollback()
                return str(e), 400

    if request.method == 'PATCH':
        data = request.json
        try:
            if 'accepted' in data:
                a = conn.execute(text(f"UPDATE user_data SET accepted='{data['accepted']}' WHERE id='{id}' and approved='True'"))
                conn.commit()
                return 'Foydalanuvchi qabul qilindi', 200
            if 'role' in data:
                a = conn.execute(text(f"UPDATE user_data SET role='{data['role']}' WHERE id='{id}'"))
                conn.commit()
                return 'Foydalanuvchining roli o\'zgardi', 200
        except exc.StatementError as e:
            conn.rollback()
            return str(e), 400    
    if request.method == 'DELETE':
        try:
            # Сначала удаляем связанные записи из таблицы messages
            conn.execute(text(f"DELETE FROM messages WHERE sender_id = {id}"))
            conn.execute(text(f"DELETE FROM messages WHERE receiver_id = {id}"))

            # Теперь можно удалить запись из таблицы user_data
            conn.execute(text(f"DELETE FROM user_data WHERE id = {id}"))
            conn.commit()
            return "Foydalanuvchi o\'chirildi", 200
        except exc.StatementError as e:
            conn.rollback()
            return str(e), 400



@app.route('/update_profile/<id>', methods=['PATCH'])
@jwt_required()
def update(id: int):
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'PATCH':
            new_data = request.json
            username = new_data['username']
            try:
                updated_data = {}
                for key, value in new_data.items():
                    if key == 'password': 
                        value = hash_pass(value)
                    elif key == 'profile_photo':
                        value = save_base64_image(value)
                    elif key == 'skills':
                        value1 = [skill.strip() for skill in value]
                        # value = re.sub(r'(\w+)', r"'\1'", ','.join(value1))
                    elif key == 'resume':
                        value = save_base64_resume(value, username)
                    updated_data[key] = value
                    
                # for key, value in updated_data.items():
                    statement = text(f"UPDATE user_data SET {key} = :value WHERE id = :id")
                    parameters = {"value": value, "id": id}
                    conn.execute(statement, parameters)
                    conn.commit()
            except exc.StatementError as e:
                conn.rollback()
                if 'уникальности "username"' in str(e):
                    return "Bunday username mavjud", 400
                if 'уникальности "email"' in str(e):
                    return 'Bunday email mavjud', 400
                return str(error_dict), 400
            except exc.ResourceClosedError as e:
                conn.rollback()
                error_dict = e.__dict__
                return error_dict
            return 'Profil muvaffaqiyatli yangilandi', 200


@app.route('/users', methods=['GET', 'PATCH'])
@jwt_required()
def users():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'GET':
            try:
                result = conn.execute(text("SELECT * FROM user_data"))
                users = [dict(zip(result.keys(), row)) for row in result.fetchall()]
                all_users = []
                for user in users:
                    for key, value in user.items():
                        if isinstance(value, memoryview):
                            user[key] = value.tobytes().decode('utf-8')
                        if key == 'profile_photo' and value != None:
                            value = change_aspect_ratio_and_encode(value, 16/9)
                            user[key] = value
                    all_users.append(user)
                return jsonify(all_users), 200
            except Exception as e:
                return str(e), 400


@app.route('/admin', methods=['PATCH', 'DELETE', 'GET'])
@jwt_required()
def admin():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'PATCH':
            try:
                id = request.json
                a = conn.execute(text(f"UPDATE user_data SET accepted=true WHERE id='{id}'"))
                conn.commit()
            except exc.StatementError as e:
                conn.rollback()
                return str(e), 400
        

@app.route('/logout/<id>', methods=['POST', 'GET'])
@jwt_required()
def logout(id: int):
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'GET':
            return "Tizimdan muvaffaqiyatli chiqildi", 200
    


@app.route('/search', methods=['POST', 'GET'])
@jwt_required()
def search():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'POST':
            resumes = []
            data = request.json
            try:
                if not data:
                    search_query = "SELECT id, username, major, experience, skills, email, phone_number, resume FROM user_data"
                    search_results = conn.execute(text(search_query)).fetchall()
                    result_list = [{'id': row[0], 'username': row[1], 'major': row[2], 'experience': row[3], 'skills': [skill.replace('"', '') for skill in row[4].split(',')] if row[4] is not None else [],
                                    'email': row[5], 'phone_number': [phone_number for phone_number in row[6].split(',')] if row[6] is not None else [], 'resume': row[7]} for row in search_results]
                    return jsonify({'results': result_list}), 200
                if any(key in data for key in ['skills', 'major', 'experience']):
                    conditions = []
                    params = {}

                    if 'skills' in data:
                        skills = data['skills']
                        skill_conditions = " OR ".join(["skills ILIKE :skill_" + str(idx) for idx, _ in enumerate(skills)])
                        conditions.append("(" + skill_conditions + ")")
                        for idx, skill in enumerate(skills):
                            params["skill_" + str(idx)] = f"%{skill}%"

                    if 'major' in data:
                        conditions.append("major = :major")
                        params['major'] = data['major']
                    if 'experience' in data:
                        conditions.append("experience = :experience")
                        params['experience'] = data['experience']

                    search_query = "SELECT DISTINCT id, username, major, experience, skills, email, phone_number, resume FROM user_data"
                    if conditions:
                        search_query += " WHERE " + " AND ".join(conditions)

                    search_results = conn.execute(text(search_query), params).fetchall()
                    result_list = [{'id': row[0], 'username': row[1], 'major': row[2], 'experience': row[3], 'skills': [skill.replace('"', '') for skill in row[4].split(',')] if row[4] is not None else [],
                                    'email': row[5], 'phone_number': [phone_number for phone_number in row[6].split(',')] if row[6] is not None else [], 'resume': row[7]} for row in search_results]
                    return jsonify({'results': result_list}), 200
            except exc.StatementError as e:
                conn.rollback()
                return str(e), 400
        return "Kalit so'z xato"


@app.route('/search/<id>', methods=['POST', 'GET', 'PATCH'])
@jwt_required()
def search_id(id: int):
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'GET':
            try:
                statement = text(f"SELECT * FROM user_data WHERE id = :id")
                parameters = {"id": id}
                user = conn.execute(statement, parameters).fetchone()
                if user is None:
                    return 'Bunday foydalanuvchi mavjud emas', 400
                else:
                    photo = change_aspect_ratio_and_encode(user.profile_photo, 16/9)
                    skill = skills(user.skills)
                    phone_number = number(user.phone_number)
                    user_info = {
                    "message": "Succesfull",
                    "fullname": user.fullname,
                    "username": user.username,
                    "email": user.email,
                    "date_birth": user.date_birth,
                    "phone_number": number(user.phone_number),
                    "address": user.address,
                    "profile_photo": photo,
                    "major": user.major,
                    "experience": user.experience,
                    "skills": skill,
                    "resume": encode_to_base64(user.resume)
                }
                return jsonify(user_info), 200
            except exc.StatementError as e:
                conn.rollback()
                return str(e), 400

@app.route('/stat', methods=['POST', 'GET'])
@jwt_required()
def stat():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'GET':
            try:
                date_data = {}
                query1 = text("SELECT DATE_TRUNC('day', created_on) AS registration_date, COUNT(*) AS user_count FROM user_data GROUP BY registration_date;")
                data1 = conn.execute(query1).fetchall()
                
                query2 = text("SELECT major, COUNT(*) AS developer_count FROM user_data GROUP BY major;")
                data2 = conn.execute(query2).fetchall()

                query3 = text("SELECT experience, major, COUNT(*) AS experience_count FROM user_data GROUP BY experience, major;")
                data3 = conn.execute(query3).fetchall()

                result = []

                for row in data1:
                    result.append({"date": str(row[0]), "count": row[1], "type": "user_count"})

                for row in data2:
                    result.append({"major": str(row[0]), "count": row[1], "type": "developer_count"})

                exp_dict = []
                    
                for row in data3:
                    exp_dict.append({"experience": str(row[0]), "major": str(row[1]), "count": row[2], "type": "experience_count"})

                result.append({"experience": exp_dict})

                return result, 200
            except exc.StatementError as e:
                conn.rollback()
                return str(e), 400


@app.route('/chat/<id>', methods=['GET', 'POST'])
@jwt_required()
def chat(id: int):
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'POST':
            data = request.json
            try:
                if 'username' in data:
                    username = data['username']
                    query = text(f"SELECT profile_photo, id FROM user_data WHERE username='{username}'")
                    user_data = conn.execute(query).fetchone()
                    if user_data:
                        profile_photo = change_aspect_ratio_and_encode(user_data.profile_photo, 16/9)
                        return jsonify({"username": username, "profile_photo": profile_photo, "id": user_data.id}), 200
                    else:
                        return jsonify({"error": "User not found"}), 400
                else:
                    return jsonify({"error": "Invalid data"}), 400
            except exc.StatementError as e:
                conn.rollback()
                return str(e), 400
        if request.method == 'GET':
            query1 = text(f"SELECT profile_photo, id, username FROM user_data WHERE id != :user_id")
            params = {'user_id': id}
            result = conn.execute(query1, params).fetchall()

            messages = []
            for row in result:
                profile_photo = change_aspect_ratio_and_encode(row[0], 16/9)
                message = {
                    'profile_photo': profile_photo,
                    'id': row[1],
                    'username': row[2]
                }
                messages.append(message)
            chat_users_sorted = sorted(messages, key=lambda x: x['id'])
            return jsonify(chat_users_sorted), 200
        return "OK"

@app.route('/chat/room', methods=['GET'])
@jwt_required()
def chatroom():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401  # Возвращаем статус-код 401 и сообщение 'Invalid data'
    else:
        if request.method == 'GET':
            user_1 = request.args.get('user_id1')
            user_2 = request.args.get('user_id2')
            try:
                query = text("""
                    SELECT id, sender_id, receiver_id, message_text, timestamp, is_read
                    FROM messages
                    WHERE (sender_id = :user_id1 AND receiver_id = :user_id2)
                    OR (sender_id = :user_id2 AND receiver_id = :user_id1)
                    ORDER BY timestamp
                """)
                params = {'user_id1': user_1, 'user_id2': user_2}
                result = conn.execute(query, params).fetchall()

                # Формируем список сообщений
                messages = []
                for row in result:
                    timestamp = row[4]
                    formatted_timestamp = timestamp.strftime("(%Y-%m-%d) %H:%M")
                    message = {
                        'msg_id': row[0],
                        'sender_id': row[1],
                        'receiver_id': row[2],
                        'message': row[3],
                        'timestamp': formatted_timestamp,
                        'is_read': row[5]
                    }
                    messages.append(message)
                return jsonify(messages), 200
            except exc.StatementError as e:
                    conn.rollback()
                    return str(e), 400
        

connected_users = {}  # Используйте словарь для хранения соответствия user_id и session_id

@socketio.on('hello')
def handle_connect(data):
    print('CONNECTED')
    user_id = data['id']
    session_id = request.sid
    if user_id not in connected_users.keys():
        # Записываем session_id в словарь
        connected_users[user_id] = session_id
    else:
        return "Such a user exists", 400
    print(connected_users)


@socketio.on('new_message')
def send_message(data):
    sender_id = data['sender_id']
    receiver_id = data['receiver_id']
    message = data['message']
    socket_id = connected_users.get(sender_id)
    query = text("""
        UPDATE messages
        SET is_read = true
        WHERE sender_id = :sender_id AND receiver_id = :receiver_id;
    """)
    params = {'sender_id': receiver_id, 'receiver_id': sender_id}
    conn.execute(query, params)
    conn.commit()

    # Сохраняем сообщение в базе данных
    query1 = text("""
        INSERT INTO messages (sender_id, receiver_id, message_text, is_read)
        VALUES (:sender_id, :receiver_id, :message_text, :is_read)
    """)
    params1 = {'sender_id': sender_id, 'receiver_id': receiver_id, 'message_text': message, 'is_read': False}
    conn.execute(query1, params1)
    conn.commit()

    # Извлекаем сообщения из базы данных для отображения в чате
    query2 = text("""
        SELECT id, sender_id, receiver_id, message_text, timestamp, is_read
        FROM messages
        WHERE (sender_id = :user_id1 AND receiver_id = :user_id2)
        OR (sender_id = :user_id2 AND receiver_id = :user_id1)
        ORDER BY timestamp
    """)
    params2 = {'user_id1': sender_id, 'user_id2': receiver_id}
    result = conn.execute(query2, params2).fetchall()

    messages = []
    for row in result:
        timestamp = row[4]
        formatted_timestamp = timestamp.strftime("(%Y-%m-%d) %H:%M")
        message = {
            'msg_id': row[0],
            'message': row[3],
            'sender_id': row[1],
            'receiver_id': row[2],
            'timestamp': formatted_timestamp,
            'is_read': row[5]
        }
        messages.append(message)
    socketio.emit('new_message', messages, room=socket_id)


@socketio.on('message')
def chat_msg(data):
    print("MESSAGE")
    sender_id = data['sender_id']
    receiver_id = data['receiver_id']
    msg_id = data['msg_id']

    try:
        socket_id = connected_users.get(sender_id)
        query = text("""
            UPDATE messages
            SET is_read = TRUE
            WHERE sender_id = :sender_id AND receiver_id = :receiver_id AND id = :msg_id;
        """)
        params = {'sender_id': sender_id, 'receiver_id': receiver_id, 'msg_id': msg_id}
        conn.execute(query, params)
        conn.commit()

        query = text("""
            SELECT id, sender_id, receiver_id, message_text, timestamp, is_read
            FROM messages
            WHERE (sender_id = :user_id1 AND receiver_id = :user_id2)
            OR (sender_id = :user_id2 AND receiver_id = :user_id1)
            ORDER BY timestamp
        """)
        params = {'user_id1': sender_id, 'user_id2': receiver_id}
        result = conn.execute(query, params).fetchall()

        messages = []
        for row in result:
            timestamp = row[4]
            formatted_timestamp = timestamp.strftime("(%Y-%m-%d) %H:%M")
            message = {
                'msg_id': row[0],
                'message': row[3],
                'sender_id': row[1],
                'receiver_id': row[2],
                'timestamp': formatted_timestamp,
                'is_read': row[5]
            }
            messages.append(message)
        socketio.emit('see_message', messages, room=socket_id)
    
    except exc as e:
        conn.rollback()
        return str(e)
    return "OK"


@socketio.on('count')
def chat_count(data):
    try:
        chat_users = []
        user_id_to_exclude = data['id']
        socket_id = connected_users.get(user_id_to_exclude)
        if socket_id:
            query = text("""
                SELECT u.username, u.profile_photo, u.id, COUNT(m.id) as unread_msg
                FROM user_data u
                LEFT JOIN messages m ON u.id = m.sender_id AND m.receiver_id = :user_id AND m.is_read = false
                WHERE u.id != :user_id_to_exclude
                GROUP BY u.username, u.profile_photo, u.id;
            """)
            params = {'user_id': user_id_to_exclude, 'user_id_to_exclude': user_id_to_exclude}
            result = conn.execute(query, params).fetchall()

            for row in result:
                username, profile_photo, user_id, unread_msg = row
                photo = change_aspect_ratio_and_encode(profile_photo, 16/9)
                user_data = {
                    # "username": str(username),
                    # "profile_photo": photo,
                    "id": user_id,
                    "unread_msg": unread_msg
                }
                chat_users.append(user_data)
            # После цикла, который заполняет chat_users
            chat_users_sorted = sorted(chat_users, key=lambda x: x['id'])
            socketio.emit('count', chat_users_sorted, room=socket_id)
            # return jsonify(chat_users)

    except exc.StatementError as e:
        conn.rollback()
        return str(e), 400

@socketio.on('disconnect')
def handle_disconnect():
    print('DISCONNECTED')
    socket_id = request.sid
    for user_id, sid in list(connected_users.items()):
        if sid == socket_id:
            del connected_users[user_id]
            print("USER DELETED")
            print(connected_users)
            break

if __name__ == '__main__':
    socketio.run(app, debug=True, port=1000, host='0.0.0.0')