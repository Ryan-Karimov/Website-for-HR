from datetime import timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from sqlalchemy import create_engine, text, exc
from passlib.hash import bcrypt
from forms import *
from config import *
import smtplib, uuid
from flask_mail import Mail
from flask_socketio import SocketIO
import uuid


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




@app.route('/register', methods=['POST'])
def register():
    try:
        new_user = request.json

        # Xuddi shu ismli foydalanuvchi mavjudligini tekshiramiz
        existing_user = conn.execute(text("SELECT username FROM user_data WHERE username = :username"), {'username': new_user['username']}).fetchone()
        if existing_user:
            error = "Bu foydalanuvchi nomi band. Iltimos, boshqa foydalanuvchi nomini tanlang."
            return error, 400
        
        # Xuddi shu elektron pochtaga ega foydalanuvchi mavjudligini tekshiring
        existing_gmail = conn.execute(text("SELECT email FROM user_data WHERE email = :email"), {'email': new_user['email']}).fetchone()
        if existing_gmail:
            error = "Bu email band. Iltimos, boshqa elektron pochtadan foydalaning."
            return error, 400
        password = bcrypt.hash(new_user['password'])
        Users(
            username=new_user['username'],
            email=new_user['email'],
            password=new_user['password']
        )
        confirm_code = str(uuid.uuid4().int)[:6]
        statement = text("INSERT INTO user_data (username, email, password, accepted, role, phone_number, approved, code, skills) VALUES (:username, :email, :password, :accepted, :role, :phone_number, :approved, :code, :skills)")
        params = {'username': new_user['username'], 'email': new_user['email'], 'password': password, 'accepted': False, 'role': 'user', 'phone_number': [], 'approved': False, 'code': str(confirm_code), 'skills': []}
        conn.execute(statement, params)
        conn.commit()

        # Tasdiqlash kodini yuborish
        message = f"Tasdiqlash kodi: {confirm_code}"
        send_email(sender=from_email, recipients=new_user['email'], message=message)
        return jsonify({'message': 'Elektron pochta manzilingizga tasdiqlash kodi yuborildi!',
                        'username': new_user['username']}), 200
    except ValueError as e:
        error_message = str(e)
        return jsonify({'error': error_message}), 400
    except smtplib.SMTPAuthenticationError as e:
        return str(e)

@app.route('/register_gmail', methods=['POST'])
def register_gmail():
    try:
        new_user = request.json
        # Xuddi shu ismli foydalanuvchi mavjudligini tekshiramiz
        existing_user = conn.execute(text("SELECT username FROM user_data WHERE username = :username"), {'username': new_user['username']}).fetchone()
        if existing_user:
            error = "Bu foydalanuvchi nomi band. Iltimos, boshqa foydalanuvchi nomini tanlang."
            return error, 400
        
        # Xuddi shu elektron pochtaga ega foydalanuvchi mavjudligini tekshiring
        existing_gmail = conn.execute(text("SELECT email FROM user_data WHERE email = :email"), {'email': new_user['email']}).fetchone()
        if existing_gmail:
            error = "Bu email band. Iltimos, boshqa elektron pochtadan foydalaning."
            return error, 400
        
        # Parol xeshlash
        password = bcrypt.hash(new_user['id'])

        # Ma'lumotlar bazasiga foydalanuvchi ma'lumotlarini qo'shamiz
        statement = text("INSERT INTO user_data (username, email, password, accepted, role, phone_number, approved, skills) VALUES (:username, :email, :password, :accepted, :role, :phone_number, :approved, :skills)")
        params = {
            'username': new_user['username'],
            'email': new_user['email'],
            'password': password,
            'accepted': False,
            'role': 'user',
            'phone_number': [],
            'approved': True,
            'skills': []
        }
        conn.execute(statement, params)
        conn.commit()
        return "Ro'yxatdan o'tish muvaffaqiyatli yakunlandi"
    except smtplib.SMTPAuthenticationError as e:
        return str(e)

attempt = 3

@app.route('/register/code', methods=['POST'])
def register_code():
    try:
        data = request.json
        query = conn.execute(text("SELECT * FROM user_data WHERE username=:username"), {'username': data['username']})
        user = query.fetchone()
        if user:
            global attempt
            if attempt > 0:
                if data['code'] == user.code:
                    conn.execute(text("UPDATE user_data SET approved=:approved, code=:code WHERE username=:username"), {'approved': True, 'code': None, 'username': data['username']})
                    conn.commit()
                    attempt = 3
                    return 'Sizning e-mailingiz tasdiqlandi', 200 
                elif data['code'] != user.code:
                    attempt -= 1
                    if attempt == 0:
                        conn.execute(text("DELETE FROM user_data WHERE username=:username"), {'username': data['username']})
                        conn.commit()
                        attempt = 3
                        return 'Sizda urinishlar qolmadi. Iltimos, qayta registratsiya qiling', 400
                return f"Parol mos kelmadi. Sizda {attempt} ta urinish qoldi", 202
        return 'Foydalanuvchi topilmadi', 400
    except exc.StatementError as e:
        conn.rollback()
        return str(e), 400
        


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')

    try:
        query = conn.execute(text("SELECT username, password, id, role, accepted FROM user_data WHERE username=:username"), {'username': username})
        user = query.fetchone()
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
        return 'Invalid data', 401
    else:
        try:
            query = text("SELECT COUNT(username) FROM user_data")
            result = engine.execute(query)
            result_string = f"Ma'lumotlar omborida {result.scalar()} ta foydalanuvchi mavjud."
            return result_string, 200
        except exc.StatementError as e:
            engine.rollback()
            return str(e), 400


@app.route('/user/<id>', methods=['PATCH', 'GET', 'DELETE'])
@jwt_required()
def user_id(id: int):
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401
    else:
        if request.method == 'GET':
            try:
                user = conn.execute(text("SELECT * FROM user_data WHERE id=:id"), {'id': id}).fetchone()
                if user is None:
                    return 'User not found', 404
                photo = change_aspect_ratio_and_encode(user.profile_photo, 16/9)
                resume = encode_to_base64(user.resume)
                formatted_timestamp = user.created_on.strftime("%d %b %Y")
                degree_general = json.loads(user.degree_general) if user.degree_general else []
                print(user.skills)
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
                    "skills": json.loads(user.skills),
                    "resume": resume,
                    "joined": formatted_timestamp,
                    "degree_general": degree_general,
                    "about": user.about
                }
                return jsonify(user_data), 200
            except exc.StatementError as e:
                conn.rollback()
                return str(e), 400

    if request.method == 'PATCH':
        data = request.json
        try:
            if 'accepted' in data:
                conn.execute(text("UPDATE user_data SET accepted=:accepted WHERE id=:id AND approved='True'"), {'accepted': data['accepted'], 'id': id})
                conn.commit()
                return 'Foydalanuvchi qabul qilindi', 200
            if 'role' in data:
                conn.execute(text("UPDATE user_data SET role=:role WHERE id=:id"), {'role': data['role'], 'id': id})
                conn.commit()
                return "Foydalanuvchining roli o'zgardi", 200
        except exc.StatementError as e:
            conn.rollback()
            return str(e), 400
    if request.method == 'DELETE':
        try:
            # Сначала удалим сообщения, связанные с пользователем
            conn.execute(text("DELETE FROM messages WHERE sender_id = :user_id OR receiver_id = :user_id"), {'user_id': id})

            # Теперь удалим самого пользователя из таблицы user_data
            conn.execute(text("DELETE FROM user_data WHERE id = :user_id"), {'user_id': id})
            conn.commit()
            return "Foydalanuvchi o'chirildi", 200
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
        return 'Invalid data', 401
    else:
        if request.method == 'PATCH':
            new_data = request.json
            username = new_data['username']
            updated_data = {}
            try:
                for key, value in new_data.items():
                    if key == 'password': 
                        value = hash_pass(value)
                    elif key == 'profile_photo':
                        value = save_base64_image(value)
                    elif key == 'skills':
                        value = json.dumps(value)
                        print(value)
                    elif key == 'resume':
                        value = save_base64_resume(value, username)
                    elif key == 'degree_general':
                        value = json.dumps(value)
                    updated_data[key] = value
                print(updated_data)
                statement = text(f"UPDATE user_data SET {', '.join([f'{key} = :{key}' for key in updated_data.keys()])} WHERE id = :id")
                parameters = {**updated_data, "id": id}
                conn.execute(statement, parameters)
                conn.commit()
            except exc.StatementError as e:
                conn.rollback()
                if 'уникальности "username"' in str(e):
                    return "Bunday username mavjud", 400
                elif 'уникальности "email"' in str(e):
                    return 'Bunday email mavjud', 400
                return str(e), 400
            except exc.ResourceClosedError as e:
                conn.rollback()
                return str(e), 400
            return 'Profil muvaffaqiyatli yangilandi', 200


@app.route('/users', methods=['GET'])
@jwt_required()
def users():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401
    else:
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


@app.route('/admin', methods=['PATCH'])
@jwt_required()
def admin():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401
    else:
        try:
            data = request.json
            id = data.get('id')
            if id is None:
                return 'Invalid data', 400
            
            conn.execute(text("UPDATE user_data SET accepted=true WHERE id=:user_id"), {'user_id': id})
            conn.commit()
            return "Foydalanuvchi qabul qilindi", 200
        except exc.StatementError as e:
            conn.rollback()
            return str(e), 400
        

@app.route('/logout/<id>', methods=['GET'])
@jwt_required()
def logout(id: int):
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401
    else:
        return "Tizimdan muvaffaqiyatli chiqildi", 200
    


@app.route('/search', methods=['POST'])
@jwt_required()
def search():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401
    else:
        resumes = []
        data = request.json
        print(data)
        try:
            if not data:
                search_query_user_data = "SELECT id, username, major, experience, skills, email, phone_number, resume FROM user_data WHERE accepted = :boolean"
                search_results_user_data = conn.execute(text(search_query_user_data), {'boolean': True}).fetchall()
                result_list_user_data = [{
                    'id': row[0],
                    'username': row[1],
                    'major': row[2],
                    'experience': row[3],
                    'skills': [skill.replace('"', '') for skill in row[4].split(',')] if row[4] is not None else [],
                    'email': row[5],
                    'phone_number': [phone_number for phone_number in row[6].split(',')] if row[6] is not None else [],
                    'resume': row[7]
                } for row in search_results_user_data]

                search_query_cvs = "SELECT id, fullname, email, phone_number, major, skills, experience, resume FROM cvs"
                search_results_cvs = conn.execute(text(search_query_cvs)).fetchall()
                result_list_cvs = [{
                    'id': row[0],
                    'fullname': row[1],
                    'major': row[4],  # Assuming 'major' is at index 4 in the 'cvs' table
                    'experience': row[6],  # Assuming 'experience' is at index 6 in the 'cvs' table
                    'skills': [skill.replace('"', '') for skill in row[5].split(',')] if row[5] is not None else [],
                    'email': row[2],
                    'phone_number': [phone_number for phone_number in row[3].split(',')] if row[3] is not None else [],
                    'resume': row[7]
                } for row in search_results_cvs]

                result_list = result_list_user_data + result_list_cvs

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
            return "Kalit so'z xato"
        except exc.StatementError as e:
            conn.rollback()
            return str(e), 400


@app.route('/search/<id>', methods=['GET'])
@jwt_required()
def search_id(id: int):
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401
    else:
        try:
            user_info = []
            user = conn.execute(text(f"SELECT * FROM user_data WHERE id = :id"), {"id": id}).fetchone()
            if user is None:
                return 'Bunday foydalanuvchi mavjud emas', 400
            else:
                degree_general = json.loads(user.degree_general) if user.degree_general else []
                skill = skills(user.skills)
                user_info.append({
                    "message": "Succesfull",
                    "fullname": user.fullname,
                    "username": user.username,
                    "email": user.email,
                    "date_birth": user.date_birth,
                    "phone_number": number(user.phone_number),
                    "address": user.address,
                    "major": user.major,
                    "experience": user.experience,
                    "skills": skill,
                    "resume": encode_to_base64(user.resume),
                    "degree_general": degree_general,
                    "about": user.about
                })
            return jsonify(user_info), 200
        except exc.StatementError as e:
            conn.rollback()
            return str(e), 400

@app.route('/stat', methods=['GET'])
@jwt_required()
def stat():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401
    else:
        try:
            date_data = {}
            query1 = text("SELECT DATE_TRUNC('day', created_on) AS registration_date, COUNT(*) AS user_count FROM user_data GROUP BY registration_date;")
            data1 = conn.execute(query1).fetchall()
            data1 = sorted(data1, key=lambda row: row[0])
            
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
        return 'Invalid data', 401
    else:
        if request.method == 'POST':
            data = request.json
            try:
                if 'username' in data:
                    username = data['username']
                    user_data = conn.execute(text("SELECT profile_photo, id FROM user_data WHERE username=:username"), {"username": username}).fetchone()
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
            statement = text("SELECT profile_photo, id, username FROM user_data WHERE id != :user_id AND accepted = :boolean")
            result = conn.execute(statement, {'user_id': id, 'boolean': True}).fetchall()

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
        return 'Invalid data', 401
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
                result = conn.execute(query, {'user_id1': user_1, 'user_id2': user_2}).fetchall()

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
            

@app.route('/resumes', methods=['POST', 'GET'])
@jwt_required()
def resumes():
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)

    if not is_valid:
        return 'Invalid data', 401
    else:
        if request.method == 'POST':
            try:
                data = request.json
                fullname = data['fullname']
                print(data)
                existing_gmail = conn.execute(text("SELECT email FROM cvs WHERE email = :email"), {'email': data['email']}).fetchone()
                if existing_gmail:
                    error = "Bu email band. Iltimos, boshqa elektron pochtadan foydalaning."
                    return error, 400
                
                for key, value in data.items():
                    if key == 'skills':
                        skills = json.dumps(data['skills'])
                    elif key == 'degree_general':
                        degree = json.dumps(data['degree_general'])
                    elif key == 'resume':
                        resume = save_base64_resume(value, username=fullname)

                query = text("INSERT INTO user_data (id, fullname, email, address, phone_number, degree_general, major, skills, experience) VALUES (:id, :fullname, :email, :address, :phone_number, :degree_general, :major, :skills, :experience)")
                params = {
                    'id': str(uuid.uuid4()),
                    'fullname': data['fullname'],
                    'email': data['email'],
                    'address': data['address'],
                    'phone_number': data['phone_number'],
                    'degree_general': degree,
                    'major': data['major'],
                    'skills': skills,
                    'experience': data['experience'],
                    'resume': resume
                }
                conn.execute(query, params)
                conn.commit()
                return "Resume added successfully", 200
            except ValueError as e:
                error_message = str(e)
                return jsonify({'error': error_message}), 400
            except smtplib.SMTPAuthenticationError as e:
                return str(e)
        if request.method == 'GET':
            return "OK"
        

@app.route('/change_password/<id>', methods=['POST'])
@jwt_required()
def change_password(id: int):
    current_user = get_jwt_identity()
    user_id = request.headers.get('X-Userid')
    user_role = request.headers.get('X-Userrole')
    is_valid = check_user(current_user, user_id, user_role)
    
    if not is_valid:
        return 'Invalid data', 401
    else:
        if request.method == 'POST':
            old, new = request.json['old_password'], request.json['new_password']
            query = conn.execute(text(f"SELECT password FROM user_data WHERE id = {id}")).fetchone()
            is_valid = bcrypt.verify(old, query.password)
            if is_valid:
                conn.execute(text("UPDATE user_data SET password=:value WHERE id=:user_id"), {'user_id': id, 'value': new})
                conn.commit()
                return "Parol muvaffaqiyatli o'zgartirildi"
            else:
                return "Parol mos kelmadi"

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
    conn.execute(query, {'sender_id': receiver_id, 'receiver_id': sender_id})
    conn.commit()

    # Сохраняем сообщение в базе данных
    query1 = text("""
        INSERT INTO messages (sender_id, receiver_id, message_text, is_read)
        VALUES (:sender_id, :receiver_id, :message_text, :is_read)
    """)
    conn.execute(query1, {'sender_id': sender_id, 'receiver_id': receiver_id, 'message_text': message, 'is_read': False})
    conn.commit()

    # Извлекаем сообщения из базы данных для отображения в чате
    query2 = text("""
        SELECT id, sender_id, receiver_id, message_text, timestamp, is_read
        FROM messages
        WHERE (sender_id = :user_id1 AND receiver_id = :user_id2)
        OR (sender_id = :user_id2 AND receiver_id = :user_id1)
        ORDER BY timestamp
    """)
    result = conn.execute(query2, {'user_id1': sender_id, 'user_id2': receiver_id}).fetchall()

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
    receiver_socket_id = connected_users.get(receiver_id)
    if receiver_socket_id:
        socketio.emit('new_message', messages, room=receiver_socket_id)


@socketio.on('see_message')
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
        conn.execute(query, {'sender_id': sender_id, 'receiver_id': receiver_id, 'msg_id': msg_id})
        conn.commit()

        query = text("""
            SELECT id, sender_id, receiver_id, message_text, timestamp, is_read
            FROM messages
            WHERE (sender_id = :user_id1 AND receiver_id = :user_id2)
            OR (sender_id = :user_id2 AND receiver_id = :user_id1)
            ORDER BY timestamp
        """)
        result = conn.execute(query, {'user_id1': sender_id, 'user_id2': receiver_id}).fetchall()

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
        receiver_socket_id = connected_users.get(receiver_id)
        if receiver_socket_id:
            socketio.emit('see_message', messages, room=receiver_socket_id)
    
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
                SELECT u.id, COUNT(m.id) as unread_msg
                FROM user_data u
                LEFT JOIN messages m ON u.id = m.sender_id AND m.receiver_id = :user_id AND m.is_read = false
                WHERE u.id != :user_id_to_exclude
                GROUP BY u.id;
            """)
            result = conn.execute(query, {'user_id': user_id_to_exclude, 'user_id_to_exclude': user_id_to_exclude}).fetchall()

            for row in result:
                user_id, unread_msg = row
                user_data = {
                    "id": user_id,
                    "unread_msg": unread_msg
                }
                chat_users.append(user_data)
            chat_users_sorted = sorted(chat_users, key=lambda x: x['id'])
            socketio.emit('count', chat_users_sorted, room=socket_id)

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
    # socketio.run(app, debug=True, host='localhost', port=1000)
    socketio.run(app, debug=True, port=1000, host='0.0.0.0')