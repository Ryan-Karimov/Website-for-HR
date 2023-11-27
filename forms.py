from io import BytesIO
import json
from sqlalchemy.orm import validates, declarative_base
from sqlalchemy import Column, String, Boolean, Integer, text
import validators, base64, os
from datetime import datetime
from PIL import Image
from passlib.hash import bcrypt
from flask_mail import Message

from main import mail, conn

#validatsiya
Base = declarative_base()

class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(50), nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    role = Column(String(50), default='user', nullable=True)
    accepted = Column(Boolean, default=False, nullable=True)

    @validates('username')
    def username_alphanumeric(self, key, username):
        if not username[0].isalpha():
            raise ValueError("Foydalanuvchi nomining birinchi belgisi harfdan iborat bo'lishi kerak")
        if not username.isalnum():
            raise ValueError("Foydalanuvchi nomi faqat harf va raqamlardan iborat bo'lishi kerak")
        return username
    
    @validates('email')
    def email_valid(self, key, email):
        if not validators.email(email):
            raise ValueError("Elektron pochta formati noto'g'ri")
        return email
    
    @validates('password')
    def validate_password(self, key, password):
        if len(password) < 8:
            raise ValueError("Parol kamida 8 ta belgidan iborat bo'lishi kerak")
        if not any(c.isupper() for c in password):
            raise ValueError("Parol kamida bitta katta harfdan iborat bo'lishi kerak")
        if not any(c.islower() for c in password):
            raise ValueError("Parol kamida bitta kichik harfdan iborat bo'lishi kerak")
        if not any(c.isdigit() for c in password):
            raise ValueError("Parol kamida bitta raqamdan iborat bo'lishi kerak")
        return password


#base64'ni rasmga aylantirish va saqlash
def save_base64_image(image):
    if "," in image:
        image = image.split(',')[1]
    base64_string = base64.b64decode(image)
    directory = "C:/Users/U0104/Desktop/Profile_images"
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"image_{current_time}.jpg"
    file_path = os.path.join(directory, filename)
    with open(file_path, 'wb') as f:
        f.write(base64_string)
    image = Image.open(file_path)
    
    resized_image = image.resize((640, 360))
    
    resized_image.save(file_path, format='PNG')
    return file_path

#telefon raqamlarni ro'yxat shaklida qaytarish
def get_phone(phone_number):
    phone_list = []
    if phone_number is not None:
        data = phone_number.strip("{}")
        data_list = data.split(", ")
        phone_list = [int(item) for item in data_list if item != '' and item != '[]']
    return phone_list



#parolni shifrlash
def hash_pass(password):
    hashed_password = bcrypt.hash(password)
    return hashed_password

#rasmni formatini o'zgartirib, enkodlab jo'natish
# def change_aspect_ratio_and_encode(image_path, new_ratio):
#     if image_path == None:
#         return image_path
#     img = Image.open(image_path)
#     width, height = img.size
#     current_ratio = width / height

#     if current_ratio > new_ratio:
#         new_width = int(new_ratio * height)
#         img = img.resize((new_width, height), resample=Image.LANCZOS)
#     else:
#         new_height = int(width / new_ratio)
#         img = img.resize((width, new_height), resample=Image.LANCZOS)

#     with BytesIO() as buffer:
#         img.save(buffer, "PNG")
#         encoded_string = base64.b64encode(buffer.getvalue())
#     encoded_image = "data:image/png;base64," + encoded_string.decode("utf-8")
#     return encoded_image
def change_aspect_ratio_and_encode(image_path, new_ratio):
    if image_path is None:
        return None

    try:
        with Image.open(image_path) as img:
            width, height = img.size
            current_ratio = width / height

            if current_ratio > new_ratio:
                new_width = int(new_ratio * height)
                img = img.resize((new_width, height), resample=Image.LANCZOS)
            else:
                new_height = int(width / new_ratio)
                img = img.resize((width, new_height), resample=Image.LANCZOS)

            with BytesIO() as buffer:
                img.save(buffer, "PNG")
                encoded_string = base64.b64encode(buffer.getvalue())
            encoded_image = "data:image/png;base64," + encoded_string.decode("utf-8")
            return encoded_image
    except Exception as e:
        # Handle any exceptions here or log them if necessary
        return None

#elektron pochta manzili verifikatsiyasi
def send_email(sender, recipients, message):
    subject = 'Elektron pochta orqali tasdiqlash'
    msg = Message(subject=subject, sender = sender, recipients = recipients.split())
    msg.body = message
    mail.send(message=msg)

def skills(skills):
    if skills == None:
        skills = []
        return skills
    skills_list = skills[1:-1].split(',')
    skills_list = [skill.strip() for skill in skills_list]
    return skills_list

#jsonni ro'yhatga o'zgartirish
def number(num):
    cleaned_string = num.replace("{", "[").replace("}", "]")
    phone_list = json.loads(cleaned_string)
    return phone_list


#base64'ni rezyumega aylantirish va saqlash
def save_base64_resume(resume, username):
    if "," in resume:
        resume = resume.split(',')[1]
    base64_string = base64.b64decode(resume)
    directory = "C:/Users/U0104/Desktop/Resumes"
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"{username}_{current_time}.pdf"
    file_path = os.path.join(directory, filename)
    with open(file_path, 'wb') as f:
        f.write(base64_string)
    return file_path


#urlni PDF faylga aylantirish
def encode_to_base64(file_path):
    if file_path is None:
        return None
    with open(file_path, 'rb') as f:
        binary_data = f.read()
    base64_data = "data:application/pdf;base64," + base64.b64encode(binary_data).decode('utf-8')
    return base64_data


def check_token(user):
    claims = {
        'username': user.username,
        "id": user.id,
        "role": user.role
    }
    return claims


def check_user(current_user, user_id, user_role):
    query1 = text(f"SELECT * FROM user_data WHERE username='{current_user['username']}'")
    result1 = conn.execute(query1).fetchone()
    
    if str(result1.id) != user_id or result1.role != user_role:
        return False
    else:
        return True
    
def clean_skills_list(skill_list):
    cleaned_list = [skill.strip("[").strip("]") for skill in skill_list]
    return cleaned_list