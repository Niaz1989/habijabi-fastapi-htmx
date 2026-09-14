import os
from fastapi import FastAPI, HTTPException,Depends,Request,status,Response
from sqlalchemy.orm import Session,sessionmaker
from sqlalchemy import String, Integer, Column,Float,create_engine
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.ext.declarative import declarative_base
from pwdlib import PasswordHash
from datetime import datetime, timedelta, timezone
import jwt
from fastapi.responses import HTMLResponse
from fastapi.responses import PlainTextResponse
import shutil
from fastapi import File, UploadFile
from fastapi.staticfiles import StaticFiles


app = FastAPI()

#...........Folder path(only template folder)........
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'frontend','templates')
templates = Jinja2Templates(directory=TEMPLATES_DIR)

#................Database & password hashing........
password_hash=PasswordHash.recommended()
DATABASE_URL = "mysql+pymysql://root:root@localhost:3306/test?charset=utf8mb4"
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserTable(Base):
    __tablename__ = "amil_data"
    id = Column(Integer, primary_key=True,index=True,autoincrement=True)
    name = Column(String(255), unique=True, index=True)
    age = Column(Integer)
    height = Column(Float)
    weight = Column(Float)
    role = Column(String(255), default="user")
    profile_pic = Column(String(255),nullable=True)
    password = Column(String(255))

Base.metadata.create_all(engine)

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

SECRET_KEY = "your_secret_key_is_secure_under_precise_testing"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_name: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        user_role: str = payload.get("role", "user")
        if user_name is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return {"user_name": user_name, "user_id": user_id,"role": user_role}
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# --- রাউটস (Routes) ---

# ১. মূল হোমপেজ (এখানে রেজিস্ট্রেশন এবং লগইন ফর্ম দুটোই একসাথে থাকবে)
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # ইউজার যদি অলরেডি লগইন করা থাকে, তাকে সরাসরি ড্যাশবোর্ডে পাঠিয়ে দেবে
    if request.cookies.get("access_token"):
        return HTMLResponse(content="<script>window.location.href='/dashboard';</script>")
    return templates.TemplateResponse("index.html", {"request": request})





@app.post("/login", response_class=HTMLResponse)
async def login(response: Response, request: Request, db: Session = Depends(get_db)):
    form_data = await request.form()
    username = form_data.get("name").strip()
    password = form_data.get("password").strip()

    db.expire_all()

    user = db.query(UserTable).filter(UserTable.name == username).first()

    if not user:
        return """
        <div class="p-4 mb-4 text-sm text-red-800 bg-red-50 rounded-lg border border-red-200">
            ইউজার খুঁজে পাওয়া যায়নি!
        </div>
        """

    is_password_correct =password_hash.verify(password, user.password)
    if not is_password_correct:
        return """
        <div class="p-4 mb-4 text-sm text-red-800 bg-red-50 rounded-lg border border-red-200">
            ভুল ইউজারনেম বা পাসওয়ার্ড!
        </div>
        """

    # টোকেন তৈরি এবং HttpOnly কুকিতে সেট করা
    access_token = create_access_token(data={"sub": user.name, "user_id": user.id, "role": user.role})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax"
    )

  # লগইন সফল হলে HTMX-কে পুরো পেজ রিফ্রেশ করে ড্যাশবোর্ডে পাঠানোর সিগন্যাল
    response.headers["HX-Refresh"] = "true"
    return "<p class='text-green-600 font-bold'>লগইন সফল! রিডাইরেক্ট হচ্ছে...</p>"


@app.get("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    resp = PlainTextResponse(content="", status_code=200)
    resp.delete_cookie("access_token")   # delete cookie must be set on the actual response returned
    resp.headers["HX-Redirect"] = "/"
    return resp


# ড্যাশবোর্ড রাউট: সব ইউজারের তালিকা তুলে এনে পেজে পাঠানো

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    # ১. ব্রাউজার কুকি থেকে টোকেন চেক এবং ইউজার ডেটা ডিকোড
    token = request.cookies.get("access_token")
    if not token:
        return HTMLResponse(content="<script>window.location.href='/';</script>")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("DEBUG:", payload)
        current_user = {
            "user_name": payload.get("sub"),
            "user_id": payload.get("user_id"),
            "role": payload.get("role", "user")
        }
    except jwt.PyJWTError:
        return HTMLResponse(content="<script>window.location.href='/';</script>")

    # ২. ডেটাবেজ থেকে ফ্রেশ ইউজার লিস্ট তুলে আনা
    db.expire_all()
    db_users = db.query(UserTable).all()

    # ৩. জিংজা টেমপ্লেটের জন্য অবজেক্টগুলোকে খাঁটি পাইথন ডিকশনারিতে রূপান্তর (ম্যাজিক ট্রিক)
    formatted_users = []
    for u in db_users:
        formatted_users.append({
            "id": u.id,
            "name": u.name,
            "age": u.age,
            "height": u.height,
            "weight": u.weight,
            "role": u.role,
            "profile_pic": u.profile_pic
        })

    # ৪. কনটেক্সটে ফ্রেশ লিস্টটি পাস করা
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user,
        "users": formatted_users  # খাঁটি পাইথন লিস্ট পাঠানো হলো
    })


# --- ১. ইউজার ডিলিট করার এন্ডপয়েন্ট (HTMX Delete) ---
@app.delete("/amil/delete/{user_id}", response_class=HTMLResponse)
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()

    # HTMX-এর নিয়ম অনুযায়ী, ডিলিট সফল হলে ফাঁকা স্ট্রিং পাঠালে সেই রো (Row) টি স্ক্রিন থেকে হাওয়া হয়ে যাবে
    return ""


# --- ২. এডিট করার জন্য ইনলাইন ফর্ম (HTMX Inline Edit Form ফিক্স) ---
@app.get("/amil/edit/{user_id}", response_class=HTMLResponse)
async def edit_user_form(user_id: int, request: Request, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.id == user_id).first()
    if not user:
        return "ইউজার পাওয়া যায়নি"

    # ফর্মের অ্যাকশনে hx-put ব্যবহার করে ইনলাইন ইনপুট ফিল্ড ও সেভ/ক্যান্সেল বাটন পাঠানো
    return f"""
    <tr id="user-row-{user.id}" class="bg-blue-50 border-b">
        <td class="px-6 py-4 font-medium text-gray-900">{user.id}</td>
        <td class="px-4 py-2"><input type="text" name="name" value="{user.name}" class="border rounded p-1 text-sm w-full text-black"></td>
        <td class="px-4 py-2"><input type="number" name="age" value="{user.age}" class="border rounded p-1 text-sm w-full text-black"></td>
        <td class="px-4 py-2"><input type="number" step="0.1" name="height" value="{user.height}" class="border rounded p-1 text-sm w-full text-black"></td>
        <td class="px-4 py-2"><input type="number" step="0.1" name="weight" value="{user.weight}" class="border rounded p-1 text-sm w-full text-black"></td>
        <td class="px-4 py-2"><input type="text" name="role" value="{user.role}" class="border rounded p-1 text-sm w-full text-black"></td>
        <td class="px-6 py-4 flex gap-2">
            <!-- hx-include="closest tr" যোগ করার কারণে এই বাটনে চাপ দিলে পুরো লাইনের সব ইনপুট ডাটা ব্যাকএন্ডে সাবমিট হবে -->
            <button hx-put="/amil/update/{user.id}" 
                    hx-target="#user-row-{user.id}" 
                    hx-swap="outerHTML" 
                    hx-include="closest tr"
                    class="bg-green-600 text-white px-2 py-1 rounded text-xs hover:bg-green-700 font-semibold cursor-pointer">
                Save
            </button>
            <button hx-get="/dashboard" 
                    hx-target="body" 
                    class="bg-gray-500 text-white px-2 py-1 rounded text-xs hover:bg-gray-600 font-semibold cursor-pointer">
                Cancel
            </button>
        </td>
    </tr>
    """


# --- ৩. এডিট করা ডাটা ডাটাবেজে আপডেট করা (HTMX Put ফিক্স) ---
@app.put("/amil/update/{user_id}", response_class=HTMLResponse)
async def update_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    form_data = await request.form()
    user = db.query(UserTable).filter(UserTable.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # ইনপুট ফিল্ড থেকে নতুন ডাটা নিয়ে ডাটাবেজে আপডেট করা হচ্ছে
    user.name = form_data.get("name")
    user.age = int(form_data.get("age"))
    user.height = float(form_data.get("height"))
    user.weight = float(form_data.get("weight"))
    user.role = form_data.get("role")

    db.commit()
    db.refresh(user)

    # আপডেট শেষে আবার সাধারণ টেবিল রো (Row) ফরম্যাটে ডাটা ফেরত পাঠানো
    return f"""
    <tr id="user-row-{user.id}" class="hover:bg-gray-50 transition border-b">
        <td class="px-6 py-4 font-medium text-gray-900">{user.id}</td>
        <td class="px-6 py-4">{user.name}</td>
        <td class="px-6 py-4">{user.age}</td>
        <td class="px-6 py-4">{user.height}</td>
        <td class="px-6 py-4">{user.weight}</td>
        <td class="px-6 py-4">
            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                {user.role}
            </span>
        </td>
        <td class="px-6 py-4 flex gap-3">
            <button hx-get="/amil/edit/{user.id}" hx-target="#user-row-{user.id}" hx-swap="outerHTML" class="text-blue-600 hover:text-blue-900 font-medium cursor-pointer">Edit</button>
            <button hx-delete="/amil/delete/{user.id}" hx-target="#user-row-{user.id}" hx-swap="outerHTML" hx-confirm="আপনি কি নিশ্চিতভাবে এই ইউজারকে মুছে ফেলতে চান?" class="text-red-600 hover:text-red-900 font-medium cursor-pointer">Delete</button>
        </td>
    </tr>
    """


# আপলোড করা ছবি রাখার জন্য ফোল্ডার তৈরি
UPLOAD_DIR = os.path.join(BASE_DIR, "frontend", "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# আগের static মাউন্টিং-এ uploads ফোল্ডার চেনার জন্য এটি নিশ্চিত করুন:
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "frontend", "static")), name="static")


@app.post("/amil", response_class=HTMLResponse)
async def amil_1(
        request: Request,
        db: Session = Depends(get_db),
        profile_pic: UploadFile = File(None)
):
    print("DEBUG profile_pic:", profile_pic, profile_pic.filename if profile_pic else None)
    form_data = await request.form()
    name = form_data.get("name").strip()
    password = form_data.get("password").strip()

    existing = db.query(UserTable).filter(UserTable.name == name).first()
    if existing:
        return """
          <div class="p-4 mb-4 text-sm text-red-800 bg-red-50 rounded-lg border border-red-200">
              এই নামে ইউজার আগে থেকেই আছে!
          </div>
          """

    pic_filename = None
    if profile_pic and profile_pic.filename:
        pic_filename = f"{int(datetime.now().timestamp())}_{profile_pic.filename}"
        file_path = os.path.join(UPLOAD_DIR, pic_filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(profile_pic.file, buffer)

    hashed_password = password_hash.hash(password)

    db_user = UserTable(
        name=name,
        age=int(form_data.get("age")),
        height=float(form_data.get("height")),
        weight=float(form_data.get("weight")),
        password=hashed_password,
        role=form_data.get("role", "user"),
        profile_pic=f"/static/uploads/{pic_filename}" if pic_filename else None
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return templates.TemplateResponse("success_msg.html", {"request": request, "user": db_user})





