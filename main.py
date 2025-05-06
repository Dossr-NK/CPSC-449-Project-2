
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy import Column, Integer, String, Float, create_engine, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import re

# App setup
app = FastAPI()

# Constants
SECRET_KEY = "CPSC449"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# MySQL setup
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://root:Ryan172124$$@localhost/inventory_db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# MongoDB setup
mongo_client = AsyncIOMotorClient("mongodb://localhost:27017")
mongo_db = mongo_client["inventory_db"]
mongo_inventory_collection = mongo_db["inventory_items"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(String(100), default="user")

class InventoryItem(Base):
    __tablename__ = "inventory_items"
    id = Column(Integer, primary_key=True, index=True)
    item_name = Column(String(100), nullable=False)
    description = Column(String(255))
    quantity = Column(Integer, nullable=False)
    price = Column(Float, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User")
    
Base.metadata.create_all(bind=engine)

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Schemas
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    def validate_password(self):
        if (len(self.password) < 8 or
            not re.search(r"[A-Z]", self.password) or
            not re.search(r"\d", self.password) or
            not re.search(r"[!@#$%^&*(),.?\\\":{}|<>]", self.password)):
            raise ValueError("Password must be 8+ characters long, include uppercase, number, special character.")
        return self.password
    
class UserLogin(BaseModel):
    username: str
    password: str

class InventoryCreate(BaseModel):
    item_name: str
    description: str = ""
    quantity: int = Field(..., ge=0, description="Quantity must be non-negative")
    price: float = Field(..., ge=0.0, description="Price must be non-negative")

    @validator("item_name")
    def item_name_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError("Item name cannot be empty or just whitespace.")
        return v

# JWT Utilities
def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def get_user_from_token(token: str, db: Session):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return db.query(User).filter_by(username=payload.get("sub")).first()
    except JWTError:
        return None

# ---------------- Auth Routes ----------------

@app.post("/api/auth/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    user.validate_password()
    if db.query(User).filter_by(username=user.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    hashed_pw = pwd_context.hash(user.password)
    new_user = User(username=user.username, email=user.email, password=hashed_pw)
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
def login(user: UserLogin, response: Response, db: Session = Depends(get_db)):
    db_user = db.query(User).filter_by(username=user.username).first()
    if not db_user or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": db_user.username})
    response.set_cookie(key="session", value=token, httponly=True, max_age=1800)
    return {"message": "Login successful"}

@app.get("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("session")
    return {"message": "Logged out successfully"}

@app.get("/api/auth/status")
def status(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("session")
    user = get_user_from_token(token, db) if token else None
    return {"status": "logged_in", "username": user.username} if user else {"status": "not_logged_in"}

@app.get("/api/mongo/test")
async def test_mongo_connection():
    try:
        await mongo_inventory_collection.insert_one({"test": "connection"})
        return {"message": "MongoDB connection successful"}
    except Exception as e:
        return {"error": str(e)}

# ---------------- MySQL Routes (User-Specific) ----------------

@app.post("/api/sql/inventory")
def create_inventory(item: InventoryCreate, db: Session = Depends(get_db), request: Request = None):
    token = request.cookies.get("session")
    user = get_user_from_token(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    new_item = InventoryItem(
        item_name=item.item_name,
        description=item.description,
        quantity=item.quantity,
        price=item.price,
        user_id=user.id
    )
    db.add(new_item)
    db.commit()
    return {"message": "Item created", "item_id": new_item.id}

@app.get("/api/sql/inventory")
def read_inventory(db: Session = Depends(get_db), request: Request = None):
    token = request.cookies.get("session")
    user = get_user_from_token(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return db.query(InventoryItem).filter_by(user_id=user.id).all()

@app.put("/api/sql/inventory/{item_id}")
def update_inventory(item_id: int, item: InventoryCreate, db: Session = Depends(get_db), request: Request = None):
    token = request.cookies.get("session")
    user = get_user_from_token(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    db_item = db.query(InventoryItem).filter_by(id=item_id, user_id=user.id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    for key, value in item.dict().items():
        setattr(db_item, key, value)
    db.commit()
    return {"message": "Item updated"}

@app.delete("/api/sql/inventory/{item_id}")
def delete_inventory(item_id: int, db: Session = Depends(get_db), request: Request = None):
    token = request.cookies.get("session")
    user = get_user_from_token(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    db_item = db.query(InventoryItem).filter_by(id=item_id, user_id=user.id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(db_item)
    db.commit()
    return {"message": "Item deleted"}

# ---------------- MongoDB Routes (User-Specific) ----------------

@app.post("/api/mongo/inventory")
async def mongo_create_inventory_item(item: InventoryCreate, request: Request):
    token = request.cookies.get("session")
    db = next(get_db())
    user = get_user_from_token(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    new_item = item.dict()
    new_item["user_id"] = user.id
    await mongo_inventory_collection.insert_one(new_item)
    return {"message": "Mongo item created"}

@app.get("/api/mongo/inventory")
async def mongo_get_inventory(request: Request):
    token = request.cookies.get("session")
    db = next(get_db())
    user = get_user_from_token(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    items = await mongo_inventory_collection.find({"user_id": user.id}).to_list(100)
    for item in items:
        item["_id"] = str(item["_id"])
    return items

@app.put("/api/mongo/inventory/{item_id}")
async def mongo_update_inventory_item(item_id: str, item: InventoryCreate, request: Request):
    token = request.cookies.get("session")
    db = next(get_db())
    user = get_user_from_token(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    update_data = item.dict()
    result = await mongo_inventory_collection.update_one(
        {"_id": ObjectId(item_id), "user_id": user.id},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Mongo item updated"}

@app.delete("/api/mongo/inventory/{item_id}")
async def mongo_delete_inventory_item(item_id: str, request: Request):
    token = request.cookies.get("session")
    db = next(get_db())
    user = get_user_from_token(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    item = await mongo_inventory_collection.find_one({"_id": ObjectId(item_id), "user_id": user.id})
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    await mongo_inventory_collection.delete_one({"_id": ObjectId(item_id), "user_id": user.id})
    return {"message": "Item deleted successfully"}

# ---------------- Admin Routes Import ----------------

from admin import router as admin_router
app.include_router(admin_router)
