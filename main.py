import ssl
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, ForeignKey, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
import jwt, datetime
from passlib.context import CryptContext
from geopy.distance import geodesic

ssl._create_default_https_context = ssl._create_unverified_context

app = FastAPI()
DATABASE_URL = "sqlite:///./shop.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "mysecret"

# Models
class Vendor(Base):
    __tablename__ = "vendors"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

class Shop(Base):
    __tablename__ = "shops"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    owner = Column(String)
    type = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    vendor_id = Column(Integer, ForeignKey("vendors.id"))

Base.metadata.create_all(bind=engine)

# Schemas
class VendorCreate(BaseModel):
    name: str
    email: str
    password: str

class VendorLogin(BaseModel):
    email: str
    password: str

class ShopCreate(BaseModel):
    name: str
    owner: str
    type: str
    latitude: float
    longitude: float

class TokenData(BaseModel):
    token: str

# Helper Functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_token(data: dict):
    return jwt.encode({"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1), **data}, SECRET_KEY, algorithm="HS256")

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# Routes
@app.post("/register/")
def register(vendor: VendorCreate, db: Session = Depends(get_db)):
    vendor.password = hash_password(vendor.password)
    new_vendor = Vendor(**vendor.dict())
    db.add(new_vendor)
    db.commit()
    return {"message": "Vendor registered successfully"}

@app.post("/login/")
def login(vendor: VendorLogin, db: Session = Depends(get_db)):
    db_vendor = db.query(Vendor).filter(Vendor.email == vendor.email).first()
    if not db_vendor or not verify_password(vendor.password, db_vendor.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_token({"vendor_id": db_vendor.id})
    return {"token": token}

@app.post("/shops/")
def create_shop(shop: ShopCreate, token: TokenData, db: Session = Depends(get_db)):
    vendor_data = decode_token(token.token)
    new_shop = Shop(**shop.dict(), vendor_id=vendor_data["vendor_id"])
    db.add(new_shop)
    db.commit()
    return {"message": "Shop created successfully"}

@app.get("/shops/")
def get_shops(token: TokenData, db: Session = Depends(get_db)):
    vendor_data = decode_token(token.token)
    shops = db.query(Shop).filter(Shop.vendor_id == vendor_data["vendor_id"]).all()
    return shops

@app.delete("/shops/{shop_id}")
def delete_shop(shop_id: int, token: TokenData, db: Session = Depends(get_db)):
    vendor_data = decode_token(token.token)
    shop = db.query(Shop).filter(Shop.id == shop_id, Shop.vendor_id == vendor_data["vendor_id"]).first()
    if not shop:
        raise HTTPException(status_code=404, detail="Shop not found")
    db.delete(shop)
    db.commit()
    return {"message": "Shop deleted"}

@app.get("/search/")
def search_shops(latitude: float, longitude: float, radius: float, db: Session = Depends(get_db)):
    shops = db.query(Shop).all()
    nearby_shops = [shop for shop in shops if geodesic((latitude, longitude), (shop.latitude, shop.longitude)).km <= radius]
    return nearby_shops

@app.get("/routes")
def get_routes():
    return {route.path: route.methods for route in app.routes}