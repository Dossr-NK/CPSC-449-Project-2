from fastapi import APIRouter, Request, Depends, HTTPException, Response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from motor.motor_asyncio import AsyncIOMotorClient
from jose import jwt, JWTError
from bson import ObjectId
from main import User, InventoryItem, Base, get_db, SECRET_KEY, ALGORITHM, InventoryCreate, get_user_from_token

router = APIRouter(prefix="/api/admin", tags=["Admin"])

# MongoDB setup (reuse the same connection settings)
mongo_client = AsyncIOMotorClient("mongodb://localhost:27017")
mongo_inventory_collection = mongo_client["inventory_db"]["inventory_items"]


def require_admin(token: str, db: Session):
    user = get_user_from_token(token, db)
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ---------------- MySQL Admin Routes ----------------

@router.get("/sql/inventory")
def admin_get_all_inventory(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("session")
    require_admin(token, db)
    return db.query(InventoryItem).all()

@router.post("/sql/inventory")
def admin_create_inventory(item: InventoryCreate, request: Request, db: Session = Depends(get_db)):
    admin_user = require_admin(request.cookies.get("session"), db)
    new_item = InventoryItem(**item.dict(), user_id=admin_user.id)
    db.add(new_item)
    db.commit()
    return {"message": "Admin created item", "item_id": new_item.id}

@router.put("/sql/inventory/{item_id}")
def admin_update_inventory(item_id: int, item: InventoryCreate, request: Request, db: Session = Depends(get_db)):
    admin_user = require_admin(request.cookies.get("session"), db)
    db_item = db.query(InventoryItem).filter_by(id=item_id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    for key, value in item.dict().items():
        setattr(db_item, key, value)
    db.commit()
    return {"message": "Item updated by admin"}

@router.delete("/sql/inventory/{item_id}")
def admin_delete_inventory(item_id: int, request: Request, db: Session = Depends(get_db)):
    admin_user = require_admin(request.cookies.get("session"), db)
    db_item = db.query(InventoryItem).filter_by(id=item_id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(db_item)
    db.commit()
    return {"message": "Item deleted by admin"}

# ---------------- MongoDB Admin Routes ----------------

@router.get("/mongo/inventory")
async def admin_get_all_mongo_inventory(request: Request):
    db = next(get_db())
    require_admin(request.cookies.get("session"), db)
    items = await mongo_inventory_collection.find().to_list(100)
    for item in items:
        item["_id"] = str(item["_id"])
    return items

@router.post("/mongo/inventory")
async def admin_create_mongo_inventory(item: InventoryCreate, request: Request):
    db = next(get_db())
    admin_user = require_admin(request.cookies.get("session"), db)
    new_item = item.dict()
    new_item["user_id"] = admin_user.id
    await mongo_inventory_collection.insert_one(new_item)
    return {"message": "Mongo item created by admin"}

@router.put("/mongo/inventory/{item_id}")
async def admin_update_mongo_inventory(item_id: str, item: InventoryCreate, request: Request):
    db = next(get_db())
    admin_user = require_admin(request.cookies.get("session"), db)
    update_data = item.dict()
    result = await mongo_inventory_collection.update_one(
        {"_id": ObjectId(item_id)},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Mongo item updated by admin"}

@router.delete("/mongo/inventory/{item_id}")
async def admin_delete_mongo_inventory(item_id: str, request: Request):
    db = next(get_db())
    admin_user = require_admin(request.cookies.get("session"), db)
    item = await mongo_inventory_collection.find_one({"_id": ObjectId(item_id)})
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    await mongo_inventory_collection.delete_one({"_id": ObjectId(item_id)})
    return {"message": "Mongo item deleted by admin"}
