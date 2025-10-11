"""
FastAPI Backend with API Key Generation
Complete backend service for managing applications and API keys
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Optional, List
import secrets
import hashlib
import os

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class Application(Base):
    __tablename__ = "applications"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    api_keys = relationship("APIKey", back_populates="application", cascade="all, delete-orphan")


class APIKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Integer, default=1)  # 1 = active, 0 = revoked
    
    # Relationship
    application = relationship("Application", back_populates="api_keys")


# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic Models
class ApplicationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class ApplicationResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(
        orm_mode=True
    )


class APIKeyCreate(BaseModel):
    name: Optional[str] = None
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    id: int
    api_key: str  # Only returned on creation
    name: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]


class APIKeyInfo(BaseModel):
    id: int
    name: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    is_active: bool
    
    model_config = ConfigDict(
        orm_mode=True
    )


# FastAPI App
app = FastAPI(
    title="Application API Key Manager",
    description="API for managing applications and their API keys",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Utility Functions
def hash_api_key(api_key: str) -> str:
    """Hash an API key using SHA-256"""
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(db: Session, api_key: str) -> Optional[APIKey]:
    """Verify an API key and return the key record if valid"""
    key_hash = hash_api_key(api_key)
    key_record = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == 1
    ).first()
    
    if key_record:
        # Check if expired
        if key_record.expires_at and key_record.expires_at < datetime.utcnow():
            return None
        
        # Update last used timestamp
        key_record.last_used_at = datetime.utcnow()
        db.commit()
        
    return key_record


# Dependency for API key authentication
async def require_api_key(
    x_api_key: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """Dependency to require valid API key"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    key_record = verify_api_key(db, x_api_key)
    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")
    
    return key_record


# Routes

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Application API Key Manager",
        "version": "1.0.0"
    }


@app.post("/app", response_model=ApplicationResponse, status_code=201)
async def create_application(
    app_data: ApplicationCreate,
    db: Session = Depends(get_db)
):
    """Create a new application"""
    try:
        new_app = Application(
            name=app_data.name,
            description=app_data.description
        )
        db.add(new_app)
        db.commit()
        db.refresh(new_app)
        return new_app
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create application: {str(e)}")


@app.get("/apps", response_model=List[ApplicationResponse])
async def list_applications(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List all applications"""
    apps = db.query(Application).offset(skip).limit(limit).all()
    return apps


@app.get("/app/{app_id}", response_model=ApplicationResponse)
async def get_application(app_id: int, db: Session = Depends(get_db)):
    """Get a specific application"""
    app = db.query(Application).filter(Application.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return app


@app.delete("/app/{app_id}", status_code=204)
async def delete_application(app_id: int, db: Session = Depends(get_db)):
    """Delete an application and all its API keys"""
    app = db.query(Application).filter(Application.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    db.delete(app)
    db.commit()
    return None


@app.post("/app/{app_id}/api-key", response_model=APIKeyResponse, status_code=201)
async def generate_api_key(
    app_id: int,
    key_data: APIKeyCreate = APIKeyCreate(),
    db: Session = Depends(get_db)
):
    """Generate a new API key for an application"""
    # Verify application exists
    app = db.query(Application).filter(Application.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    try:
        # Generate a secure random API key
        api_key = f"sk_{secrets.token_urlsafe(32)}"
        
        # Store hashed version in database
        key_record = APIKey(
            app_id=app_id,
            key_hash=hash_api_key(api_key),
            name=key_data.name or f"API Key for {app.name}",
            expires_at=key_data.expires_at,
            created_at=datetime.utcnow()
        )
        
        db.add(key_record)
        db.commit()
        db.refresh(key_record)
        
        # Return the plain key (only time it's shown)
        return APIKeyResponse(
            id=key_record.id,
            api_key=api_key,
            name=key_record.name,
            created_at=key_record.created_at,
            expires_at=key_record.expires_at
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to generate API key: {str(e)}")


@app.get("/app/{app_id}/api-keys", response_model=List[APIKeyInfo])
async def list_api_keys(app_id: int, db: Session = Depends(get_db)):
    """List all API keys for an application (without showing the actual keys)"""
    app = db.query(Application).filter(Application.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    keys = db.query(APIKey).filter(APIKey.app_id == app_id).all()
    return [
        APIKeyInfo(
            id=k.id,
            name=k.name,
            created_at=k.created_at,
            expires_at=k.expires_at,
            last_used_at=k.last_used_at,
            is_active=bool(k.is_active)
        )
        for k in keys
    ]


@app.delete("/app/{app_id}/api-key/{key_id}", status_code=204)
async def revoke_api_key(
    app_id: int,
    key_id: int,
    db: Session = Depends(get_db)
):
    """Revoke (deactivate) an API key"""
    key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.app_id == app_id
    ).first()
    
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    key.is_active = 0
    db.commit()
    return None


@app.get("/protected")
async def protected_route(key_record: APIKey = Depends(require_api_key)):
    """Example protected route that requires a valid API key"""
    return {
        "message": "Access granted!",
        "app_id": key_record.app_id,
        "key_name": key_record.name
    }


@app.post("/verify-key")
async def verify_key(x_api_key: str = Header(...), db: Session = Depends(get_db)):
    """Verify if an API key is valid"""
    key_record = verify_api_key(db, x_api_key)
    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")
    
    return {
        "valid": True,
        "app_id": key_record.app_id,
        "key_name": key_record.name,
        "expires_at": key_record.expires_at
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)