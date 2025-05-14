# database.py (PostgreSQL Database Manager)
import os
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, MetaData, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.sql import func
from datetime import datetime, timedelta
from contextlib import contextmanager

# Use environment variable for database connection
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:RjHoIqYWjTOVPczUeEYbvCTqaTGqYRQD@shuttle.proxy.rlwy.net:44122/railway')

# Create SQLAlchemy engine and session
engine = create_engine(DATABASE_URL) if DATABASE_URL else None
db_session = scoped_session(sessionmaker(bind=engine)) if engine else None
Base = declarative_base()
if db_session:
    Base.query = db_session.query_property()

# Define models
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    
class Session(Base):
    __tablename__ = 'sessions'
    
    session_id = Column(String(32), primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    expires_at = Column(DateTime, nullable=False)

class RateLimit(Base):
    __tablename__ = 'rate_limits'
    
    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    request_count = Column(Integer, default=0)
    last_request = Column(DateTime, nullable=False)

class ChatHistory(Base):
    __tablename__ = 'chat_history'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    role = Column(String(10), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, server_default=func.now())
    
class Document(Base):
    __tablename__ = 'documents'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    filename = Column(String(255), nullable=False)
    content_type = Column(String(100), nullable=False)
    file_path = Column(String(255), nullable=False)
    upload_date = Column(DateTime, server_default=func.now())
    analysis = Column(Text, nullable=True)  # Stores the AI analysis of the document

class DatabaseManager:
    def __init__(self):
        self.db_initialized = False
        self._init_db()
    
    @contextmanager
    def _get_session(self):
        """Get a database session with exception handling"""
        if not self.db_initialized or not db_session:
            # If database isn't initialized, yield None
            yield None
            return
        
        session = None
        try:
            session = db_session()
            yield session
            session.commit()
        except Exception as e:
            if session:
                session.rollback()
            print(f"Database error: {e}")
        finally:
            if session:
                session.close()

    def _init_db(self):
        """Initialize database tables"""
        if not engine:
            print("Database engine not initialized - no connection string provided")
            return
            
        try:
            Base.metadata.create_all(bind=engine)
            self.db_initialized = True
            print("Database initialized successfully")
        except Exception as e:
            print(f"Error initializing database: {e}")
            self.db_initialized = False

    # User management methods
    def create_user(self, username, password):
        """Create a new user"""
        with self._get_session() as session:
            if not session:
                print("Failed to create user: Database not available")
                return None
                
            try:
                # Ensure we have a clean string password before hashing
                if not isinstance(password, str):
                    password = str(password)
                
                # Hash and store the password as a string
                hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                password_hash_str = hashed.decode('utf-8')  # Store the hash as a string
                
                # Create the new user
                new_user = User(username=username, password_hash=password_hash_str)
                session.add(new_user)
                session.flush()
                
                print(f"User created successfully: {username}")
                return new_user.id
                
            except Exception as e:
                print(f"Error creating user: {e}")
                return None

    def verify_user(self, username, password):
        """Verify user credentials"""
        with self._get_session() as session:
            if not session:
                print("Failed to verify user: Database not available")
                return None
                
            try:
                user = session.query(User).filter_by(username=username).first()
                if not user:
                    print(f"User not found: {username}")
                    return None
                
                try:
                    # For better debugging
                    print(f"Attempting to verify password for user: {username}")
                    
                    # Ensure password is a string
                    if not isinstance(password, str):
                        password = str(password)
                    
                    # Get password hash from database
                    password_hash = user.password_hash
                    
                    # Ensure password hash is properly encoded
                    if isinstance(password_hash, str):
                        password_hash = password_hash.encode('utf-8')
                        
                    # Check password
                    if bcrypt.checkpw(password.encode('utf-8'), password_hash):
                        print(f"Password verified for user: {username}")
                        return user.id
                    else:
                        print(f"Invalid password for user: {username}")
                        return None
                except Exception as e:
                    print(f"Password verification error: {e}")
                    
                    # Let's try a fallback method as well
                    try:
                        # Create a new hash with the same password to see if it works
                        new_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                        # Store this hash for debugging
                        print(f"Debug - New hash for comparison: {new_hash.decode('utf-8')}")
                        return None
                    except Exception as fallback_error:
                        print(f"Fallback error: {fallback_error}")
                        return None
            except Exception as e:
                print(f"Error verifying user: {e}")
                return None

    # Session management methods
    def create_session(self, user_id, session_duration=3600):
        """Create a new session for a user"""
        session_id = os.urandom(16).hex()
        expires_at = datetime.now() + timedelta(seconds=session_duration)
        
        with self._get_session() as session:
            if not session:
                print("Failed to create session: Database not available")
                return session_id  # Return the ID anyway so UI doesn't break
                
            try:
                new_session = Session(session_id=session_id, user_id=user_id, expires_at=expires_at)
                session.add(new_session)
                return session_id
            except Exception as e:
                print(f"Error creating session: {e}")
                return session_id  # Return the ID anyway so UI doesn't break

    def validate_session(self, session_id):
        """Validate an existing session"""
        with self._get_session() as session:
            if not session:
                print("Failed to validate session: Database not available")
                return None
                
            try:
                user_session = session.query(Session).filter_by(session_id=session_id).first()
                if user_session and datetime.now() < user_session.expires_at:
                    return user_session.user_id
                return None
            except Exception as e:
                print(f"Error validating session: {e}")
                return None

    # Rate limiting methods
    def check_rate_limit(self, user_id, limit=10, window=60):
        """Check and update rate limit for a user"""
        if not user_id:
            return False
            
        with self._get_session() as session:
            if not session:
                print("Failed to check rate limit: Database not available")
                return True  # Allow the request if DB is not available
                
            try:
                rate_limit = session.query(RateLimit).filter_by(user_id=user_id).first()
                now = datetime.now()
                
                if not rate_limit:
                    # First request, create new rate limit
                    rate_limit = RateLimit(user_id=user_id, request_count=1, last_request=now)
                    session.add(rate_limit)
                    return True
                    
                if now - rate_limit.last_request > timedelta(seconds=window):
                    # Expired window, reset counter
                    rate_limit.request_count = 1
                    rate_limit.last_request = now
                    return True
                elif rate_limit.request_count < limit:
                    # Within limit, increment counter
                    rate_limit.request_count += 1
                    rate_limit.last_request = now
                    return True
                    
                # Rate limit exceeded
                return False
            except Exception as e:
                print(f"Error checking rate limit: {e}")
                return True  # Allow the request if there's an error

    # Chat history methods
    def save_message(self, user_id, role, content):
        """Save a chat message"""
        with self._get_session() as session:
            if not session:
                print("Failed to save message: Database not available")
                return
                
            try:
                message = ChatHistory(user_id=user_id, role=role, content=content)
                session.add(message)
            except Exception as e:
                print(f"Error saving message: {e}")

    def get_history(self, user_id, limit=100):
        """Get chat history for a user"""
        with self._get_session() as session:
            if not session:
                print("Failed to get history: Database not available")
                return []  # Return empty history if DB is not available
                
            try:
                messages = session.query(ChatHistory).filter_by(user_id=user_id).order_by(
                    ChatHistory.timestamp.desc()).limit(limit).all()
                # Reverse the order to display oldest messages first
                return [{"role": msg.role, "content": msg.content} for msg in reversed(messages)]
            except Exception as e:
                print(f"Error getting history: {e}")
                return []  # Return empty history on error
                
    def clear_history(self, user_id):
        """Clear chat history for a user"""
        with self._get_session() as session:
            if not session:
                print("Failed to clear history: Database not available")
                return False
                
            try:
                session.query(ChatHistory).filter_by(user_id=user_id).delete()
                session.commit()
                return True
            except Exception as e:
                print(f"Error clearing history: {e}")
                session.rollback()
                return False
                
    def save_document(self, user_id, filename, content_type, file_path):
        """Save document information to database"""
        with self._get_session() as session:
            if not session:
                print("Failed to save document: Database not available")
                return None
                
            try:
                document = Document(
                    user_id=user_id,
                    filename=filename,
                    content_type=content_type,
                    file_path=file_path
                )
                session.add(document)
                session.commit()
                return document.id
            except Exception as e:
                print(f"Error saving document: {e}")
                session.rollback()
                return None
                
    def get_user_documents(self, user_id):
        """Get all documents for a user"""
        with self._get_session() as session:
            if not session:
                print("Failed to get documents: Database not available")
                return []
                
            try:
                documents = session.query(Document).filter_by(user_id=user_id).order_by(
                    Document.upload_date.desc()).all()
                return documents
            except Exception as e:
                print(f"Error getting documents: {e}")
                return []
                
    def save_document_analysis(self, document_id, analysis_text):
        """Save analysis for a document"""
        with self._get_session() as session:
            if not session:
                print("Failed to save analysis: Database not available")
                return False
                
            try:
                document = session.query(Document).filter_by(id=document_id).first()
                if document:
                    document.analysis = analysis_text
                    session.commit()
                    return True
                return False
            except Exception as e:
                print(f"Error saving analysis: {e}")
                session.rollback()
                return False
                
    def get_document(self, document_id, user_id=None):
        """Get a document by id, optionally verifying user ownership"""
        with self._get_session() as session:
            if not session:
                print("Failed to get document: Database not available")
                return None
                
            try:
                query = session.query(Document).filter_by(id=document_id)
                if user_id:
                    query = query.filter_by(user_id=user_id)
                document = query.first()
                return document
            except Exception as e:
                print(f"Error getting document: {e}")
                return None
