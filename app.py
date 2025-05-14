# app.py (Main Application)
import os
import json
import streamlit as st

# Set page config first (must be the first Streamlit command)
st.set_page_config(
    page_title="Healthcare AI Assistant",
    page_icon="🏥",
    layout="wide"
)

from dotenv import load_dotenv
import utils
from utils import load_config, setup_logger, create_download_link
from database import DatabaseManager, User, Session, RateLimit, ChatHistory, Document
import sqlalchemy.exc
from password_validator import PasswordValidator
from styles import apply_custom_styles
from components import session_timer, rate_limit_indicator, password_strength_meter, format_timestamp
from datetime import datetime
from groq import Groq
from model_handler import GroqModelHandler

# Load configurations and environment
load_dotenv()
config = load_config('config.json')
logger = setup_logger()
password_validator = PasswordValidator()

# Initialize database and Groq client
db = DatabaseManager()

# Initialize Groq client if API key is available
groq_api_key = os.environ.get("GROQ_API_KEY")
if groq_api_key:
    groq_client = Groq(api_key=groq_api_key)
    model_handler = GroqModelHandler(groq_client)
else:
    groq_client = None
    model_handler = None

class ChatBot:
    def __init__(self):
        self.initialize_session()
        self.load_styles()
    
    def load_styles(self):
        """Load custom styles for the application"""
        apply_custom_styles()
    
    def initialize_session(self):
        """Initialize session state variables"""
        if "history" not in st.session_state:
            st.session_state.history = []
        if "user_id" not in st.session_state:
            st.session_state.user_id = None
        if "session_id" not in st.session_state:
            st.session_state.session_id = None
        if "active_tab" not in st.session_state:
            st.session_state.active_tab = "chat"
        if "edit_profile" not in st.session_state:
            st.session_state.edit_profile = False
        if "password_strength" not in st.session_state:
            st.session_state.password_strength = 0
        if "password_color" not in st.session_state:
            st.session_state.password_color = "red"
        if "selected_model" not in st.session_state:
            st.session_state.selected_model = config.get('model_name', 'llama3-70b-8192')
        if "temperature" not in st.session_state:
            st.session_state.temperature = config.get('temperature', 0.7)
    
    def render_auth_form(self):
        """Render authentication form (login/register)"""
        # Display the app icon
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.image("generated-icon.png", width=150)
            
        st.subheader("User Authentication")
        
        # Create tabs for login and register
        login_tab, register_tab = st.tabs(["Login", "Register"])
        
        with login_tab:
            with st.form("login_form"):
                username = st.text_input("Username", key="login_username")
                password = st.text_input("Password", type="password", key="login_password")
                submit_button = st.form_submit_button("Login")
                
                if submit_button:
                    if not username or not password:
                        st.error("Please enter both username and password")
                    else:
                        self.handle_login(username, password)
        
        with register_tab:
            with st.form("register_form"):
                username = st.text_input("Username", key="register_username")
                password = st.text_input("Password", type="password", key="register_password")
                confirm_password = st.text_input("Confirm Password", type="password")
                
                # Display password strength meter outside the form callback
                if password:
                    # Check password outside the form
                    valid, strength, message = password_validator.validate(password)
                    st.session_state.password_strength = strength
                    st.session_state.password_color = password_validator.get_strength_color(strength)
                    password_strength_meter(strength, password_validator.get_strength_color(strength))
                
                submit_button = st.form_submit_button("Register")
                
                if submit_button:
                    if not username or not password:
                        st.error("Please enter both username and password")
                    elif password != confirm_password:
                        st.error("Passwords do not match")
                    else:
                        valid, strength, message = password_validator.validate(password)
                        if not valid:
                            st.error(message)
                        else:
                            self.handle_registration(username, password)
    
    def check_password_strength(self, password):
        """Check password strength and update session state"""
        if password:
            valid, strength, message = password_validator.validate(password)
            st.session_state.password_strength = strength
            st.session_state.password_color = password_validator.get_strength_color(strength)
        else:
            st.session_state.password_strength = 0
            st.session_state.password_color = "red"
    
    def handle_login(self, username, password):
        """Handle user login"""
        user_id = db.verify_user(username, password)
        if user_id:
            session_id = db.create_session(user_id, config.get('session_duration', 3600))
            st.session_state.user_id = user_id
            st.session_state.session_id = session_id
            st.session_state.username = username  # Store username in session state
            
            # Load chat history from database
            st.session_state.history = db.get_history(user_id)
            
            st.success("Login successful!")
            st.rerun()
        else:
            st.error("Invalid credentials")
    
    def handle_registration(self, username, password):
        """Handle user registration"""
        try:
            user_id = db.create_user(username, password)
            st.success("Registration successful! Please login")
        except (sqlalchemy.exc.IntegrityError, sqlalchemy.exc.SQLAlchemyError) as e:
            st.error("Username already exists or database error occurred")
    
    def logout(self):
        """Handle user logout"""
        st.session_state.user_id = None
        st.session_state.session_id = None
        st.session_state.history = []
        st.session_state.active_tab = "chat"
        st.session_state.edit_profile = False
        st.rerun()
    
    def render_user_profile(self):
        """Render user profile section"""
        if not st.session_state.user_id:
            return
        
        with st.expander("User Profile", expanded=False):
            # Get user data using SQLAlchemy
            with db._get_session() as session:
                # Get user information
                user = session.query(User).filter_by(id=st.session_state.user_id).first()
                
                if not user:
                    st.warning("User data not found")
                    return
                
                username = user.username
                created_at = user.created_at
                
                # Get usage statistics
                message_count = session.query(ChatHistory).filter_by(
                    user_id=st.session_state.user_id, role='user').count()
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("##### Profile Information")
                st.write(f"**Username:** {username}")
                st.write(f"**Account Created:** {format_timestamp(created_at)}")
                st.write(f"**Total Messages:** {message_count}")
            
            with col2:
                st.markdown("##### Session Information")
                session_timer()
                rate_limit_indicator(db, st.session_state.user_id, config.get('rate_limit', 10))
            
            # Change password form
            if st.session_state.edit_profile:
                st.markdown("##### Change Password")
                with st.form("change_password_form"):
                    current_password = st.text_input("Current Password", type="password")
                    new_password = st.text_input("New Password", type="password", key="new_password") 
                    confirm_password = st.text_input("Confirm New Password", type="password")
                    
                    # Display password strength meter
                    if new_password:
                        # Check password inside form but without callbacks
                        valid, strength, message = password_validator.validate(new_password)
                        password_strength_meter(strength, password_validator.get_strength_color(strength))
                    
                    submit_button = st.form_submit_button("Update Password")
                    
                    if submit_button:
                        if not current_password or not new_password or not confirm_password:
                            st.error("All fields are required")
                        elif new_password != confirm_password:
                            st.error("New passwords do not match")
                        else:
                            valid, strength, message = password_validator.validate(new_password)
                            if not valid:
                                st.error(message)
                            else:
                                # Verify current password
                                if db.verify_user(username, current_password):
                                    # Update password in database using SQLAlchemy
                                    with db._get_session() as session:
                                        if not session:
                                            st.error("Database connection not available")
                                            return
                                            
                                        try:
                                            import bcrypt
                                            hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                                            password_hash_str = hashed.decode('utf-8')  # Convert to string for storage
                                            
                                            user = session.query(User).filter_by(id=st.session_state.user_id).first()
                                            if user:
                                                user.password_hash = password_hash_str
                                                st.success("Password updated successfully")
                                                st.session_state.edit_profile = False
                                            else:
                                                st.error("User not found")
                                        except Exception as e:
                                            st.error(f"Error updating password: {e}")
                                else:
                                    st.error("Current password is incorrect")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.session_state.edit_profile:
                    if st.button("Cancel", key="cancel_edit"):
                        st.session_state.edit_profile = False
                        st.rerun()
                else:
                    if st.button("Edit Profile", key="edit_profile"):
                        st.session_state.edit_profile = True
                        st.rerun()
            with col2:
                if st.button("Logout", key="logout_button"):
                    self.logout()
    
    def render_sidebar(self):
        """Render sidebar with configuration options"""
        with st.sidebar:
            st.title("Healthcare AI Assistant")
            
            # Use the generated icon image
            st.image("generated-icon.png", width=100)
            
            # User profile section (if logged in)
            if st.session_state.user_id:
                # Instructions first - above all other sections
                with st.expander("Instructions", expanded=False):
                    st.markdown("""
                    ### Healthcare Assistant
                    
                    This AI assistant can help with:
                    - General health questions
                    - Understanding medical terminology
                    - First aid guidance
                    - Wellness tips and lifestyle advice
                    
                    **Note:** This assistant is for informational purposes only and does not replace professional medical advice.
                    """)
                
                # Model selection options
                with st.expander("Model Settings", expanded=False):
                    st.subheader("AI Model Settings")
                    model_options = config.get('available_models', ["llama3-70b-8192"])
                    selected_model = st.selectbox(
                        "Select AI Model", 
                        options=model_options,
                        index=model_options.index(st.session_state.selected_model) if st.session_state.selected_model in model_options else 0
                    )
                    
                    # Temperature slider for response creativity
                    temperature = st.slider(
                        "Response Creativity (Temperature)", 
                        min_value=0.0, 
                        max_value=1.0, 
                        value=st.session_state.temperature,
                        step=0.1,
                        help="Lower values = more deterministic, higher values = more creative"
                    )
                    
                    # Update session state if changed
                    if selected_model != st.session_state.selected_model:
                        st.session_state.selected_model = selected_model
                    
                    if temperature != st.session_state.temperature:
                        st.session_state.temperature = temperature
                
                # User Profile below model settings
                with st.expander("User Profile", expanded=False):
                    st.write(f"**Username:** {st.session_state.username if 'username' in st.session_state else 'Anonymous'}")
                    rate_limit_indicator(db, st.session_state.user_id, config.get('rate_limit', 10))
                    if st.button("Logout", key="sidebar_logout"):
                        self.logout()
    
    def handle_documents(self):
        """Handle document upload and analysis"""
        # If user is not logged in, prompt them to do so
        if not st.session_state.user_id:
            st.info("Please log in to use document analysis")
            return
            
        st.subheader("Medical Document Analysis")
        
        # Create tabs for upload and history
        upload_tab, history_tab = st.tabs(["Upload Document", "Document History"])
        
        with upload_tab:
            st.write("Upload a medical document for AI analysis. Supported formats: PDF, DOCX, TXT")
            
            # File uploader
            uploaded_file = st.file_uploader("Choose a file", 
                type=['pdf', 'docx', 'doc', 'txt'], 
                key="document_uploader")
            
            # Document type selector
            if uploaded_file:
                # Guess document type from filename
                suggested_type = utils.get_document_type(uploaded_file.name)
                
                # Let user confirm or change the document type
                document_type = st.selectbox(
                    "Select document type",
                    options=["medical_record", "lab_report", "prescription", "discharge_summary", "medical_history"],
                    index=["medical_record", "lab_report", "prescription", "discharge_summary", "medical_history"].index(suggested_type)
                )
                
                if st.button("Analyze Document"):
                    with st.spinner("Analyzing document..."):
                        try:
                            # Save the uploaded file
                            file_path, content_type = utils.save_uploaded_file(uploaded_file)
                            
                            # Extract text from the file
                            document_text = utils.extract_text_from_file(file_path)
                            
                            if document_text and not document_text.startswith("Error"):
                                # Analyze the document using Groq API
                                analysis = model_handler.analyze_document(document_text, document_type)
                                
                                # Save the document info to the database
                                document_id = db.save_document(
                                    st.session_state.user_id, 
                                    uploaded_file.name, 
                                    content_type, 
                                    file_path
                                )
                                
                                # Save the analysis to the database
                                if document_id:
                                    db.save_document_analysis(document_id, analysis)
                                    
                                # Display the analysis
                                st.subheader("Analysis Results")
                                st.markdown(analysis)
                                
                                # Show success message
                                st.success("Document analyzed successfully!")
                                
                                # Provide download link
                                download_link = create_download_link(file_path)
                                if download_link:
                                    st.markdown("### Download Document")
                                    st.markdown("You can download the original document using the link below:")
                                    st.markdown(download_link, unsafe_allow_html=True)
                            else:
                                st.error(f"Could not extract text from document: {document_text}")
                                
                                # Still provide download link even if analysis fails
                                download_link = create_download_link(file_path)
                                if download_link:
                                    st.markdown("### Download Document")
                                    st.markdown("You can still download your original document:")
                                    st.markdown(download_link, unsafe_allow_html=True)
                                
                        except Exception as e:
                            st.error(f"Error analyzing document: {str(e)}")
                            
                            # Try to provide download link if file_path is defined
                            if 'file_path' in locals():
                                download_link = create_download_link(file_path)
                                if download_link:
                                    st.markdown("### Download Document")
                                    st.markdown("You can still download your original document:")
                                    st.markdown(download_link, unsafe_allow_html=True)
        
        with history_tab:
            st.write("View your previously analyzed documents")
            
            # Get documents from database and process them within the same database session
            with db._get_session() as session:
                try:
                    documents = session.query(Document).filter_by(user_id=st.session_state.user_id).order_by(
                        Document.upload_date.desc()).all()
                    
                    # Extract data from documents while session is still open
                    processed_documents = []
                    for doc in documents:
                        processed_documents.append({
                            "id": doc.id,
                            "filename": doc.filename,
                            "content_type": doc.content_type,
                            "file_path": doc.file_path,
                            "upload_date": doc.upload_date,
                            "analysis": doc.analysis
                        })
                
                    if not processed_documents:
                        st.info("You haven't uploaded any documents yet.")
                    else:
                        # Use the processed document data instead of direct SQLAlchemy objects
                        document_options = [f"{doc['filename']} ({doc['upload_date'].strftime('%Y-%m-%d %H:%M')})" for doc in processed_documents]
                        selected_document_index = st.selectbox(
                            "Select a document to view its analysis",
                            range(len(document_options)),
                            format_func=lambda i: document_options[i]
                        )
                except Exception as e:
                    st.error(f"Error loading documents: {str(e)}")
                    processed_documents = []
                
                if processed_documents and selected_document_index is not None and selected_document_index < len(processed_documents):
                    selected_document = processed_documents[selected_document_index]
                    
                    # Display document info
                    st.subheader(f"Document: {selected_document['filename']}")
                    st.write(f"Uploaded: {selected_document['upload_date'].strftime('%Y-%m-%d %H:%M')}")
                    st.write(f"Type: {selected_document['content_type']}")
                    
                    # Create download link for the document
                    file_path = selected_document['file_path']
                    download_link = create_download_link(file_path)
                    if download_link:
                        st.markdown(download_link, unsafe_allow_html=True)
                    else:
                        st.warning("File not found on server. It may have been moved or deleted.")
                    
                    # Display analysis
                    if selected_document['analysis']:
                        st.subheader("Analysis")
                        st.markdown(selected_document['analysis'])
                    else:
                        st.info("No analysis available for this document.")
    
    def handle_chat(self):
        """Handle chat interactions with the AI model"""
        # If user is not logged in, prompt them to do so
        if not st.session_state.user_id:
            st.info("Please log in to chat with the healthcare assistant")
            return
        
        # Display instructional content at the top
        with st.expander("Healthcare Assistant Instructions", expanded=False):
            st.markdown("""
            ### Using the Healthcare Assistant
            
            This AI assistant can help with:
            - General health questions
            - Understanding medical terminology
            - First aid guidance
            - Wellness tips and lifestyle advice
            
            **Note:** This assistant is for informational purposes only and does not replace professional medical advice.
            """)

        # Display example questions above the chat area
        with st.expander("Example Questions", expanded=False):
            st.markdown("""
            Try asking:
            - "What are symptoms of the common cold?"
            - "How can I lower my blood pressure naturally?"
            - "What should I do for a minor burn?"
            - "How much sleep do I need each night?"
            - "What foods are high in vitamin D?"
            """)
        
        # Add option to clear chat history
        col1, col2 = st.columns([5, 1])
        with col2:
            if st.button("Clear History", key="clear_chat"):
                # Clear history from session state
                st.session_state.history = []
                # Clear history from database
                db.clear_history(st.session_state.user_id)
                st.success("Chat history cleared!")
                st.rerun()
        
        # Display chat history
        for message in st.session_state.history:
            if message["role"] == "user":
                st.chat_message("user").write(message["content"])
            else:
                st.chat_message("assistant").write(message["content"])
        
        # Get user input
        user_input = st.chat_input("Ask a healthcare question...")
        
        if user_input:
            # Check rate limit
            if not db.check_rate_limit(st.session_state.user_id, config.get('rate_limit', 10), config.get('rate_window', 60)):
                st.error("Rate limit exceeded. Please wait before sending more messages.")
                return
            
            # Add user message to history and display
            st.chat_message("user").write(user_input)
            st.session_state.history.append({"role": "user", "content": user_input})
            
            # Save message to database
            db.save_message(st.session_state.user_id, "user", user_input)
            
            # Prepare prompt for healthcare-specific context
            prompt = f"""You are a helpful healthcare assistant. Answer the following medical or health-related question.
            Provide informative, evidence-based answers while being clear about medical limitations.
            Always remind users to consult healthcare professionals for personalized medical advice.
            
            User question: {user_input}
            """
            
            try:
                if model_handler:
                    # Use model handler to generate response
                    response = model_handler.generate(
                        prompt,
                        st.session_state.selected_model,
                        st.session_state.temperature,
                        config.get('max_tokens', 1024)
                    )
                    
                    # Add assistant message to history
                    st.session_state.history.append({"role": "assistant", "content": response})
                    
                    # Save message to database
                    db.save_message(st.session_state.user_id, "assistant", response)
                else:
                    st.error("AI model not available. Please check your configuration.")
            except Exception as e:
                st.error(f"Error generating response: {str(e)}")
    
    def run(self):
        """Main method to run the application"""
        # Apply custom styles
        self.load_styles()
        
        # Render sidebar
        self.render_sidebar()
        
        # Main content area
        st.title("Healthcare AI Assistant")
        
        # Check if user is logged in
        if not st.session_state.user_id:
            # Display authentication form
            self.render_auth_form()
        else:
            # Display tabs for different sections
            tabs = st.tabs(["Chat", "Documents", "Profile"])
            
            # Chat tab
            with tabs[0]:
                self.handle_chat()
            
            # Documents tab
            with tabs[1]:
                self.handle_documents()
            
            # Profile tab
            with tabs[2]:
                self.render_user_profile()

# Run the application
if __name__ == "__main__":
    app = ChatBot()
    app.run()
