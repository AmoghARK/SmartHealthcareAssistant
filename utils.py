# utils.py (Utility Functions)
import json
import logging
import os
import uuid
import base64
from typing import Dict, Any, Tuple, Optional
from datetime import datetime
import PyPDF2
import docx
import mimetypes

def load_config(config_path: str) -> Dict[str, Any]:
    try:
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file {config_path} not found")
            
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        raise RuntimeError(f"Config loading failed: {str(e)}")

def setup_logger():
    logger = logging.getLogger("chatbot")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def save_uploaded_file(uploaded_file) -> Tuple[str, str]:
    """
    Save an uploaded file to disk
    
    Args:
        uploaded_file: The file uploaded through Streamlit
        
    Returns:
        Tuple[str, str]: (file_path, content_type)
    """
    # Create uploads directory if it doesn't exist
    os.makedirs("uploads", exist_ok=True)
    
    # Generate a unique filename to avoid collisions
    file_extension = os.path.splitext(uploaded_file.name)[1]
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = os.path.join("uploads", unique_filename)
    
    # Save the file
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    # Return the file path and content type
    return file_path, uploaded_file.type

def extract_text_from_file(file_path: str) -> str:
    """
    Extract text from various file types
    
    Args:
        file_path: Path to the file
        
    Returns:
        str: Extracted text
    """
    try:
        file_extension = os.path.splitext(file_path)[1].lower()
        
        # PDF files
        if file_extension == '.pdf':
            return extract_text_from_pdf(file_path)
        
        # Word documents
        elif file_extension in ['.docx', '.doc']:
            return extract_text_from_docx(file_path)
        
        # Text files
        elif file_extension in ['.txt', '.csv', '.md']:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        
        else:
            return f"Unsupported file type: {file_extension}"
    
    except Exception as e:
        return f"Error extracting text: {str(e)}"

def extract_text_from_pdf(file_path: str) -> str:
    """Extract text from a PDF file"""
    text = ""
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                text += page.extract_text() + "\n\n"
        return text
    except Exception as e:
        return f"Error extracting text from PDF: {str(e)}"

def extract_text_from_docx(file_path: str) -> str:
    """Extract text from a Word document"""
    try:
        doc = docx.Document(file_path)
        full_text = [paragraph.text for paragraph in doc.paragraphs]
        return '\n'.join(full_text)
    except Exception as e:
        return f"Error extracting text from Word document: {str(e)}"

def get_document_type(filename: str) -> str:
    """
    Guess the document type based on the filename
    
    Args:
        filename: The name of the file
        
    Returns:
        str: Guessed document type
    """
    lower_name = filename.lower()
    
    if any(term in lower_name for term in ['lab', 'test', 'result']):
        return "lab_report"
    
    elif any(term in lower_name for term in ['prescription', 'rx', 'medication']):
        return "prescription"
    
    elif any(term in lower_name for term in ['discharge', 'summary']):
        return "discharge_summary"
    
    elif any(term in lower_name for term in ['history', 'physical', 'exam']):
        return "medical_history"
    
    else:
        return "medical_record"  # Default type
        
def get_file_for_download(file_path: str) -> Optional[Tuple[bytes, str, str]]:
    """
    Get file content for download
    
    Args:
        file_path: Path to the file
        
    Returns:
        Tuple[bytes, str, str]: (file_bytes, mimetype, filename) or None if file not found
    """
    if not os.path.exists(file_path):
        return None
        
    # Get the file content
    try:
        with open(file_path, 'rb') as file:
            file_bytes = file.read()
            
        # Get the filename and mimetype
        filename = os.path.basename(file_path)
        mimetype = mimetypes.guess_type(file_path)[0]
        if mimetype is None:
            # Default to binary if mimetype cannot be determined
            mimetype = 'application/octet-stream'
            
        return (file_bytes, mimetype, filename)
    except Exception as e:
        logging.error(f"Error reading file for download: {e}")
        return None

def create_download_link(file_path: str) -> Optional[str]:
    """
    Create a base64-encoded download link for a file
    
    Args:
        file_path: Path to the file
        
    Returns:
        str: HTML download link or None if file not found
    """
    file_data = get_file_for_download(file_path)
    if not file_data:
        return None
        
    file_bytes, mimetype, filename = file_data
    
    # Create base64 encoded version of the file
    b64 = base64.b64encode(file_bytes).decode()
    
    # Create the download link HTML
    href = f'data:{mimetype};base64,{b64}'
    return f'<a href="{href}" download="{filename}" target="_blank">Download {filename}</a>'
