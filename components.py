# components.py
import streamlit as st
import time
from datetime import datetime

def session_timer():
    """Display a session timer component"""
    if "session_start_time" not in st.session_state:
        st.session_state.session_start_time = time.time()
        
    elapsed_time = time.time() - st.session_state.session_start_time
    remaining_time = max(0, 3600 - elapsed_time)  # Default session timeout 1 hour
    
    minutes = int(remaining_time // 60)
    seconds = int(remaining_time % 60)
    
    if minutes < 5:
        st.warning(f"Session expires in {minutes:02d}:{seconds:02d}")
    else:
        st.info(f"Session time: {minutes:02d}:{seconds:02d}")
    
    # Auto refresh every 60 seconds to update the timer
    if elapsed_time > 3600:
        st.warning("Your session has expired. Please log in again.")
        # Clear session state
        st.session_state.user_id = None
        st.session_state.session_id = None
        st.rerun()

def rate_limit_indicator(db, user_id, limit=10):
    """Display a rate limit indicator"""
    if not user_id:
        return
    
    request_count = 0
    try:
        # Safe approach to prevent connection issues
        with db._get_session() as session:
            if not session:
                # If session is None (database not available)
                return
                
            try:
                # Query the rate limit using SQLAlchemy
                from database import RateLimit
                rate_limit = session.query(RateLimit).filter_by(user_id=user_id).first()
                
                if rate_limit:
                    # Check if the last request was made in the current minute
                    last_request_time = rate_limit.last_request
                    time_diff = (datetime.now() - last_request_time).total_seconds()
                    if time_diff <= 60:  # Within the rate limit window (1 minute)
                        request_count = rate_limit.request_count
            except Exception as e:
                print(f"Error querying rate limit: {e}")
    except Exception as e:
        # Fallback in case of connection error
        print(f"Error accessing rate limit data: {e}")
        request_count = 0
    
    st.markdown(f"<div class='rate-limit-container'>API Requests: {request_count}/{limit}</div>", unsafe_allow_html=True)
    
    # Calculate percentage
    percentage = (request_count / limit) * 100
    
    # Determine color based on usage
    color = "#4CAF50"  # Green
    if percentage > 70:
        color = "#FFC107"  # Yellow
    if percentage > 90:
        color = "#F44336"  # Red
    
    st.markdown(f"""
    <div class='rate-limit-bar'>
        <div class='rate-limit-progress' style='width: {percentage}%; background-color: {color};'></div>
    </div>
    """, unsafe_allow_html=True)

def password_strength_meter(strength, color):
    """Display a password strength meter"""
    st.markdown(f"""
    <div style='margin-bottom: 10px;'>
        <div style='font-size: 0.8rem;'>Password Strength</div>
        <div class='strength-meter' style='width: {strength}%; background-color: {color};'></div>
    </div>
    """, unsafe_allow_html=True)

def format_timestamp(timestamp):
    """Format timestamp (string or datetime) to human-readable format"""
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.split('.')[0])
        elif isinstance(timestamp, datetime):
            dt = timestamp
        else:
            return str(timestamp)
            
        return dt.strftime("%b %d, %Y %I:%M %p")
    except Exception as e:
        print(f"Error formatting timestamp: {e}")
        return str(timestamp)
