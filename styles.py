# styles.py
import streamlit as st

def apply_custom_styles():
    """Apply custom styles to the Streamlit app"""
    
    # General styles
    st.markdown("""
    <style>
        .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        
        /* Chat container styles */
        .chat-container {
            border-radius: 10px;
            margin-bottom: 10px;
            padding: 10px;
        }
        
        /* Strength indicator */
        .strength-meter {
            height: 8px;
            border-radius: 4px;
            transition: all 0.3s;
            margin: 5px 0;
        }
        
        /* Message styles */
        .message-container {
            max-width: 80%;
            padding: 10px 15px;
            border-radius: 15px;
            margin-bottom: 10px;
        }
        
        /* Rate limit indicator */
        .rate-limit-container {
            margin: 10px 0;
        }
        
        .rate-limit-bar {
            height: 8px;
            border-radius: 4px;
            background-color: #f0f0f0;
            margin-top: 5px;
        }
        
        .rate-limit-progress {
            height: 100%;
            border-radius: 4px;
            background-color: #4CAF50;
        }
        
        /* Profile section */
        .profile-section {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
        }
        
        /* Form styles */
        .form-container {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
        }
    </style>
    """, unsafe_allow_html=True)
