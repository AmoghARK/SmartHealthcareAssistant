# Healthcare AI Assistant

A Streamlit-based healthcare assistant with AI-powered medical consultation capabilities, user authentication, and chat history persistence.

![Healthcare AI Assistant](generated-icon.png)

## Overview

The Healthcare AI Assistant is a web application designed to provide medical information and assistance through an AI-powered chat interface. It leverages the Groq API to generate responses to healthcare-related queries, with full user authentication, session management, and chat history tracking.

## Features

### User Authentication and Management
- User registration with password strength validation
- Secure login system with session management
- User profile viewing and password update capabilities
- Session timeout for security

### AI Chat Interface
- Integration with Groq API for intelligent responses
- Multiple AI model selection (llama3-70b-8192, mixtral-8x7b-32768, gemma-7b-it)
- Adjustable temperature settings for response creativity
- Persistent chat history

### Security Features
- Secure password storage with bcrypt hashing
- Rate limiting to prevent API abuse
- Session expiration for inactive users
- Database-backed user authentication

### UI/UX
- Clean, intuitive interface
- Visual password strength indicator
- Real-time session timer
- Rate limit usage visualization

## Technical Stack

- **Frontend**: Streamlit
- **Database**: PostgreSQL with SQLAlchemy ORM (or SQLite for local development)
- **AI**: Groq API
- **Security**: bcrypt password hashing
- **Configuration**: python-dotenv for environment management

## Installation and Setup

### Running Locally

1. **Install Python Dependencies**:
   ```bash
   pip install -r deployable_requirements.txt
   ```

2. **Set up Environment Variables**:
   Create a `.env` file in the root directory with:
   ```
   GROQ_API_KEY=your_groq_api_key
   DATABASE_URL=sqlite:///chatbot.db
   ```
   - Get a Groq API key from [Groq's website](https://console.groq.com/)
   - For local development, SQLite is recommended for simplicity

3. **Run the Application**:
   ```bash
   streamlit run app.py
   ```

4. **Access the Application**:
   Open your browser and go to `http://localhost:8501`

### Required Files

Make sure you have these essential files:

- **Python Files**:
  - `app.py` - Main application
  - `components.py` - UI components
  - `database.py` - Database models and management
  - `model_handler.py` - AI model handling
  - `password_validator.py` - Password validation
  - `styles.py` - Custom UI styles
  - `utils.py` - Utility functions
  
- **Configuration Files**:
  - `config.json` - Application configuration
  - `generated-icon.png` - Application icon
  - `.env` - Environment variables (you must create this)

### Running on Replit

1. Create a new Replit or fork/clone this repository
2. Make sure to set the following secrets:
   - `GROQ_API_KEY` - Your Groq API key
   - Other database-related secrets will be automatically configured by Replit
3. Run the Replit - it will use the PostgreSQL database provided by Replit

## Usage

### Registration and Login
1. Navigate to the application URL
2. Click on the "Register" tab and create an account
3. Use your credentials to log in

### Chatting with the AI Assistant
1. Type your healthcare-related question in the chat input
2. Receive AI-generated responses based on your queries
3. Adjust model settings in the sidebar for different response styles

### User Profile Management
1. View your profile information via the User Profile expander
2. Change your password through the profile section
3. Monitor your API usage via the rate limit indicator

## Database Schema

The application uses the following data models:
- **User**: Stores user credentials and account information
- **Session**: Manages active user sessions
- **RateLimit**: Tracks API request limits per user
- **ChatHistory**: Stores conversation history

## Production Deployment

The application can be deployed on any platform that supports Python applications:

1. **Using Render**:
   - A sample configuration is included in the `render.yaml` file
   - Create the necessary environment variables in your Render dashboard
   - Point Render to your repository for automatic deployments

2. **Other Hosting Options**:
   - Heroku: Use a Procfile with `web: streamlit run app.py --server.port=$PORT --server.address=0.0.0.0`
   - Docker: Create a Dockerfile based on a Python image and install dependencies from deployable_requirements.txt

## Troubleshooting

- **API Key Issues**: Ensure your Groq API key is valid and properly set in your environment
- **Database Errors**: Check your DATABASE_URL format and ensure the database exists
- **Connection Issues**: For local development, check that port 8501 is not in use
- **Model Errors**: Verify that the selected model is available through your Groq API subscription

## Future Enhancements

- Integration with specialized healthcare models
- Document upload for medical record analysis
- Export functionality for chat histories
- Enhanced visualization of medical information

## License

MIT License

## Acknowledgements

- Groq for providing the AI models API
- Streamlit for the web application framework