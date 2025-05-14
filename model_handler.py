# model_handler.py (Model Interaction Layer)
from groq import Groq
import streamlit as st

class GroqModelHandler:
    def __init__(self, client):
        self.client = client
    
    def generate(self, prompt, model_name, temperature, max_tokens, stream=True):
        full_response = ""
        message_placeholder = st.empty()
        
        try:
            response = self.client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                stream=stream
            )

            if stream:
                for chunk in response:
                    if chunk.choices[0].delta.content:
                        full_response += chunk.choices[0].delta.content
                        message_placeholder.markdown(full_response + "▌")
                message_placeholder.markdown(full_response)
            else:
                full_response = response.choices[0].message.content
                message_placeholder.markdown(full_response)
                
            return full_response
        
        except Exception as e:
            st.error(f"Model Error: {str(e)}")
            raise RuntimeError(f"Model Error: {str(e)}")
            
    def analyze_document(self, document_text, document_type="medical_record", model_name="llama3-70b-8192"):
        """
        Analyze a document using the Groq API
        
        Args:
            document_text (str): The text content of the document
            document_type (str): Type of document (medical_record, prescription, lab_report, etc.)
            model_name (str): The model to use for analysis
            
        Returns:
            str: Analysis of the document
        """
        try:
            prompt = f"""You are an expert healthcare AI assistant. Please analyze the following {document_type}. 
            Provide a structured analysis including:
            
            1. Document Summary: Brief overview of what this document contains
            2. Key Findings: Any significant medical observations or test results
            3. Medical Terminology Explanation: Define any complex medical terms in simple language
            4. Potential Concerns: Highlight any values or findings that may need attention
            5. Follow-up Recommendations: What should be the next steps based on this document
            
            Important: If this doesn't appear to be a {document_type}, please note that and explain what it seems to be instead.
            Also note that this is an AI analysis and not medical advice. The patient should consult healthcare professionals for proper diagnosis and treatment.
            
            Document:
            ```
            {document_text}
            ```
            """
            
            # Get analysis without streaming for documents (using a non-streaming approach)
            response = self.client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,  # Lower temperature for more factual responses
                max_tokens=2048,
                stream=False
            )
            return response.choices[0].message.content
        except Exception as e:
            error_msg = f"Error analyzing document: {str(e)}"
            st.error(error_msg)
            return error_msg
