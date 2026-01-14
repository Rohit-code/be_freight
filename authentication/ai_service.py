"""
AI Service for OpenAI integration
"""
from decouple import config
from openai import OpenAI
from typing import Optional, List, Dict, Any

# Initialize OpenAI client
openai_api_key = config('OPENAI_API_KEY', default='')
client = OpenAI(api_key=openai_api_key) if openai_api_key else None


def is_ai_available() -> bool:
    """Check if OpenAI API is configured"""
    return client is not None and openai_api_key != ''


def chat_completion(messages: List[Dict[str, str]], model: str = "gpt-4o-mini", temperature: float = 0.7) -> Optional[str]:
    """
    Send a chat completion request to OpenAI
    
    Args:
        messages: List of message dictionaries with 'role' and 'content' keys
        model: Model to use (default: gpt-4o-mini)
        temperature: Sampling temperature (default: 0.7)
    
    Returns:
        Response text or None if error
    """
    if not is_ai_available():
        raise ValueError('OpenAI API key not configured')
    
    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[ERROR] OpenAI chat_completion: {str(e)}")
        raise


def summarize_text(text: str, max_length: int = 200) -> str:
    """
    Summarize a given text using AI
    
    Args:
        text: Text to summarize
        max_length: Maximum length of summary
    
    Returns:
        Summarized text
    """
    prompt = f"""Please provide a concise summary of the following text in approximately {max_length} words:

{text}

Summary:"""
    
    messages = [
        {"role": "system", "content": "You are a helpful assistant that provides concise summaries."},
        {"role": "user", "content": prompt}
    ]
    
    return chat_completion(messages, temperature=0.3) or "Unable to generate summary"


def analyze_email(email_content: str, subject: str = "", from_sender: str = "") -> Dict[str, Any]:
    """
    Analyze an email and extract key information
    
    Args:
        email_content: Email body/content
        subject: Email subject
        from_sender: Sender email address
    
    Returns:
        Dictionary with analysis results
    """
    full_email = f"Subject: {subject}\nFrom: {from_sender}\n\n{email_content}"
    
    prompt = f"""Analyze the following email and provide:
1. A brief summary (2-3 sentences)
2. Key points or action items
3. Sentiment (positive, neutral, or negative)
4. Priority level (high, medium, or low)
5. Suggested response (if applicable)

Email:
{full_email}

Please format your response as JSON with keys: summary, keyPoints, sentiment, priority, suggestedResponse"""
    
    messages = [
        {"role": "system", "content": "You are an email analysis assistant. Always respond with valid JSON."},
        {"role": "user", "content": prompt}
    ]
    
    try:
        response = chat_completion(messages, temperature=0.3)
        if response:
            import json
            return json.loads(response)
    except Exception as e:
        print(f"[ERROR] analyze_email: {str(e)}")
    
    return {
        "summary": summarize_text(email_content, 100),
        "keyPoints": [],
        "sentiment": "neutral",
        "priority": "medium",
        "suggestedResponse": ""
    }


def generate_email_response(email_content: str, subject: str = "", tone: str = "professional") -> str:
    """
    Generate a response to an email
    
    Args:
        email_content: Original email content
        subject: Email subject
        tone: Response tone (professional, friendly, formal, casual)
    
    Returns:
        Generated email response
    """
    prompt = f"""Write a {tone} email response to the following email:

Subject: {subject}

{email_content}

Response:"""
    
    messages = [
        {"role": "system", "content": f"You are a helpful assistant that writes {tone} email responses."},
        {"role": "user", "content": prompt}
    ]
    
    return chat_completion(messages, temperature=0.7) or "Unable to generate response"


def analyze_spreadsheet_data(data: List[List[str]], context: str = "") -> Dict[str, Any]:
    """
    Analyze spreadsheet data and provide insights
    
    Args:
        data: List of rows, each row is a list of cell values
        context: Optional context about the spreadsheet
    
    Returns:
        Dictionary with analysis results
    """
    # Convert data to readable format
    data_text = "\n".join(["\t".join(row) for row in data[:50]])  # Limit to first 50 rows
    
    prompt = f"""Analyze the following spreadsheet data and provide:
1. A brief overview of what the data represents
2. Key insights or patterns
3. Notable trends or anomalies
4. Recommendations (if applicable)

{context}

Data:
{data_text}

Please format your response as JSON with keys: overview, insights, trends, recommendations"""
    
    messages = [
        {"role": "system", "content": "You are a data analysis assistant. Always respond with valid JSON."},
        {"role": "user", "content": prompt}
    ]
    
    try:
        response = chat_completion(messages, temperature=0.3)
        if response:
            import json
            return json.loads(response)
    except Exception as e:
        print(f"[ERROR] analyze_spreadsheet_data: {str(e)}")
    
    return {
        "overview": "Data analysis unavailable",
        "insights": [],
        "trends": [],
        "recommendations": []
    }


def analyze_document(content: str, title: str = "") -> Dict[str, Any]:
    """
    Analyze a document and extract key information
    
    Args:
        content: Document content
        title: Document title
    
    Returns:
        Dictionary with analysis results
    """
    full_doc = f"Title: {title}\n\n{content[:5000]}"  # Limit content length
    
    prompt = f"""Analyze the following document and provide:
1. A brief summary
2. Main topics or themes
3. Key points
4. Action items (if any)

Document:
{full_doc}

Please format your response as JSON with keys: summary, topics, keyPoints, actionItems"""
    
    messages = [
        {"role": "system", "content": "You are a document analysis assistant. Always respond with valid JSON."},
        {"role": "user", "content": prompt}
    ]
    
    try:
        response = chat_completion(messages, temperature=0.3)
        if response:
            import json
            return json.loads(response)
    except Exception as e:
        print(f"[ERROR] analyze_document: {str(e)}")
    
    return {
        "summary": summarize_text(content, 150),
        "topics": [],
        "keyPoints": [],
        "actionItems": []
    }


def general_chat(message: str, conversation_history: List[Dict[str, str]] = None) -> str:
    """
    General chat completion
    
    Args:
        message: User message
        conversation_history: Optional conversation history
    
    Returns:
        AI response
    """
    messages = [
        {"role": "system", "content": "You are a helpful AI assistant integrated into a freight forwarding application. You can help with emails, documents, spreadsheets, and general questions."}
    ]
    
    if conversation_history:
        messages.extend(conversation_history)
    
    messages.append({"role": "user", "content": message})
    
    return chat_completion(messages) or "I'm sorry, I couldn't process your request."
