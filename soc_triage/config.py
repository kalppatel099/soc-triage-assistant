import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

MOCK_API_URL = os.getenv("MOCK_API_URL", "http://localhost:8000")


def get_llm(temperature: float = 0.0):
    """Create the Gemini chat model. Model name comes from .env."""
    return ChatGoogleGenerativeAI(
        model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite"),
        temperature=temperature,
    )


def text_of(message) -> str:
    """Return plain text from a model reply (handles the list-of-parts format)."""
    content = message.content
    if isinstance(content, str):
        return content
    return "".join(
        part.get("text", "") if isinstance(part, dict) else str(part)
        for part in content
    )