from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
load_dotenv()
llm = ChatGoogleGenerativeAI(model="gemini-3.5-flash-lite")
r = llm.invoke("Reply with the single word: ready")
print("RESPONSE:", repr(r.content))
