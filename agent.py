import os
import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from langchain_core.tools import tool
from langchain.agents import create_agent
from dotenv import load_dotenv # NEW: Import dotenv

# 1. API Keys (Now loaded securely from .env)
load_dotenv()

# Securely fetch the keys
google_api_key = os.getenv("GOOGLE_API_KEY")
abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")

# Safety checks to ensure the keys loaded correctly
if not google_api_key:
    raise ValueError("GOOGLE_API_KEY is missing. Check your .env file.")
if not abuseipdb_api_key:
    raise ValueError("ABUSEIPDB_API_KEY is missing. Check your .env file.")

os.environ["GOOGLE_API_KEY"] = google_api_key
ABUSEIPDB_API_KEY = abuseipdb_api_key

# 2. Define the Tool
@tool
def check_ip_threat_intel(ip_address: str) -> str:
    """Queries the AbuseIPDB API directly for real-time, dynamic IP threat intelligence."""
    print(f"\n[Agent is scanning IP: {ip_address}...]")
    
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}

    try:
        response = requests.get(url, headers=headers, params=querystring)
        return response.text
    except Exception as e:
        return f"Error connecting to AbuseIPDB API: {str(e)}"

# 3. Initialize the AI Brain
tools = [check_ip_threat_intel]
system_prompt = """You are a senior Security Operations Center (SOC) analyst. 
Your job is to use your tools to check IP threat intelligence. 
The tool will return raw JSON. You must carefully read this JSON.
Extract the 'abuseConfidenceScore', 'usageType', and 'domain' from the JSON data.
If the score is 0, declare the IP SAFE. 
If the score is above 0, declare the IP MALICIOUS and explain the risk based on the score.
Always output a final, concise recommendation formatted cleanly using Markdown."""

agent_executor = create_agent(
    model="google_genai:gemini-3.5-flash", 
    tools=tools, 
    system_prompt=system_prompt
)

# 4. FASTAPI SERVER SETUP
app = FastAPI(title="Autonomous SOC API")

# --- CORS MIDDLEWARE ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=False,  
    allow_methods=["*"],  
    allow_headers=["*"],  
)
# -----------------------

# Define the expected JSON payload from React Native
class ThreatRequest(BaseModel):
    ip_address: str

# Expose the POST endpoint
@app.post("/api/scan")
async def scan_ip(request: ThreatRequest):
    print(f"--- Incoming Request from Mobile App for IP: {request.ip_address} ---")
    try:
        user_query = f"Please check {request.ip_address} and give me a security recommendation."
        response = agent_executor.invoke({"messages": [("user", user_query)]})
        
        final_message = response["messages"][-1].content
        if isinstance(final_message, list):
            clean_text = final_message[0].get("text", final_message[0])
        else:
            clean_text = final_message
            
        return {
            "status": "success", 
            "ip_scanned": request.ip_address,
            "report": clean_text
        }
    except Exception as e:
        import traceback
        print("\n--- CRITICAL BACKEND ERROR ---")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))