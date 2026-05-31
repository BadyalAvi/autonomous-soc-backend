import os
import requests
import socket
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from langchain_core.tools import tool
from langchain.agents import create_agent
from dotenv import load_dotenv

# 1. API Keys
load_dotenv()
google_api_key = os.getenv("GOOGLE_API_KEY")
abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")

if not google_api_key or not abuseipdb_api_key:
    raise ValueError("Missing API Keys in .env file.")

os.environ["GOOGLE_API_KEY"] = google_api_key
ABUSEIPDB_API_KEY = abuseipdb_api_key

# 2. Define the Tools
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

@tool
def resolve_domain_to_ip(domain: str) -> str:
    """Resolves a domain name or URL to an IPv4 address. Use this FIRST if the user provides a website link or domain name."""
    print(f"\n[Agent is resolving domain: {domain}...]")
    try:
        # Strip out https:// or http:// if the user included it
        if "://" in domain:
            domain = urlparse(domain).netloc
        
        # Get the IP address
        ip = socket.gethostbyname(domain)
        return f"The IP address for {domain} is {ip}"
    except Exception as e:
        return f"Error resolving domain {domain}: {str(e)}"

# 3. Initialize the AI Brain with Multiple Tools
tools = [check_ip_threat_intel, resolve_domain_to_ip]

system_prompt = """You are a senior Security Operations Center (SOC) analyst. 
You have access to tools for threat intelligence.
- If the user provides an IPv4 address, use the `check_ip_threat_intel` tool directly.
- If the user provides a Domain or URL, FIRST use the `resolve_domain_to_ip` tool to find its IP address. THEN, use the `check_ip_threat_intel` tool on that newly discovered IP.

Extract the 'abuseConfidenceScore', 'usageType', and 'domain' from the AbuseIPDB JSON data.
If the score is 0, declare the target SAFE. 
If the score is above 0, declare the target MALICIOUS and explain the risk.
Always output a final, concise recommendation formatted cleanly using Markdown."""

# Note: Using 1.5-flash to avoid Free Tier Rate Limits
agent_executor = create_agent(
    model="google_genai:gemini-2.5-flash", 
    tools=tools, 
    system_prompt=system_prompt
)

# 4. FASTAPI SERVER SETUP
app = FastAPI(title="Autonomous SOC API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,  
    allow_methods=["*"],  
    allow_headers=["*"],  
)

# NEW: Changed 'ip_address' to 'target' to accept both URLs and IPs
class ThreatRequest(BaseModel):
    target: str

@app.post("/api/scan")
async def scan_target(request: ThreatRequest):
    print(f"--- Incoming Request from Mobile App for Target: {request.target} ---")
    try:
        user_query = f"Please check {request.target} and give me a security recommendation."
        response = agent_executor.invoke({"messages": [("user", user_query)]})
        
        final_message = response["messages"][-1].content
        if isinstance(final_message, list):
            clean_text = final_message[0].get("text", final_message[0])
        else:
            clean_text = final_message
            
        return {
            "status": "success", 
            "target_scanned": request.target,
            "report": clean_text
        }
    except Exception as e:
        import traceback
        print("\n--- CRITICAL BACKEND ERROR ---")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))