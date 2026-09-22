"""
Main Entry Point to launch FastAPI Gateway Server.
"""
import uvicorn
from gateway.api import app

if __name__ == "__main__":
    uvicorn.run("gateway.api:app", host="127.0.0.1", port=8000, reload=True)
