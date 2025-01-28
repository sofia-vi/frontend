from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import uvicorn

app = FastAPI()

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Example route
@app.get("/api/test")
async def test():
    return {"message": "Python backend is working!"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)