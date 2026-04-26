import os
from typing import List

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.config import Config


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]


class ChatResponse(BaseModel):
    reply: str


router = APIRouter(
    prefix="/api/agent",
    tags=["agent"],
    responses={404: {"description": "Not found"}},
)


async def call_deepseek(messages: List[ChatMessage]) -> str:
    api_key = Config.DEEPSEEK_API_KEY or os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="DeepSeek API key is not configured",
        )
    base_url = Config.DEEPSEEK_API_BASE
    model = Config.DEEPSEEK_MODEL
    url = f"{base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "你是一个智能客服助手，负责为用户解答本文件管理系统的使用问题，并以简洁的中文回答。"},
            *[{"role": m.role, "content": m.content} for m in messages],
        ],
        "stream": False,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.post(url, json=payload, headers=headers)
        except httpx.RequestError:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="无法连接到 DeepSeek 服务",
            )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="DeepSeek 服务返回错误",
        )
    data = response.json()
    choices = data.get("choices")
    if not choices:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="DeepSeek 返回了空响应",
        )
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not content:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="DeepSeek 响应中缺少内容",
        )
    return content


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    if not request.messages:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="messages 不能为空",
        )
    reply = await call_deepseek(request.messages)
    return ChatResponse(reply=reply)

