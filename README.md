# Enterprise AI Gateway

A secure, high-performance, and scalable AI Gateway for routing requests to Gemini language models.

## Features

- **Dual Authentication**: Supports both robust OAuth2 JWT tokens for dynamic clients, and API Keys for service-to-service communication.
- **Secure Password Hashing**: Passwords are cryptographically hashed using `bcrypt` preventing plaintext exposure.
- **Robust Rate Limiting**: Powered by `slowapi` to protect against spam and denial-of-service, securely tracking requests.
- **LLM Prompt Auditor**: Employs `gemini-2.5-flash` as a gatekeeper to detect and reject jailbreak attempts and malicious prompts *before* they reach the core generation models.
- **Real-time Streaming**: Full streaming token support for long outputs, providing immediate responsiveness for end-users.
- **JSON Structured Logging**: Observability ready out-of-the-box. Logs are emitted in JSON format containing full request telemetry (latency, status codes, paths) suitable for ingestion into Splunk, Datadog, etc.

## Setup

1. **Environment Variables**: Create a `.env` file from the example or ensure you have configured:
   - `GEMINI_API_KEY`: Your Google Gemini API Key
   - `GATEWAY_API_KEY`: Static API key for M2M communication
   - `GATEWAY_USERNAME`: Admin username
   - `GATEWAY_PASSWORD`: Admin password
   - `SECRET_KEY`: A secure random string for JWT signing

2. **Dependencies**: 
   ```bash
   uv sync
   ```

3. **Run the Server**:
   ```bash
   uv run uvicorn main:app --reload --port 8000
   ```

## Usage

### 1. Retrieve a Token (OAuth2 flow)
```bash
curl -X POST "http://localhost:8000/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&password=secret"
```

### 2. Make a Chat Request
Using the token from above:
```bash
curl -X POST "http://localhost:8000/chat" \
     -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     -H "Content-Type: application/json" \
     -d '{"prompt": "Hello!", "model": "gemini-2.5-flash"}'
```

Or using an API key:
```bash
curl -X POST "http://localhost:8000/chat" \
     -H "X-API-Key: YOUR_GATEWAY_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"prompt": "Hello!", "model": "gemini-2.5-flash"}'
```
