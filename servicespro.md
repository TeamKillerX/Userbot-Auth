# Services Pro AI Text Generation API

## Product Description

**Services Pro** is a production-grade AI API service provided by Ryzenth, designed for text generation, recommendations, and language processing. This service is optimized for developers and systems that require stable, controlled, and scalable AI access.

The API is currently available under **Services Pro infrastructure** and uses API key–based authentication. Each product grants **30-day API access**, suitable for application integration, automation, and backend services.

Service status & maintenance:
`https://services-pro.ryzenths.dpdns.org`

Product reference:
https://finework.id/product/ai-kimi-custom-api-key

Optional integration:
- **Userbot-Auth (Free rate limit, optional)**
- Activation requires contacting support
`https://ubt.ryzenths.dpdns.org`

---

## API Overview

Base URL: `https://services-pro.ryzenths.dpdns.org`

Endpoint

**POST:** `/api/text/generate`

Authentication

x-api-key: `fw_live_xxxxx`


---

## Request Format

The API accepts a JSON payload with a `messages` array, similar to chat-based AI models.

Example payload:
```json
{
  "messages": [
    { "role": "user", "content": "Hello world" }
  ]
}
```

---

## Python Example
```py
import requests

payload = {
    "messages": [
        {"role": "user", "content": "Hello world"}
    ]
}

headers = {
    "x-api-key": "fw_live_xxxxx"
}

resp = requests.post(
    "https://services-pro.ryzenths.dpdns.org/api/text/generate",
    json=payload,
    headers=headers
)

print(resp.json())
```

---

## JavaScript Example (Node.js / Fetch)
```js
const payload = {
  messages: [
    { role: "user", content: "Hello World" }
  ]
};

fetch("https://services-pro.ryzenths.dpdns.org/api/text/generate", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": "fw_live_xxxxx"
  },
  body: JSON.stringify(payload)
})
  .then(res => res.json())
  .then(data => console.log(data))
  .catch(err => console.error(err));
```

---

## Usage Notes
- API keys are valid for **30 days** from activation.
- Rate limits may vary depending on service configuration.
- Userbot-Auth is **optional** and disabled by default.
- Do not expose your API key publicly.

---

## Intended Use
This service is intended for:
- AI text generation
- Content recommendation systems
- Automation workflows
- Backend AI integration
- Developer tools and SaaS platforms
