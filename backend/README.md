# AI Scam Detector Backend with GroqCloud LLM

This Flask API loads the ML model from:

```text
../models/scam_detector_model.pkl
```

It can also use GroqCloud through the Groq API when `GROQ_API_KEY` is set. If the key is missing or the API call fails, the backend falls back to the local ML model.

## Run

```powershell
cd D:\OTHERS\internship_geakminds\day5\Mini_project\backend
python app.py
```

For the LLM version:

```powershell
cd D:\OTHERS\internship_geakminds\day5\mini_project_llm\backend
copy .env.example .env
notepad .env
python app.py
```

Inside `.env`, set:

```env
GROQ_API_KEY=your_groq_gsk_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile
```

The LLM backend runs on:

```text
http://127.0.0.1:5001
```

## Test

Open:

```text
http://127.0.0.1:5001/
```

POST prediction requests to:

```text
http://127.0.0.1:5001/predict
```

Example JSON body:

```json
{
  "message": "Urgent! Your account is blocked. Verify OTP now at http://fake-bank-login.com"
}
```

Example response:

```json
{
  "prediction": "Scam",
  "scam_score": 86.4,
  "risk_level": "High",
  "suspicious_phrases": ["urgent", "blocked", "otp"],
  "urls_detected": ["http://fake-bank-login.com"],
  "url_analysis": [
    {
      "url": "http://fake-bank-login.com",
      "reasons": ["URL is not explicitly HTTPS"]
    }
  ],
  "fraud_patterns": [],
  "explanation": "..."
}
```
