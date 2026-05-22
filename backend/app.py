import os
import re
import sys
import json
import urllib.error
import urllib.request

import joblib
from flask import Flask, jsonify, request


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "scam_detector_model.pkl")
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BACKEND_DIR, ".env")


def load_env_file():
    if not os.path.exists(ENV_PATH):
        return

    with open(ENV_PATH, "r", encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ[key] = value


load_env_file()

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.getenv("GROQ_MODEL") or os.getenv("XAI_MODEL") or "llama-3.3-70b-versatile"
if GROQ_MODEL.startswith("grok-"):
    GROQ_MODEL = "llama-3.3-70b-versatile"

SUSPICIOUS_PHRASES = [
    "urgent",
    "immediately",
    "act now",
    "limited time",
    "last chance",
    "account locked",
    "account has been locked",
    "suspended",
    "blocked",
    "verify your identity",
    "otp",
    "password",
    "pin",
    "cvv",
    "bank details",
    "aadhaar",
    "card number",
    "registration fee",
    "refundable",
    "you have won",
    "lottery",
    "claim now",
    "free gift",
    "work from home",
    "selected",
]

FRAUD_PATTERNS = {
    "Urgency manipulation": [
        "urgent",
        "immediately",
        "act now",
        "limited time",
        "last chance",
        "today",
    ],
    "Account threat": [
        "account locked",
        "account has been locked",
        "suspended",
        "blocked",
        "verify your identity",
    ],
    "Sensitive information request": [
        "otp",
        "password",
        "pin",
        "cvv",
        "bank details",
        "aadhaar",
        "card number",
    ],
    "Money or fee request": [
        "pay",
        "fee",
        "registration fee",
        "refundable",
        "deposit",
        "gift card",
    ],
    "Reward or job bait": [
        "you have won",
        "lottery",
        "claim now",
        "free gift",
        "work from home",
        "selected",
    ],
}


app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " urltoken ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def load_model():
    if not os.path.exists(MODEL_PATH):
        return None

    setattr(sys.modules["__main__"], "clean_text", clean_text)
    bundle = joblib.load(MODEL_PATH)
    if isinstance(bundle, dict) and "model" in bundle:
        return bundle["model"]
    return bundle


model = load_model()


def detect_urls(text):
    url_pattern = r"\b(?:https?://)?(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?:/[^\s]*)?"
    return re.findall(url_pattern, text)


def url_risk_reasons(url):
    reasons = []
    lowered = url.lower()
    hostname = lowered.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]

    if not lowered.startswith("https://"):
        reasons.append("URL is not explicitly HTTPS")
    if any(shortener in lowered for shortener in ["bit.ly", "tinyurl", "t.co"]):
        reasons.append("Shortened URL hides the real destination")
    if re.search(r"\d", hostname.split(".")[0]):
        reasons.append("Domain contains numbers")
    if hostname.count(".") >= 3:
        reasons.append("URL uses a deep subdomain chain")
    if not reasons:
        reasons.append("No obvious URL red flags detected")

    return reasons


def find_suspicious_phrases(text):
    lowered = text.lower()
    return [phrase for phrase in SUSPICIOUS_PHRASES if phrase in lowered]


def analyze_fraud_patterns(text):
    lowered = text.lower()
    detected = []

    for pattern_name, keywords in FRAUD_PATTERNS.items():
        matched_keywords = [keyword for keyword in keywords if keyword in lowered]
        if matched_keywords:
            detected.append(
                {
                    "pattern": pattern_name,
                    "matched_keywords": matched_keywords,
                }
            )

    return detected


def risk_level_from_score(score):
    if score >= 75:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


def extract_json_from_text(text):
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.I).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()
    return json.loads(cleaned)


def call_groq_analysis(message):
    api_key = os.getenv("GROQ_API_KEY") or os.getenv("XAI_API_KEY")
    if not api_key:
        return None

    payload = {
        "model": GROQ_MODEL,
        "stream": False,
        "temperature": 0.1,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert cyber safety assistant for phishing, SMS scam, "
                    "WhatsApp scam, and social engineering detection. Return only valid JSON. "
                    "Do not include markdown. Do not ask follow-up questions."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Analyze this message for scam risk. Return JSON with exactly these keys: "
                    "prediction, scam_score, risk_level, suspicious_phrases, urls_detected, "
                    "url_analysis, fraud_patterns, explanation. "
                    "prediction must be Scam or Legitimate. scam_score must be a number from 0 to 100. "
                    "risk_level must be Low, Medium, or High. suspicious_phrases must be an array of strings. "
                    "urls_detected must be an array of strings. url_analysis must be an array of objects with url and reasons. "
                    "fraud_patterns must be an array of objects with pattern and matched_keywords. "
                    "explanation must be a short paragraph that explains the risk clearly.\n\n"
                    f"Message:\n{message}"
                ),
            },
        ],
    }

    api_request = urllib.request.Request(
        GROQ_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "AI-Scam-Detector-MiniProject/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(api_request, timeout=45) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        error_body = error.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Groq API error {error.code}: {error_body}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Groq API connection error: {error.reason}") from error

    content = response_data["choices"][0]["message"]["content"]
    groq_result = extract_json_from_text(content)
    groq_result["analysis_engine"] = f"GroqCloud LLM ({GROQ_MODEL})"
    return groq_result


def build_explanation(prediction, scam_score, patterns, urls):
    if prediction == "Scam":
        explanation = "The message looks risky because the ML model found scam-like wording."
    else:
        explanation = "The message looks mostly legitimate based on the current ML model."

    if patterns:
        explanation += " It also contains known fraud patterns such as " + ", ".join(
            pattern["pattern"] for pattern in patterns
        ) + "."

    if urls:
        explanation += " URL checks were included because links are common in phishing attempts."

    if scam_score >= 75:
        explanation += " Avoid clicking links or sharing personal details."
    elif scam_score >= 45:
        explanation += " Verify the sender through an official channel before taking action."
    else:
        explanation += " Still be careful with unexpected requests."

    return explanation


@app.get("/")
def home():
    return jsonify(
        {
            "message": "AI Scam Detector Backend is running",
            "model_loaded": model is not None,
            "llm_enabled": bool(os.getenv("GROQ_API_KEY") or os.getenv("XAI_API_KEY")),
            "llm_provider": "GroqCloud",
            "llm_model": GROQ_MODEL,
            "predict_endpoint": "/predict",
        }
    )


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "model_loaded": model is not None,
            "llm_enabled": bool(os.getenv("GROQ_API_KEY") or os.getenv("XAI_API_KEY")),
            "llm_provider": "GroqCloud",
            "llm_model": GROQ_MODEL,
        }
    )


@app.post("/predict")
def predict():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    llm_error = None

    if not message:
        return jsonify({"error": "Message is required"}), 400

    try:
        groq_result = call_groq_analysis(message)
        if groq_result:
            return jsonify(groq_result)
    except Exception as error:
        llm_error = str(error)
        if model is None:
            return jsonify({"error": str(error)}), 502

    if model is None:
        return jsonify(
            {
                "error": "Model file not found. Run scam_detector_ml.ipynb first to create models/scam_detector_model.pkl."
            }
        ), 500

    cleaned_message = clean_text(message)
    probability = float(model.predict_proba([cleaned_message])[0][1])
    scam_score = round(probability * 100, 2)
    prediction = "Scam" if probability >= 0.5 else "Legitimate"

    urls = detect_urls(message)
    url_analysis = [{"url": url, "reasons": url_risk_reasons(url)} for url in urls]
    suspicious_phrases = find_suspicious_phrases(message)
    fraud_patterns = analyze_fraud_patterns(message)
    risk_level = risk_level_from_score(scam_score)
    explanation = build_explanation(prediction, scam_score, fraud_patterns, urls)

    return jsonify(
        {
            "prediction": prediction,
            "scam_score": scam_score,
            "risk_level": risk_level,
            "suspicious_phrases": suspicious_phrases,
            "urls_detected": urls,
            "url_analysis": url_analysis,
            "fraud_patterns": fraud_patterns,
            "explanation": explanation,
            "analysis_engine": "Local ML fallback",
            "llm_error": llm_error,
        }
    )


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=int(os.getenv("PORT", "5001")))
