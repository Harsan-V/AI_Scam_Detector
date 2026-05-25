const API_BASE_URL = "http://127.0.0.1:5001";
const API_URL = `${API_BASE_URL}/predict`;

const messageInput = document.getElementById("message");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const statusText = document.getElementById("status");
const scoreCircle = document.getElementById("scoreCircle");
const scoreValue = document.getElementById("scoreValue");
const prediction = document.getElementById("prediction");
const analysisEngine = document.getElementById("analysisEngine");
const explanation = document.getElementById("explanation");
const phrasesList = document.getElementById("phrasesList");
const urlsList = document.getElementById("urlsList");
const patternsList = document.getElementById("patternsList");
const riskLevel = document.getElementById("riskLevel");
const sampleStatus = document.getElementById("sampleStatus");
const sampleList = document.getElementById("sampleList");

function setList(element, items, formatter) {
  element.innerHTML = "";

  if (!items || items.length === 0) {
    const li = document.createElement("li");
    li.textContent = "None found";
    element.appendChild(li);
    return;
  }

  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = formatter ? formatter(item) : item;
    element.appendChild(li);
  });
}

function updateScore(score, level) {
  const percentage = `${score}%`;
  scoreValue.textContent = score;
  scoreCircle.style.setProperty("--score", percentage);
  scoreCircle.classList.remove("low", "medium", "high");

  if (level === "High") {
    scoreCircle.classList.add("high");
  } else if (level === "Medium") {
    scoreCircle.classList.add("medium");
  } else {
    scoreCircle.classList.add("low");
  }
}

function renderSamples(samples) {
  sampleList.innerHTML = "";

  if (!samples || samples.length === 0) {
    return;
  }

  samples.forEach((sample) => {
    const item = document.createElement("article");
    item.className = "sample-item";

    const message = document.createElement("p");
    message.className = "sample-message";
    message.textContent = sample.message;

    const result = document.createElement("p");
    result.className = `sample-result ${sample.risk_level.toLowerCase()}`;
    result.textContent = `${sample.prediction} - ${sample.risk_level} Risk - ${sample.scam_score}/100`;

    item.append(message, result);
    sampleList.appendChild(item);
  });
}

async function loadLocalSamples(reason) {
  sampleStatus.textContent = reason;

  try {
    const response = await fetch(`${API_BASE_URL}/samples`);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Could not load local ML samples");
    }

    sampleStatus.textContent = "LLM is unavailable, so these test samples are predicted by the trained local ML model.";
    renderSamples(data.samples);
  } catch (error) {
    sampleStatus.textContent = `Local ML samples unavailable: ${error.message}`;
    renderSamples([]);
  }
}

async function analyzeMessage() {
  const message = messageInput.value.trim();

  if (!message) {
    statusText.textContent = "Please paste a message first.";
    statusText.classList.add("error");
    return;
  }

  statusText.textContent = "Analyzing message...";
  statusText.classList.remove("error");
  analyzeBtn.disabled = true;

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Backend request failed");
    }

    updateScore(data.scam_score, data.risk_level);
    prediction.textContent = `${data.prediction} (${data.risk_level} Risk)`;
    analysisEngine.textContent = `Engine: ${data.analysis_engine || "Unknown"}`;
    explanation.textContent = data.explanation;
    if (data.llm_error) {
      explanation.textContent += " The LLM could not be used, so the local ML model handled this prediction.";
      loadLocalSamples("Loading trained local ML test samples...");
    }
    riskLevel.textContent = `Risk Level: ${data.risk_level}. Scam Score: ${data.scam_score}/100.`;

    setList(phrasesList, data.suspicious_phrases);
    setList(urlsList, data.url_analysis, (item) => {
      return `${item.url} - ${item.reasons.join(", ")}`;
    });
    setList(patternsList, data.fraud_patterns, (item) => {
      return `${item.pattern}: ${item.matched_keywords.join(", ")}`;
    });

    statusText.textContent = "Analysis complete.";
  } catch (error) {
    statusText.textContent = `Error: ${error.message}. Make sure Flask is running on http://127.0.0.1:5001`;
    statusText.classList.add("error");
  } finally {
    analyzeBtn.disabled = false;
  }
}

analyzeBtn.addEventListener("click", analyzeMessage);

clearBtn.addEventListener("click", () => {
  messageInput.value = "";
  scoreValue.textContent = "--";
  prediction.textContent = "Not analyzed yet";
  analysisEngine.textContent = "Engine: not selected";
  explanation.textContent = "Paste a message and click Analyze Message.";
  riskLevel.textContent = "Risk level will appear here.";
  setList(phrasesList, []);
  setList(urlsList, []);
  setList(patternsList, []);
  sampleStatus.textContent = "Samples appear here when the LLM is unavailable.";
  renderSamples([]);
  statusText.textContent = "Cleared.";
  statusText.classList.remove("error");
});

async function checkLlmStatus() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    const data = await response.json();

    if (response.ok && !data.llm_enabled) {
      loadLocalSamples("No LLM API key found. Loading trained local ML test samples...");
    }
  } catch (error) {
    sampleStatus.textContent = "Start Flask on http://127.0.0.1:5001 to load local ML samples.";
  }
}

checkLlmStatus();
