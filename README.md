# 🛡️ PhishGuard AI
### AI-Powered Phishing URL Detection System

PhishGuard AI is a cybersecurity web application that uses Machine Learning to detect potentially malicious and phishing URLs. It helps users evaluate website links before visiting them by providing a prediction, risk score, and detection explanations.

## 🚀 Project Overview

Phishing attacks use fake websites and malicious links to trick users into revealing sensitive information such as passwords, personal details, and financial data.

PhishGuard AI aims to make URL security analysis easier by providing an intelligent system that analyzes submitted URLs and identifies potential phishing threats.

## ✨ Key Features

- **URL Detection:** Analyze pasted website URLs.
- **Risk Assessment:** Display a risk score for analyzed URLs.
- **URL Classification:** Classify links as Legitimate, Suspicious, or Phishing.
- **Explainable Results:** Provide reasons behind detection results.
- **User Authentication:** Secure registration and login.
- **Scan History:** Access previously analyzed URLs.
- **Dashboard:** View scanning activity and results.

## 🧠 Machine Learning Approach

The system uses a trained Machine Learning classification model to analyze URL patterns and predict whether a URL is potentially legitimate or malicious.

The model is trained using a labeled dataset containing phishing and legitimate URLs.

**Detection Workflow:**

1. Collect and prepare the URL dataset.
2. Train the Machine Learning model.
3. Extract and analyze URL characteristics.
4. Generate predictions for submitted URLs.
5. Display the classification and risk assessment.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming and ML |
| Machine Learning | URL classification |
| FastAPI | Backend API |
| HTML | Webpage structure |
| CSS | User interface styling |
| JavaScript | Frontend functionality |
| Firebase Authentication | User authentication |
| PostgreSQL (Neon) | Database storage |
| Joblib | Model serialization |

## ⚙️ System Architecture

**Frontend → FastAPI Backend → ML Model → Prediction → Result Display**

Firebase Authentication manages user access, while PostgreSQL stores application data and scan records.

## 💻 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/UmairALI512/PhishGuard-AI.git
```

### 2. Navigate to the Project

```bash
cd PhishGuard-Ai
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

### 4. Activate the Environment

Windows:

```bash
venv\Scripts\activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure Environment Variables

Configure the required Firebase and database environment variables before running the application.

Never upload private credentials, service account JSON files, or database connection strings to GitHub.

### 7. Run the Application

```bash
uvicorn main:app --reload
```

Open the local application URL shown in your terminal or configured for your frontend.

## 🎯 Project Objectives

- Improve awareness of phishing threats.
- Help users identify suspicious website links.
- Apply Machine Learning to a real-world cybersecurity problem.
- Provide understandable URL analysis results.

## 👨‍💻 Developer

**Umair Ali**

BS Information Technology  
Shaheed Benazir Bhutto University (SBBU), Nawabshah

**Roll Number:** 24BS(IT)-29

## ⚠️ Disclaimer

PhishGuard AI is an educational cybersecurity project. Its predictions are intended to assist users in identifying potentially malicious URLs and should not be considered a guarantee of website safety.

---

*Built with Python, Machine Learning, and Cybersecurity in mind. 🛡️*
