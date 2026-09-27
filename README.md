# 🛡️ INTRISENSE

### Intelligent Network Intrusion Detection, Attack Classification & Security Recommendation

<p align="center">
  <strong>Detect. Classify. Understand. Respond.</strong><br>
  A machine-learning framework for analyzing network traffic and identifying potentially malicious activity.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Streamlit-Web%20Interface-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" alt="Streamlit">
  <img src="https://img.shields.io/badge/Machine%20Learning-Random%20Forest-228B22?style=for-the-badge" alt="Random Forest">
  <img src="https://img.shields.io/badge/Dataset-UNSW--NB15-6A5ACD?style=for-the-badge" alt="UNSW-NB15">
</p>

---

## 🌐 Try INTRISENSE Online

**Live Application:** [Open INTRISENSE](https://intrisense.streamlit.app)

The online version allows users to upload compatible network-flow CSV files, analyze traffic records, view model predictions, and explore security recommendations.

> **Want to monitor traffic from your own Windows computer?** See the Windows Application section below.

---

## 🔍 What Is INTRISENSE?

INTRISENSE is a machine-learning-based network intrusion detection application. It analyzes network-flow information to identify normal and potentially malicious activity, classify supported attack categories, and provide security recommendations.

The application uses a trained **Random Forest model** and an interactive **Streamlit dashboard** to make network traffic analysis easier to understand.

INTRISENSE is available in two modes:

| Version                           | What it does                                                                                    |
| --------------------------------- | ----------------------------------------------------------------------------------------------- |
| ☁️ **Cloud Web Application**      | Analyzes uploaded CSV datasets through a browser.                                               |
| 🖥️ **Windows Local Application** | Runs on a Windows computer and includes live network packet capture and analysis functionality. |

Both versions use the project's machine-learning model and analysis components. The main difference is where the application runs and how network data is supplied.

---

## ⚙️ How INTRISENSE Works

INTRISENSE processes network information through a sequence of steps.

### 1. Network Data Input

The application receives network information in one of two ways:

* **Cloud version:** The user uploads a compatible CSV file containing network-flow records.
* **Windows version:** The application can capture packets from the local computer's network interface and prepare them for analysis.

### 2. Flow Processing and Feature Extraction

For live monitoring, captured packets are grouped into network flows. The application extracts flow-level features required by the trained model.

For CSV analysis, the uploaded data is checked and prepared using the project's preprocessing pipeline.

### 3. Machine-Learning Prediction

The prepared features are passed to the saved Random Forest model. The model predicts whether the traffic is normal or associated with a supported attack category.

### 4. Results and Security Recommendations

The application presents the analysis through the dashboard, including prediction results, confidence information, and relevant rule-based security recommendations.

### Workflow Overview

```text
                 NETWORK DATA
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
   CLOUD WEB APP           WINDOWS LOCAL APP
   Upload CSV              Capture Packets
          │                       │
          │                       ▼
          │                Build Network Flows
          │                       │
          │                       ▼
          │                Extract Flow Features
          │                       │
          └───────────┬───────────┘
                      │
                      ▼
             Input Validation &
              Preprocessing
                      │
                      ▼
             Random Forest Model
                      │
                      ▼
          Detection & Classification
                      │
                      ▼
          Confidence & Recommendations
                      │
                      ▼
             INTRISENSE Dashboard
```

---

## ☁️ Cloud Web Application

The cloud version is hosted using **Streamlit Community Cloud**.

### What can users do?

* Open the application through a web browser.
* Upload a compatible network-flow CSV file.
* Analyze records using the trained machine-learning model.
* View prediction results and confidence information.
* Explore attack classifications and security recommendations.
* Review available model-performance information.

### Why does the cloud version not capture my computer's packets?

The cloud application runs on a remote server. It does not run directly on the visitor's computer, so it cannot directly access that computer's local network interface for packet capture.

For live monitoring of a Windows computer, use the local Windows application described below.

---

## 🖥️ Windows Application: Live Network Monitoring

The Windows version runs locally on the user's computer and includes the live packet-capture components.

### How live monitoring works

1. The user launches INTRISENSE on a Windows computer.
2. The packet-capture module captures traffic available to the selected local network interface.
3. Captured packets are grouped into network flows.
4. The application extracts the required flow features.
5. The saved preprocessing pipeline and Random Forest model analyze the flow.
6. The dashboard displays the prediction, confidence information, and relevant security recommendations.

### Windows Setup

**Requirements:** Python 3.13, Git with Git LFS, and Npcap (if required for packet capture).

1. Install the required software.
2. Clone the INTRISENSE repository from GitHub and open the project folder.
3. Create a Python virtual environment.
4. Install the dependencies listed in `requirements.txt`.
5. Launch the Windows application using Streamlit.
6. Open the local URL displayed in the terminal, usually `http://localhost:8501`.

> **Note:** Live packet capture runs locally on your Windows computer and may require Npcap and appropriate permissions. Only monitor network traffic you are authorized to capture.
---


## ✨ Application Features

| Feature                      | Description                                                                     |
| ---------------------------- | ------------------------------------------------------------------------------- |
| 📊 Security Dashboard        | Displays network-analysis summaries and detection information.                  |
| 📁 Dataset Analysis          | Accepts compatible CSV files for model-based analysis.                          |
| 🧠 Intrusion Detection       | Uses the trained Random Forest model to analyze network-flow features.          |
| 🏷️ Attack Classification    | Predicts supported attack categories.                                           |
| 🔎 Prediction Confidence     | Displays confidence information with prediction results.                        |
| 🛡️ Security Recommendations | Provides rule-based recommendations associated with detected activity.          |
| 📈 Model Performance         | Displays stored model-performance information.                                  |
| 🌐 Live Network Monitoring   | Captures and analyzes locally available network traffic in the Windows version. |

---

## 🛠️ Technology Stack

| Technology     | Purpose                                              |
| -------------- | ---------------------------------------------------- |
| Python         | Core application and machine-learning implementation |
| Streamlit      | Interactive web interface                            |
| Pandas & NumPy | Data processing and numerical operations             |
| Scikit-learn   | Preprocessing and Random Forest model                |
| Joblib         | Loading saved model artifacts                        |
| Scapy          | Packet capture in the local Windows version          |
| Git & Git LFS  | Version control and large model-file tracking        |
| UNSW-NB15      | Network intrusion detection dataset                  |

---


## 📄 Dataset Input

The dataset-analysis feature accepts CSV files containing the network-flow features expected by the model.

A sample input file is available at:

```text
data/sample_network_input.csv
```

For reliable results, use a compatible dataset with the required feature columns and appropriate data types.

---

## ⚠️ Important Notes

* Model files are tracked using **Git Large File Storage (Git LFS)**.
* Install Git LFS before cloning if you need to download the saved model artifacts.
* The cloud application supports dataset-based analysis; it does not directly capture traffic from a visitor's computer.
* The Windows version performs local packet capture and may require Npcap and elevated permissions.
* Predictions and recommendations are intended to support security analysis, not replace professional security monitoring or incident-response procedures.
* Only capture network traffic that you are authorized to monitor.

---

## 🔮 Future Enhancements

* Package the Windows version into a downloadable executable.
* Create a guided Windows installer and setup process.
* Improve live network monitoring and traffic visualization.
* Expand dataset compatibility and input validation.
* Add more detailed explanations for model predictions.
* Explore additional models and evaluation approaches.

---

## 👩‍💻 Author

**Madiha Tarannum**

**Project:** INTRISENSE — *An Intelligent Machine Learning Framework for Network Intrusion Detection, Attack Classification, and Security Recommendation*

* **GitHub Repository:** [madiha-2212/INTRISENSE](https://github.com/madiha-2212/INTRISENSE)
* **Live Application:** [intrisense.streamlit.app](https://intrisense.streamlit.app)

---

<p align="center">
  <strong>INTRISENSE</strong><br>
  <em>Detect. Classify. Understand. Respond.</em>
</p>
