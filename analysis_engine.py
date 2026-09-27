
import joblib
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "models", "intrisense_random_forest.pkl")
PREPROCESSOR_PATH = os.path.join(BASE_DIR, "models", "intrisense_preprocessor.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "models", "intrisense_attack_encoder.pkl")
FEATURE_INFO_PATH = os.path.join(BASE_DIR, "models", "feature_information.json")

model = joblib.load(MODEL_PATH)
preprocessor = joblib.load(PREPROCESSOR_PATH)
attack_encoder = joblib.load(ENCODER_PATH)

with open(FEATURE_INFO_PATH, "r") as file:
    feature_information = json.load(file)


security_recommendations = {

    "Normal": {
        "severity": "Low",
        "recommendation": "Continue routine network monitoring and maintain standard security practices.",
        "explanation": "Your network activity appears normal and no suspicious attack pattern was detected. You can continue using the system normally. Keep your software and security tools updated. Regularly monitor the network so that unusual activity can be detected early."
    },

    "Analysis": {
        "severity": "Medium",
        "recommendation": "Investigate the unusual traffic pattern and review relevant network and system logs.",
        "explanation": "The system has noticed some unusual network behavior. This does not necessarily mean that your computer has been attacked. Check recent network activity and system logs for anything that looks unfamiliar. If the unusual activity continues, investigate the source more carefully."
    },

    "Backdoor": {
        "severity": "Critical",
        "recommendation": "Immediately isolate the affected system and investigate potential unauthorized access.",
        "explanation": "Someone may have found a hidden way to access your computer without permission. Disconnect the affected computer from the network to prevent further access. Check for unknown users, programs, or login activity. Change important passwords and investigate how the unauthorized access occurred."
    },

    "DoS": {
        "severity": "High",
        "recommendation": "Identify the source of excessive traffic and apply appropriate traffic filtering or rate-limiting controls.",
        "explanation": "Your system may be receiving an unusually large amount of network traffic. This can make websites, applications, or services slow or unavailable. Find out where the excessive traffic is coming from. Block or limit suspicious sources so that normal users can access the system."
    },

    "Exploits": {
        "severity": "High",
        "recommendation": "Identify the targeted service, apply necessary security patches, and investigate potential system compromise.",
        "explanation": "Someone may be trying to take advantage of a weakness in your software or system. Check which application or service is being targeted. Install the latest security updates and patches. Also check the system to make sure the attacker did not gain access."
    },

    "Fuzzers": {
        "severity": "Medium",
        "recommendation": "Inspect abnormal input patterns and strengthen input validation and filtering mechanisms.",
        "explanation": "Someone may be sending unusual or unexpected information to your system. This can be an attempt to find weaknesses in an application or service. Check the affected application and review the unusual requests. Make sure the application properly handles incorrect or unexpected input."
    },

    "Generic": {
        "severity": "High",
        "recommendation": "Investigate the anomalous traffic and review system, network, and access logs for potential threats.",
        "explanation": "The system has detected suspicious activity that does not clearly match one specific attack type. This means the activity should not be ignored. Check recent network connections, system activity, and login records. Look for anything unusual and take action if suspicious behavior is confirmed."
    },

    "Reconnaissance": {
        "severity": "Medium",
        "recommendation": "Monitor the source of the scanning activity and restrict unauthorized network or port discovery attempts.",
        "explanation": "Someone may be looking around your network to discover computers, services, or open ports. Attackers often do this before attempting a more serious attack. Monitor where the scanning activity is coming from. Block or restrict unknown sources when appropriate and keep unnecessary services closed."
    },

    "Shellcode": {
        "severity": "Critical",
        "recommendation": "Immediately isolate the affected system and investigate potential malicious code execution.",
        "explanation": "Someone may be trying to run harmful code on your computer. This could allow an attacker to control the system or perform unwanted actions. Disconnect the affected computer from the network immediately. Check the system for malicious programs and investigate how the suspicious code was introduced."
    },

    "Worms": {
        "severity": "Critical",
        "recommendation": "Immediately isolate infected systems and investigate potential lateral movement across the network.",
        "explanation": "A worm may have infected one computer and could be spreading to other computers. Disconnect the affected computer from the network as quickly as possible. Check other connected computers for similar suspicious activity. Remove the infection and make sure the affected systems are secure before reconnecting them."
    }
}


def analyze_network(input_data):

    processed_data = preprocessor.transform(input_data)

    prediction = model.predict(processed_data)

    predicted_category = attack_encoder.inverse_transform(prediction)[0]

    probabilities = model.predict_proba(processed_data)[0]

    confidence = float(probabilities.max())

    security_info = security_recommendations.get(
        predicted_category,
        {
            "severity": "Unknown",
            "recommendation": "Investigate the detected network activity.",
            "explanation": "The system detected unusual activity. Further investigation is recommended."
        }
    )

    return {
        "attack_type": predicted_category,
        "confidence": confidence,
        "severity": security_info["severity"],
        "recommendation": security_info["recommendation"],
        "explanation": security_info["explanation"]
    }
