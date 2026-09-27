
import pandas as pd
import numpy as np
import joblib
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "models", "intrisense_random_forest.pkl")
PREPROCESSOR_PATH = os.path.join(BASE_DIR, "models", "intrisense_preprocessor.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "models", "intrisense_attack_encoder.pkl")


model = joblib.load(MODEL_PATH)
preprocessor = joblib.load(PREPROCESSOR_PATH)
attack_encoder = joblib.load(ENCODER_PATH)


SECURITY_RECOMMENDATIONS = {

    "Normal": {
        "severity": "Low",
        "recommendation":
            "Continue routine network monitoring and maintain standard security practices.",
        "explanation":
            "Your network activity appears normal and no suspicious attack pattern was detected. "
            "You can continue using the system normally. Keep your software and security tools "
            "updated and monitor the network regularly."
    },

    "Analysis": {
        "severity": "Medium",
        "recommendation":
            "Investigate unusual traffic patterns and review relevant network and system logs.",
        "explanation":
            "The activity shows an unusual pattern that is not necessarily a confirmed attack. "
            "Check the related connections and system logs. If the behavior continues, investigate "
            "the source and affected service."
    },

    "Backdoor": {
        "severity": "Critical",
        "recommendation":
            "Immediately isolate the affected system and investigate potential unauthorized access.",
        "explanation":
            "A backdoor can provide hidden or unauthorized access to a system. Disconnect the "
            "affected device from the network if appropriate, check unfamiliar accounts or programs, "
            "and investigate suspicious login activity."
    },

    "DoS": {
        "severity": "High",
        "recommendation":
            "Identify the source of excessive traffic and apply appropriate traffic filtering or rate limiting.",
        "explanation":
            "The traffic pattern may indicate an attempt to overwhelm a service with excessive requests. "
            "Check the traffic source and use filtering or rate limiting to reduce suspicious traffic."
    },

    "Exploits": {
        "severity": "High",
        "recommendation":
            "Identify the targeted service, apply security patches, and investigate possible compromise.",
        "explanation":
            "The traffic pattern may indicate an attempt to exploit a software or service weakness. "
            "Identify the affected service, apply available security updates, and check whether the "
            "system shows signs of compromise."
    },

    "Fuzzers": {
        "severity": "Medium",
        "recommendation":
            "Inspect abnormal input patterns and strengthen input validation and filtering.",
        "explanation":
            "The traffic may contain unusual or unexpected inputs intended to discover weaknesses. "
            "Review the related requests and ensure applications properly validate unexpected input."
    },

    "Generic": {
        "severity": "High",
        "recommendation":
            "Investigate anomalous traffic and review system, network, and access logs.",
        "explanation":
            "The activity appears suspicious but does not clearly identify one specific attack type. "
            "Review network connections, login activity, and system logs to determine whether the "
            "behavior is legitimate or malicious."
    },

    "Reconnaissance": {
        "severity": "Medium",
        "recommendation":
            "Monitor the scanning source and restrict unauthorized network or port discovery.",
        "explanation":
            "The traffic may indicate that someone is looking for available systems, services, or open "
            "ports. Monitor the source and restrict unauthorized scanning where possible."
    },

    "Shellcode": {
        "severity": "Critical",
        "recommendation":
            "Immediately isolate the affected system and investigate possible malicious code execution.",
        "explanation":
            "The traffic pattern may indicate activity associated with malicious code execution. "
            "Isolate the affected system when appropriate and investigate suspicious programs, processes, "
            "and the possible entry point."
    },

    "Worms": {
        "severity": "Critical",
        "recommendation":
            "Immediately isolate potentially infected systems and investigate possible lateral movement.",
        "explanation":
            "Worm activity can spread from one system to another. Isolate potentially affected systems, "
            "check connected devices for similar activity, and remove the infection before reconnecting "
            "systems to the network."
    }
}


def analyze_live_flow(flow_features):

    required_features = list(preprocessor.feature_names_in_)

    input_data = pd.DataFrame(
        [[flow_features.get(feature, 0) for feature in required_features]],
        columns=required_features
    )

    processed_data = preprocessor.transform(input_data)

    prediction_encoded = model.predict(processed_data)[0]

    probabilities = model.predict_proba(processed_data)[0]

    confidence = float(np.max(probabilities))

    attack_type = attack_encoder.inverse_transform(
        [prediction_encoded]
    )[0]

    info = SECURITY_RECOMMENDATIONS.get(
        attack_type,
        {
            "severity": "Unknown",
            "recommendation":
                "Review the detected network activity and investigate the affected connection.",
            "explanation":
                "The model identified an unusual network pattern. Further investigation is recommended."
        }
    )

    return {
        "attack_type": attack_type,
        "confidence": confidence,
        "severity": info["severity"],
        "recommendation": info["recommendation"],
        "explanation": info["explanation"]
    }
