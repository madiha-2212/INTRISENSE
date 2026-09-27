import os
import json
import time
import pandas as pd
import streamlit as st

from live_capture import capture_packets
from flow_builder import build_flows
from live_features import extract_flow_features
from realtime_engine import analyze_live_flow


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="INTRISENSE | Intelligent Network Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# HTML RENDER HELPER  (THIS IS THE FIX)
# ------------------------------------------------------------
# Streamlit's Markdown renderer treats any line that is indented
# by 4+ spaces as an "indented code block". Because this file builds
# HTML snippets inside triple-quoted strings that are indented to
# match the surrounding Python code, Streamlit was displaying the
# raw HTML/CSS as literal text instead of rendering it.
#
# render_html() strips the leading whitespace from every line of
# the HTML string before handing it to st.markdown, so the parser
# no longer mistakes it for a code block. Use render_html() instead
# of st.markdown(..., unsafe_allow_html=True) everywhere in this file.
# ============================================================

def render_html(content: str) -> None:
    lines = content.strip("\n").split("\n")
    cleaned = "\n".join(line.lstrip() for line in lines)
    st.markdown(cleaned, unsafe_allow_html=True)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")

PERFORMANCE_FILE = os.path.join(
    MODEL_DIR,
    "model_performance.json"
)


# ============================================================
# SESSION STATE
# ============================================================

if "packets_captured" not in st.session_state:
    st.session_state.packets_captured = 0

if "flows_analyzed" not in st.session_state:
    st.session_state.flows_analyzed = 0

if "normal_flows" not in st.session_state:
    st.session_state.normal_flows = 0

if "suspicious_flows" not in st.session_state:
    st.session_state.suspicious_flows = 0

if "high_risk_flows" not in st.session_state:
    st.session_state.high_risk_flows = 0

if "last_detection" not in st.session_state:
    st.session_state.last_detection = "No detections yet"

if "last_results" not in st.session_state:
    st.session_state.last_results = []

if "monitoring_active" not in st.session_state:
    st.session_state.monitoring_active = False


# ============================================================
# LOAD MODEL PERFORMANCE
# ============================================================

def load_model_performance():

    default_performance = {
        "accuracy": 0.928424,
        "macro_f1": 0.777607,
        "weighted_f1": 0.938838
    }

    try:
        with open(PERFORMANCE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        return {
            "accuracy": data.get(
                "accuracy",
                default_performance["accuracy"]
            ),
            "macro_f1": data.get(
                "macro_f1",
                default_performance["macro_f1"]
            ),
            "weighted_f1": data.get(
                "weighted_f1",
                default_performance["weighted_f1"]
            )
        }

    except Exception:
        return default_performance


performance = load_model_performance()


# ============================================================
# CUSTOM CSS
# ============================================================

render_html(
    """
    <style>

    /* =====================================================
       GLOBAL
       ===================================================== */

    @import url(
        'https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Inter:wght@400;500;600;700;800&display=swap'
    );

    .stApp {
        background:
            radial-gradient(
                circle at top right,
                rgba(130, 0, 0, 0.20),
                transparent 30%
            ),
            radial-gradient(
                circle at bottom left,
                rgba(90, 0, 0, 0.14),
                transparent 30%
            ),
            #070707;
        color: #f5f5f5;
        font-family: 'Inter', sans-serif;
    }

    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 4rem;
        max-width: 1450px;
    }


    /* =====================================================
       SIDEBAR
       ===================================================== */

    section[data-testid="stSidebar"] {
        background:
            linear-gradient(
                180deg,
                #0c0c0c 0%,
                #080808 70%,
                #120000 100%
            );

        border-right: 1px solid rgba(190, 0, 0, 0.35);
    }

    section[data-testid="stSidebar"] * {
        color: #eeeeee;
    }

    section[data-testid="stSidebar"] .stRadio label {
        font-size: 1.10rem !important;
        font-weight: 700 !important;
        padding: 0.45rem 0;
    }

    section[data-testid="stSidebar"] .stRadio > div {
        gap: 0.25rem;
    }


    /* =====================================================
       MAIN TITLE
       ===================================================== */

    .intrisense-title {
        font-family: 'Orbitron', sans-serif;
        font-size: clamp(3rem, 7vw, 6rem);
        font-weight: 900;
        letter-spacing: 0.12em;
        text-align: center;

        background:
            linear-gradient(
                90deg,
                #ffffff 0%,
                #ff4b4b 45%,
                #8b0000 100%
            );

        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;

        text-shadow:
            0 0 18px rgba(180, 0, 0, 0.35);

        margin-bottom: 0.15rem;
    }

    .intrisense-subtitle {
        text-align: center;
        color: #bcbcbc;
        font-size: 1.05rem;
        letter-spacing: 0.12em;
        margin-bottom: 2.2rem;
    }


    /* =====================================================
       SECTION HEADINGS
       ===================================================== */

    .section-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.75rem;
        font-weight: 800;
        color: #ff5555;
        letter-spacing: 0.04em;
        margin-top: 0.5rem;
        margin-bottom: 1rem;
    }


    /* =====================================================
       DASHBOARD CARDS
       ===================================================== */

    .metric-card {
        background:
            linear-gradient(
                145deg,
                rgba(28, 28, 28, 0.96),
                rgba(12, 12, 12, 0.96)
            );

        border: 1px solid rgba(150, 0, 0, 0.40);
        border-radius: 16px;
        padding: 1.25rem;

        min-height: 145px;

        box-shadow:
            0 8px 30px rgba(0, 0, 0, 0.30);
    }

    .metric-label {
        color: #a9a9a9;
        font-size: 0.88rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }

    .metric-value {
        color: #ffffff;
        font-family: 'Orbitron', sans-serif;
        font-size: 2.2rem;
        font-weight: 800;
        margin-top: 0.45rem;
    }

    .metric-description {
        color: #777777;
        font-size: 0.80rem;
        margin-top: 0.25rem;
    }


    /* =====================================================
       STATUS
       ===================================================== */

    .status-online {
        display: inline-block;
        padding: 0.45rem 0.85rem;
        border-radius: 999px;

        background: rgba(0, 130, 60, 0.15);
        border: 1px solid rgba(0, 200, 100, 0.40);

        color: #61e89a;
        font-weight: 800;
        letter-spacing: 0.05em;
    }

    .status-idle {
        display: inline-block;
        padding: 0.45rem 0.85rem;
        border-radius: 999px;

        background: rgba(120, 120, 120, 0.12);
        border: 1px solid rgba(150, 150, 150, 0.25);

        color: #c6c6c6;
        font-weight: 800;
        letter-spacing: 0.05em;
    }


    /* =====================================================
       ALERT CARDS
       ===================================================== */

    .alert-high {
        background:
            linear-gradient(
                135deg,
                rgba(100, 0, 0, 0.55),
                rgba(35, 0, 0, 0.90)
            );

        border: 1px solid #ff3333;
        border-radius: 15px;

        padding: 1.25rem;

        box-shadow:
            0 0 25px rgba(255, 0, 0, 0.18);
    }

    .alert-normal {
        background:
            linear-gradient(
                135deg,
                rgba(15, 45, 25, 0.55),
                rgba(8, 20, 12, 0.90)
            );

        border: 1px solid rgba(80, 200, 120, 0.35);
        border-radius: 15px;

        padding: 1.25rem;
    }


    /* =====================================================
       BUTTONS
       ===================================================== */

    .stButton > button {
        border-radius: 10px;
        font-weight: 800;
        border: 1px solid rgba(180, 0, 0, 0.55);

        background:
            linear-gradient(
                135deg,
                #8b0000,
                #470000
            );

        color: white;

        transition: 0.2s ease;
    }

    .stButton > button:hover {
        border-color: #ff4444;

        box-shadow:
            0 0 20px rgba(180, 0, 0, 0.35);

        transform: translateY(-1px);
    }


    /* =====================================================
       INFO BOX
       ===================================================== */

    .info-panel {
        background: rgba(20, 20, 20, 0.82);
        border: 1px solid rgba(150, 0, 0, 0.28);
        border-radius: 15px;
        padding: 1.25rem;
        margin: 1rem 0;
    }


    /* =====================================================
       FOOTER
       ===================================================== */

    .footer {
        margin-top: 4rem;
        padding-top: 1.5rem;

        border-top: 1px solid rgba(150, 0, 0, 0.35);

        text-align: center;
        color: #888888;
    }

    .footer-name {
        font-family: 'Orbitron', sans-serif;
        color: #ff4545;
        font-size: 1.25rem;
        font-weight: 800;
        letter-spacing: 0.08em;
    }

    .footer-developer {
        color: #dddddd;
        font-size: 0.95rem;
        margin-top: 0.35rem;
    }

    .footer-contact {
        color: #999999;
        font-size: 0.85rem;
        margin-top: 0.3rem;
    }


    /* =====================================================
       DATAFRAME
       ===================================================== */

    div[data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
    }

    </style>
    """
)


# ============================================================
# HEADER
# ============================================================

render_html('<div class="intrisense-title">INTRISENSE</div>')

render_html(
    '<div class="intrisense-subtitle">'
    'INTELLIGENT NETWORK INTRUSION DETECTION & SECURITY ANALYTICS'
    '</div>'
)


# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

with st.sidebar:

    render_html(
        """
        <div style="
            text-align:center;
            margin-bottom:1.5rem;
            padding-bottom:1rem;
            border-bottom:1px solid rgba(150,0,0,0.35);
        ">
            <div style="
                font-family:'Orbitron';
                font-size:1.5rem;
                font-weight:800;
                color:#ff4444;
                letter-spacing:0.08em;
            ">
                🛡️ INTRISENSE
            </div>

            <div style="
                color:#777;
                font-size:0.75rem;
                margin-top:0.35rem;
            ">
                SECURITY OPERATIONS CENTER
            </div>
        </div>
        """
    )

    page = st.radio(
        "NAVIGATION",
        [
            "🏠  Security Dashboard",
            "📡  Live Network Monitoring",
            "📊  Dataset Analysis",
            "📈  Model Performance",
            "🛡️  Security Recommendations"
        ],
        label_visibility="visible"
    )


# ============================================================
# DASHBOARD
# ============================================================

if page == "🏠  Security Dashboard":

    render_html('<div class="section-title">🛰️ Security Operations Dashboard</div>')

    render_html(
        """
        <div class="info-panel">
        <b>INTRISENSE</b> continuously transforms network traffic into
        actionable security intelligence using machine-learning based
        intrusion detection and attack classification.
        </div>
        """
    )

    status = (
        '<span class="status-online">● MONITORING READY</span>'
        if st.session_state.monitoring_active
        else
        '<span class="status-idle">● SYSTEM READY</span>'
    )

    render_html(status)

    st.write("")

    # Dashboard metrics

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        render_html(
            f"""
            <div class="metric-card">
                <div class="metric-label">📦 Packets Captured</div>
                <div class="metric-value">
                    {st.session_state.packets_captured}
                </div>
                <div class="metric-description">
                    Observed by live packet capture
                </div>
            </div>
            """
        )

    with c2:
        render_html(
            f"""
            <div class="metric-card">
                <div class="metric-label">🔗 Flows Analyzed</div>
                <div class="metric-value">
                    {st.session_state.flows_analyzed}
                </div>
                <div class="metric-description">
                    Network conversations analyzed
                </div>
            </div>
            """
        )

    with c3:
        render_html(
            f"""
            <div class="metric-card">
                <div class="metric-label">🟢 Normal Flows</div>
                <div class="metric-value">
                    {st.session_state.normal_flows}
                </div>
                <div class="metric-description">
                    Flows classified as normal
                </div>
            </div>
            """
        )

    with c4:
        render_html(
            f"""
            <div class="metric-card">
                <div class="metric-label">🚨 High Risk</div>
                <div class="metric-value">
                    {st.session_state.high_risk_flows}
                </div>
                <div class="metric-description">
                    High / very-high severity detections
                </div>
            </div>
            """
        )

    st.write("")
    st.write("")

    left, right = st.columns(2)

    with left:

        render_html('<div class="section-title">🧠 Detection Engine</div>')

        render_html(
            f"""
            <div class="metric-card">
                <div class="metric-label">Machine Learning Model</div>
                <div class="metric-value" style="font-size:1.55rem;">
                    Random Forest
                </div>

                <div style="
                    margin-top:0.8rem;
                    color:#aaa;
                    line-height:1.8;
                ">
                    <b>Accuracy:</b> {performance["accuracy"] * 100:.2f}%<br>
                    <b>Macro F1:</b> {performance["macro_f1"] * 100:.2f}%<br>
                    <b>Weighted F1:</b> {performance["weighted_f1"] * 100:.2f}%
                </div>
            </div>
            """
        )

    with right:

        render_html('<div class="section-title">📡 Monitoring Pipeline</div>')

        render_html(
            """
            <div class="metric-card">
                <div style="
                    line-height:2.0;
                    color:#cccccc;
                ">
                    <b>01</b> → Packet Capture<br>
                    <b>02</b> → Flow Construction<br>
                    <b>03</b> → Feature Extraction<br>
                    <b>04</b> → ML Classification<br>
                    <b>05</b> → Risk Assessment<br>
                    <b>06</b> → Security Recommendation
                </div>
            </div>
            """
        )

    st.write("")
    st.write("")

    # Last detection

    render_html('<div class="section-title">🔎 Latest Detection</div>')

    if st.session_state.last_results:

        latest = st.session_state.last_results[-1]

        severity = latest.get("severity", "Low")
        attack = latest.get("attack_type", "Unknown")
        confidence = latest.get("confidence", 0)

        if severity in ["High", "Very High"]:

            render_html(
                f"""
                <div class="alert-high">
                    <h3>🚨 {severity.upper()} RISK DETECTED</h3>
                    <b>Attack Type:</b> {attack}<br>
                    <b>Confidence:</b> {confidence:.2f}%
                </div>
                """
            )

        else:

            render_html(
                f"""
                <div class="alert-normal">
                    <h3>🟢 NETWORK STATUS: {attack}</h3>
                    <b>Confidence:</b> {confidence:.2f}%<br>
                    <b>Severity:</b> {severity}
                </div>
                """
            )

    else:

        st.info(
            "No live detection has been recorded yet. "
            "Start Live Network Monitoring to populate the dashboard."
        )


# ============================================================
# LIVE NETWORK MONITORING
# ============================================================

elif page == "📡  Live Network Monitoring":

    render_html('<div class="section-title">📡 Live Network Monitoring</div>')

    render_html(
        """
        <div class="info-panel">
        <b>REAL-TIME MODE</b><br>
        INTRISENSE captures network packets from this Windows machine,
        groups them into network flows, extracts UNSW-NB15-compatible
        features, and sends the resulting flows through the trained
        Random Forest classifier.
        </div>
        """
    )

    col1, col2 = st.columns(2)

    with col1:

        packet_limit = st.slider(
            "📦 Packets to Capture",
            min_value=50,
            max_value=2000,
            value=500,
            step=50
        )

    with col2:

        capture_duration = st.slider(
            "⏱️ Capture Duration (seconds)",
            min_value=5,
            max_value=60,
            value=15,
            step=5
        )

    st.write("")

    if st.button(
        "🚨 START LIVE NETWORK ANALYSIS",
        use_container_width=True
    ):

        st.session_state.monitoring_active = True

        status_box = st.empty()

        try:

            status_box.info(
                "📡 Capturing live network traffic..."
            )

            # --------------------------------------------------
            # LIVE TRAFFIC CHART
            # --------------------------------------------------
            # live_capture.capture_packets() now accepts an on_packet
            # callback. scapy's sniff() runs this callback in the
            # same thread as the capture call, so a single continuous
            # capture can update the chart per packet in real time --
            # no chunking, no gaps, no re-opened sockets.
            #
            # Redraws are throttled to a few times per second so the
            # UI doesn't try to push a chart update for every single
            # packet on high-traffic links.

            RENDER_INTERVAL_SECONDS = 0.3

            render_html('<div class="section-title">📶 Live Traffic Rate</div>')

            traffic_chart_box = st.empty()
            traffic_stats_box = st.empty()

            traffic_state = {
                "start_time": None,
                "bucket_counts": {},
                "total": 0,
                "last_render": 0.0
            }

            def render_traffic_chart():
                bucket_items = sorted(
                    traffic_state["bucket_counts"].items()
                )

                chart_df = pd.DataFrame(
                    {
                        "Elapsed (s)": [b for b, _ in bucket_items],
                        "Packets/sec": [c for _, c in bucket_items]
                    }
                ).set_index("Elapsed (s)")

                traffic_chart_box.line_chart(
                    chart_df,
                    use_container_width=True
                )

                traffic_stats_box.markdown(
                    f"**{traffic_state['total']}** packets captured so far"
                )

            def on_packet_captured(pkt):

                if traffic_state["start_time"] is None:
                    traffic_state["start_time"] = pkt["timestamp"]

                elapsed_second = int(
                    pkt["timestamp"] - traffic_state["start_time"]
                )

                traffic_state["bucket_counts"][elapsed_second] = (
                    traffic_state["bucket_counts"].get(elapsed_second, 0) + 1
                )
                traffic_state["total"] += 1

                now = time.time()

                if now - traffic_state["last_render"] < RENDER_INTERVAL_SECONDS:
                    return

                traffic_state["last_render"] = now

                render_traffic_chart()

            packets = capture_packets(
                packet_count=packet_limit,
                timeout=capture_duration,
                on_packet=on_packet_captured
            )

            # Final redraw so the last partial second isn't dropped
            if traffic_state["bucket_counts"]:
                render_traffic_chart()

            packet_count = len(packets)

            st.session_state.packets_captured += packet_count

            status_box.success(
                f"✅ Captured {packet_count} packets."
            )


            if packet_count == 0:

                st.warning(
                    "No packets were captured during the selected "
                    "capture window. Try increasing the duration."
                )

            else:

                status_box.info(
                    "🔗 Building bidirectional network flows..."
                )

                flows = build_flows(packets)

                st.session_state.flows_analyzed += len(flows)

                st.success(
                    f"🔗 Built {len(flows)} network flows."
                )

                results = []

                progress = st.progress(0)

                for index, flow in enumerate(flows.values()):

                    try:

                        features = extract_flow_features(flow)

                        result = analyze_live_flow(features)

                        result["flow_number"] = index + 1

                        results.append(result)

                    except Exception as flow_error:

                        results.append(
                            {
                                "flow_number": index + 1,
                                "attack_type": "Analysis Error",
                                "confidence": 0.0,
                                "severity": "Unknown",
                                "recommendation": str(flow_error),
                                "explanation": (
                                    "This flow could not be analyzed."
                                )
                            }
                        )

                    progress.progress(
                        (index + 1) / max(len(flows), 1)
                    )

                st.session_state.last_results = results

                # Count results

                for result in results:

                    attack_type = result.get(
                        "attack_type",
                        "Unknown"
                    )

                    severity = result.get(
                        "severity",
                        "Low"
                    )

                    if attack_type == "Normal":
                        st.session_state.normal_flows += 1
                    else:
                        st.session_state.suspicious_flows += 1

                    if severity in ["High", "Very High"]:
                        st.session_state.high_risk_flows += 1

                if results:

                    st.session_state.last_detection = results[-1].get(
                        "attack_type",
                        "Unknown"
                    )

                # ------------------------------------------------
                # RESULTS
                # ------------------------------------------------

                render_html('<div class="section-title">🔍 Flow Analysis Results</div>')

                for result in results:

                    attack_type = result.get(
                        "attack_type",
                        "Unknown"
                    )

                    confidence = result.get(
                        "confidence",
                        0
                    )

                    severity = result.get(
                        "severity",
                        "Unknown"
                    )

                    recommendation = result.get(
                        "recommendation",
                        "No recommendation available."
                    )

                    explanation = result.get(
                        "explanation",
                        "No explanation available."
                    )

                    flow_number = result.get(
                        "flow_number",
                        0
                    )

                    if severity in ["High", "Very High"]:

                        render_html(
                            f"""
                            <div class="alert-high">

                                <h3>
                                    🚨 FLOW {flow_number} —
                                    {severity.upper()} RISK
                                </h3>

                                <b>Attack Type:</b>
                                {attack_type}
                                <br>

                                <b>Model Confidence:</b>
                                {confidence:.2f}%
                                <br>

                                <b>Severity:</b>
                                {severity}

                            </div>
                            """
                        )

                    else:

                        render_html(
                            f"""
                            <div class="alert-normal">

                                <h3>
                                    🟢 FLOW {flow_number} —
                                    {attack_type}
                                </h3>

                                <b>Model Confidence:</b>
                                {confidence:.2f}%
                                <br>

                                <b>Severity:</b>
                                {severity}

                            </div>
                            """
                        )

                    with st.expander(
                        f"🛡️ Security Guidance — Flow {flow_number}"
                    ):

                        st.markdown(
                            "**Recommendation**"
                        )

                        st.write(recommendation)

                        st.markdown(
                            "**Explanation**"
                        )

                        st.write(explanation)

                render_html('<div class="section-title">📊 Capture Summary</div>')

                summary_data = []

                for result in results:

                    summary_data.append(
                        {
                            "Flow": result.get(
                                "flow_number",
                                "-"
                            ),
                            "Attack Type": result.get(
                                "attack_type",
                                "Unknown"
                            ),
                            "Confidence": (
                                f'{result.get("confidence", 0):.2f}%'
                            ),
                            "Severity": result.get(
                                "severity",
                                "Unknown"
                            )
                        }
                    )

                if summary_data:

                    st.dataframe(
                        pd.DataFrame(summary_data),
                        use_container_width=True,
                        hide_index=True
                    )

                    # --------------------------------------------
                    # POST-RUN CHARTS
                    # --------------------------------------------

                    render_html(
                        '<div class="section-title">📈 Confidence & Severity Trend</div>'
                    )

                    chart_col1, chart_col2 = st.columns(2)

                    with chart_col1:

                        confidence_df = pd.DataFrame(
                            {
                                "Flow": [
                                    r.get("flow_number", i + 1)
                                    for i, r in enumerate(results)
                                ],
                                "Confidence (%)": [
                                    r.get("confidence", 0)
                                    for r in results
                                ]
                            }
                        ).set_index("Flow")

                        st.markdown("**Model Confidence per Flow**")

                        st.line_chart(
                            confidence_df,
                            use_container_width=True
                        )

                    with chart_col2:

                        severity_counts = (
                            pd.Series(
                                [
                                    r.get("severity", "Unknown")
                                    for r in results
                                ]
                            )
                            .value_counts()
                        )

                        st.markdown("**Flows by Severity**")

                        st.bar_chart(
                            severity_counts,
                            use_container_width=True
                        )

        except Exception as error:

            st.error(
                "❌ Live network analysis failed."
            )

            st.code(
                str(error)
            )

        finally:

            st.session_state.monitoring_active = False


# ============================================================
# DATASET ANALYSIS
# ============================================================

elif page == "📊  Dataset Analysis":

    render_html('<div class="section-title">📊 Dataset-Based Analysis</div>')

    render_html(
        """
        <div class="info-panel">
        Upload a CSV containing network-flow features compatible with
        the trained INTRISENSE pipeline. The uploaded records are
        passed through the same preprocessing and Random Forest
        classification pipeline used by the live monitoring system.
        </div>
        """
    )

    uploaded_file = st.file_uploader(
        "📁 Upload Network Flow CSV",
        type=["csv"]
    )

    if uploaded_file is not None:

        try:

            df = pd.read_csv(uploaded_file)

            st.success(
                f"✅ Dataset loaded successfully — "
                f"{len(df)} records found."
            )

            st.markdown(
                "### 🔎 Input Preview"
            )

            st.dataframe(
                df.head(10),
                use_container_width=True,
                hide_index=True
            )

            required_features = [
                "dur", "proto", "service", "state",
                "spkts", "dpkts", "sbytes", "dbytes",
                "rate", "sttl", "dttl", "sload", "dload",
                "sloss", "dloss", "sinpkt", "dinpkt",
                "sjit", "djit", "swin", "stcpb", "dtcpb",
                "dwin", "tcprtt", "synack", "ackdat",
                "smean", "dmean", "trans_depth",
                "response_body_len", "ct_srv_src",
                "ct_state_ttl", "ct_dst_ltm",
                "ct_src_dport_ltm",
                "ct_dst_sport_ltm",
                "ct_dst_src_ltm",
                "is_ftp_login", "ct_ftp_cmd",
                "ct_flw_http_mthd", "ct_src_ltm",
                "ct_srv_dst", "is_sm_ips_ports"
            ]

            missing = [
                feature
                for feature in required_features
                if feature not in df.columns
            ]

            if missing:

                st.error(
                    "❌ Required features are missing."
                )

                st.write(missing)

            else:

                if st.button(
                    "🔍 ANALYZE DATASET",
                    use_container_width=True
                ):

                    from realtime_engine import (
                        preprocessor,
                        model,
                        attack_encoder
                    )

                    input_data = df[required_features].copy()

                    processed = preprocessor.transform(
                        input_data
                    )

                    predictions = model.predict(
                        processed
                    )

                    decoded_predictions = attack_encoder.inverse_transform(
                        predictions
                    )

                    confidence_values = (
                        model.predict_proba(processed).max(axis=1)
                        * 100
                    )

                    output = pd.DataFrame(
                        {
                            "Predicted Attack Type":
                                decoded_predictions,
                            "Confidence (%)":
                                confidence_values.round(2)
                        }
                    )

                    st.markdown(
                        "### 🎯 Prediction Results"
                    )

                    st.dataframe(
                        output,
                        use_container_width=True,
                        hide_index=True
                    )

                    st.markdown(
                        "### 📈 Prediction Distribution"
                    )

                    distribution = (
                        output[
                            "Predicted Attack Type"
                        ]
                        .value_counts()
                        .rename_axis("Attack Type")
                        .reset_index(
                            name="Number of Flows"
                        )
                    )

                    st.bar_chart(
                        distribution.set_index(
                            "Attack Type"
                        )
                    )

        except Exception as error:

            st.error(
                "❌ Dataset analysis failed."
            )

            st.code(
                str(error)
            )


# ============================================================
# MODEL PERFORMANCE
# ============================================================

elif page == "📈  Model Performance":

    render_html('<div class="section-title">📈 Model Performance</div>')

    render_html(
        """
        <div class="info-panel">
        The final INTRISENSE classifier was selected after comparing
        multiple machine-learning models on the UNSW-NB15 dataset.
        Random Forest achieved the strongest overall performance and
        was selected as the final classification model.
        </div>
        """
    )

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric(
            "🎯 Accuracy",
            f'{performance["accuracy"] * 100:.2f}%'
        )

    with c2:
        st.metric(
            "⚖️ Macro F1",
            f'{performance["macro_f1"] * 100:.2f}%'
        )

    with c3:
        st.metric(
            "📊 Weighted F1",
            f'{performance["weighted_f1"] * 100:.2f}%'
        )

    st.write("")

    comparison = pd.DataFrame(
        {
            "Model": [
                "Random Forest",
                "Decision Tree",
                "HistGradient Boosting",
                "Logistic Regression"
            ],
            "Accuracy": [
                "92.84%",
                "92.79%",
                "87.80%",
                "70.21%"
            ],
            "Macro F1": [
                "77.76%",
                "77.52%",
                "57.38%",
                "43.52%"
            ],
            "Weighted F1": [
                "93.88%",
                "93.86%",
                "87.53%",
                "74.59%"
            ]
        }
    )

    st.markdown(
        "### 🏆 Model Comparison"
    )

    st.dataframe(
        comparison,
        use_container_width=True,
        hide_index=True
    )

    st.info(
        "Random Forest was selected as the final INTRISENSE model "
        "because it achieved the strongest overall evaluation results."
    )


# ============================================================
# SECURITY RECOMMENDATIONS
# ============================================================

elif page == "🛡️  Security Recommendations":

    render_html('<div class="section-title">🛡️ Security Recommendations</div>')

    render_html(
        """
        <div class="info-panel">
        INTRISENSE does not stop at attack classification.
        It converts the detected attack category into practical
        security guidance so that users can understand what action
        should be considered next.
        </div>
        """
    )

    recommendations = {

        "Generic":
            "Inspect the affected communication and review access "
            "controls, authentication, and unusual traffic patterns.",

        "Exploits":
            "Review exposed services, apply security patches, "
            "inspect the affected host, and investigate suspicious "
            "connections immediately.",

        "Fuzzers":
            "Inspect abnormal input traffic and consider filtering "
            "unexpected or malformed requests.",

        "DoS":
            "Monitor traffic volume, identify the source of excessive "
            "requests, apply rate limiting, and consider network-level "
            "traffic controls.",

        "Reconnaissance":
            "Investigate scanning activity and restrict unnecessary "
            "exposed services and ports.",

        "Analysis":
            "Review unusual communication patterns and inspect the "
            "affected host for suspicious activity.",

        "Backdoor":
            "Immediately investigate the affected host for unauthorized "
            "remote access mechanisms and suspicious processes.",

        "Shellcode":
            "Isolate the affected host if appropriate and investigate "
            "possible code-execution activity.",

        "Worms":
            "Investigate rapid propagation patterns and isolate "
            "potentially affected systems.",

        "Normal":
            "Continue routine network monitoring and maintain standard "
            "security practices."
    }

    for attack, recommendation in recommendations.items():

        if attack == "Normal":

            render_html(
                f"""
                <div class="alert-normal">
                    <h3>🟢 {attack}</h3>
                    <p>{recommendation}</p>
                </div>
                """
            )

        else:

            render_html(
                f"""
                <div class="alert-high">
                    <h3>🚨 {attack}</h3>
                    <p>{recommendation}</p>
                </div>
                """
            )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

render_html(
    """
    <div style="text-align:center; padding:20px 10px;">

        <div style="font-size:24px; font-weight:800; letter-spacing:3px;">
            INTRISENSE
        </div>

        <div style="font-size:16px; margin-top:8px;">
            Developed by <b>Madiha Tarannum</b>
        </div>

        <div style="font-size:14px; margin-top:6px;">
            📧 Email: madihatarannum5757@gmail.com
        </div>

        <div style="font-size:12px; margin-top:12px;">
            Intelligent Machine Learning Framework for Network Intrusion Detection,
            Attack Classification, and Security Recommendation
        </div>

    </div>
    """
)