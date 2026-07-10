import streamlit as st
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt

st.set_page_config(page_title="🔒 AI Cyber Defense Platform", layout="wide")
st.title("🔒 AI Cyber Defense Platform")
st.markdown("Real-time network anomaly detection & automated threat response")

@st.cache_data
def generate_network_traffic(n_normal=500, n_attacks=50):
    np.random.seed(42)
    normal_data = pd.DataFrame({
        "src_bytes": np.random.exponential(1000, n_normal),
        "dst_bytes": np.random.exponential(500, n_normal),
        "duration": np.random.exponential(10, n_normal),
        "packet_count": np.random.poisson(50, n_normal),
        "label": "benign"
    })
    
    ddos = pd.DataFrame({
        "src_bytes": np.random.exponential(5000, n_attacks//2),
        "dst_bytes": np.random.exponential(100, n_attacks//2),
        "duration": np.random.exponential(2, n_attacks//2),
        "packet_count": np.random.poisson(500, n_attacks//2),
        "label": "ddos"
    })
    
    exfil = pd.DataFrame({
        "src_bytes": np.random.exponential(100, n_attacks//2),
        "dst_bytes": np.random.exponential(5000, n_attacks//2),
        "duration": np.random.exponential(30, n_attacks//2),
        "packet_count": np.random.poisson(1000, n_attacks//2),
        "label": "data_exfiltration"
    })
    
    return pd.concat([normal_data, ddos, exfil]).reset_index(drop=True)

data = generate_network_traffic()

tab1, tab2, tab3 = st.tabs(["📊 Traffic Analysis", "🚨 Detection Model", "🛡️ Live Monitoring"])

with tab1:
    st.subheader("Network Traffic Distribution")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Flows", len(data))
    col2.metric("Benign", len(data[data.label=="benign"]))
    col3.metric("Attacks", len(data[data.label!="benign"]))
    
    fig, axes = plt.subplots(2, 2, figsize=(10, 8))
    data[data.label=="benign"]["src_bytes"].hist(bins=50, ax=axes[0,0], alpha=0.7, color="green", label="Benign")
    axes[0,0].set_title("Source Bytes (Benign)")
    data[data.label!="benign"]["dst_bytes"].hist(bins=50, ax=axes[0,1], alpha=0.7, color="red", label="Attack")
    axes[0,1].set_title("Dest Bytes (Attack)")
    data.groupby("label").size().plot(kind="bar", ax=axes[1,0], color=["green", "red", "orange"])
    axes[1,0].set_title("Flow Distribution by Type")
    data[data.label=="benign"]["duration"].hist(bins=30, ax=axes[1,1], alpha=0.7)
    axes[1,1].set_title("Duration (Benign)")
    st.pyplot(fig)

with tab2:
    if st.button("🚀 Train Anomaly + Attack Classifier"):
        X = data[["src_bytes", "dst_bytes", "duration", "packet_count"]]
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_scores = iso_forest.fit_predict(X_scaled)
        data["anomaly_score"] = 1 - (iso_forest.score_samples(X_scaled) - iso_forest.score_samples(X_scaled).min()) / (iso_forest.score_samples(X_scaled).max() - iso_forest.score_samples(X_scaled).min())
        
        st.success(f"✅ Isolation Forest trained. Detected {(anomaly_scores==-1).sum()} anomalies")
        
        y_binary = (data.label != "benign").astype(int)
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_binary, test_size=0.2, random_state=42)
        
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X_train, y_train)
        acc = rf.score(X_test, y_test)
        st.success(f"✅ Attack Classifier trained. Test Accuracy: {acc:.1%}")
        
        st.session_state["iso_forest"] = iso_forest
        st.session_state["rf"] = rf
        st.session_state["scaler"] = scaler

with tab3:
    st.subheader("Live Flow Analysis")
    c1, c2 = st.columns(2)
    src_bytes = c1.slider("Source Bytes (KB)", 0, 10000, 500)
    dst_bytes = c2.slider("Dest Bytes (KB)", 0, 10000, 300)
    duration = c1.slider("Duration (sec)", 0, 100, 5)
    packets = c2.slider("Packet Count", 10, 2000, 50)
    
    if st.button("🔍 Analyze Flow"):
        if "iso_forest" in st.session_state:
            flow = np.array([[src_bytes, dst_bytes, duration, packets]])
            flow_scaled = st.session_state["scaler"].transform(flow)
            
            anomaly_pred = st.session_state["iso_forest"].predict(flow_scaled)[0]
            anomaly_score = st.session_state["iso_forest"].score_samples(flow_scaled)[0]
            
            attack_pred = st.session_state["rf"].predict(flow_scaled)[0]
            attack_conf = st.session_state["rf"].predict_proba(flow_scaled)[0].max()
            
            if anomaly_pred == -1:
                st.warning(f"⚠️ **ANOMALY DETECTED** — Anomaly Score: {anomaly_score:.2f}")
                if attack_conf > 0.7:
                    st.error(f"🚨 **HIGH CONFIDENCE ATTACK** — {['Benign','Attack'][attack_pred]} ({attack_conf:.0%})")
                    st.warning("🔴 Action: BLOCK IP & Alert SOC")
                else:
                    st.info(f"🟡 Low confidence attack prediction ({attack_conf:.0%}) — Monitor")
            else:
                st.success("✅ **BENIGN FLOW** — No threat detected")
        else:
            st.warning("Train the model first (Detection Model tab)")

st.markdown("---")
st.caption("Demo uses simulated traffic. In production, feed Zeek/Suricata logs or pcap dumps.")
