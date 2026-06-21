import collections
import collections.abc
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
import os

def create_presentation():
    prs = Presentation()

    # Title Slide (Slide 1)
    slide_layout = prs.slide_layouts[0] 
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    subtitle = slide.placeholders[1]
    title.text = "AI-Driven IoT Intrusion Detection System"
    subtitle.text = "A Hybrid Deterministic-Probabilistic Security Framework Using Optimized Isolation Forests and Signature Fusion for Edge Networks\n\nM.Tech Project Presentation"

    # Slide 2: Background and Motivation
    slide_layout = prs.slide_layouts[1]
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Background and Motivation"
    content = slide.placeholders[1]
    tf = content.text_frame
    tf.text = "Proliferation of IoT Devices:"
    p = tf.add_paragraph()
    p.text = "Expected to exceed 15 billion active nodes, increasing vulnerability to Botnets and DDoS."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Traditional IDS Limitations:"
    p = tf.add_paragraph()
    p.text = "Signature-based systems miss zero-day attacks."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "ML-based models suffer from high false positives and latency."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Need for an edge-native, hybrid approach to secure IoT environments."

    # Slide 3: Problem Definition
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Problem Definition"
    tf = slide.placeholders[1].text_frame
    tf.text = "Detection Gap:"
    p = tf.add_paragraph()
    p.text = "Signature-based vs. ML-based architectures lack unified fusion."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Edge Deployment Gap:"
    p = tf.add_paragraph()
    p.text = "Existing hybrid IDS evaluate performance on cloud scale, not resource-constrained edge hardware."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Operational Resilience Gap:"
    p = tf.add_paragraph()
    p.text = "Current IoT IDS lack continuous monitoring to detect model drift over time."
    p.level = 1

    # Slide 4: Objectives of the Project
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Objectives of the Project"
    tf = slide.placeholders[1].text_frame
    tf.text = "Combine signature matching with optimized ML models (Isolation Forest/XGBoost)."
    p = tf.add_paragraph()
    p.text = "Develop a 21-feature extraction pipeline from raw network flows."
    p = tf.add_paragraph()
    p.text = "Implement a mathematically formal hybrid score fusion engine."
    p = tf.add_paragraph()
    p.text = "Deploy as hardened Docker microservices on a Raspberry Pi 4."
    p = tf.add_paragraph()
    p.text = "Integrate an MLOps drift detection pipeline for continuous monitoring."

    # Slide 5: IoT Network Threat Landscape
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "IoT Network Threat Landscape"
    tf = slide.placeholders[1].text_frame
    tf.text = "Extreme protocol heterogeneity and constrained computational resources."
    p = tf.add_paragraph()
    p.text = "Primary Threat Categories:"
    p = tf.add_paragraph()
    p.text = "Botnet Recruitment (e.g., Mirai, Bashlite)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Reconnaissance Scanning (Port scans, service enumeration)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Data Exfiltration (Cameras, smart sensors)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Lateral Movement to higher-value enterprise targets"
    p.level = 1

    # Slide 6: System Architecture (with image)
    slide_layout_title_only = prs.slide_layouts[5]
    slide = prs.slides.add_slide(slide_layout_title_only)
    title = slide.shapes.title
    title.text = "System Architecture"
    img_path = r"c:\Users\Dell\New-IoT-Project\figures\Designer.png"
    if os.path.exists(img_path):
        try:
            left = Inches(1)
            top = Inches(1.5)
            height = Inches(5.5)
            slide.shapes.add_picture(img_path, left, top, height=height)
        except Exception as e:
            print(f"Error adding image: {e}")
            txBox = slide.shapes.add_textbox(Inches(1), Inches(2), Inches(8), Inches(4))
            tf = txBox.text_frame
            tf.text = f"(Failed to add architecture Diagram: {e})"
    else:
        txBox = slide.shapes.add_textbox(Inches(1), Inches(2), Inches(8), Inches(4))
        tf = txBox.text_frame
        tf.text = f"(Architecture Diagram not found at {img_path})"

    # Slide 7: Isolation Forest Theory
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Isolation Forest Theory"
    tf = slide.placeholders[1].text_frame
    tf.text = "Unsupervised anomaly detection method."
    p = tf.add_paragraph()
    p.text = "Anomalies are easier to isolate than normal instances."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Isolation Tree (iTree) Construction:"
    p = tf.add_paragraph()
    p.text = "Randomly select feature and split value."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Recursively partition until isolated."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Anomaly score based on path length: shorter paths = anomalies."

    # Slide 8: Feature Engineering Pipeline
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Feature Engineering Pipeline"
    tf = slide.placeholders[1].text_frame
    tf.text = "21 Engineered Features across 5 Categories:"
    p = tf.add_paragraph()
    p.text = "Base Network (e.g., protocol types, connection states)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Volume Metrics (Bytes/packets sent/received)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Ratio Metrics (In/Out byte ratio)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Intensity Metrics (Packets/Bytes per second)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Statistical/Binary Indicators (Flags, mean packet sizes)"
    p.level = 1

    # Slide 9: Preprocessing Pipeline Evaluation
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Preprocessing Pipeline"
    tf = slide.placeholders[1].text_frame
    tf.text = "Challenges in IoT Traffic Data:"
    p = tf.add_paragraph()
    p.text = "Heavy-tailed distributions with extreme outliers (e.g., video streaming vs ping)."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Evaluated Scaling Strategies:"
    p = tf.add_paragraph()
    p.text = "StandardScaler, MinMaxScaler, RobustScaler."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Selected Strategy:"
    p = tf.add_paragraph()
    p.text = "RobustScaler using median and IQR provides superior robustness against outliers."
    p.level = 1

    # Slide 10: Machine Learning Models
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Machine Learning Models"
    tf = slide.placeholders[1].text_frame
    tf.text = "Unsupervised Model:"
    p = tf.add_paragraph()
    p.text = "Isolation Forest ensemble of 5 diversely configured models."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Optimized via hyperparameter grid search (contamination, sample fractions)."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Supervised Classifiers:"
    p = tf.add_paragraph()
    p.text = "XGBoost and CatBoost evaluated for labeled threat classification."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Provides high accuracy benchmark for known attack patterns."
    p.level = 1

    # Slide 11: Hybrid Score Fusion Engine
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Hybrid Score Fusion Engine"
    tf = slide.placeholders[1].text_frame
    tf.text = "Core innovation of the project."
    p = tf.add_paragraph()
    p.text = "Integrates:"
    p = tf.add_paragraph()
    p.text = "Deterministic signature rules (Zeek/Suricata)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Probabilistic ML anomaly predictions"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Computes a unified, confidence-weighted threat score."
    p = tf.add_paragraph()
    p.text = "Dynamic severity classification adjusts alert thresholds to reduce false positives."

    # Slide 12: Edge Computing & Containerization
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Edge Computing & Containerization"
    tf = slide.placeholders[1].text_frame
    tf.text = "Hardware: Raspberry Pi 4 Edge Gateway."
    p = tf.add_paragraph()
    p.text = "Local processing reduces latency and bandwidth."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Containerization (Docker):"
    p = tf.add_paragraph()
    p.text = "Layered microservices architecture."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Hardened security controls: capability limitation, read-only FS, privilege escalation prevention."
    p.level = 1

    # Slide 13: Dataset and Evaluation Strategy
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Dataset and Evaluation Strategy"
    tf = slide.placeholders[1].text_frame
    tf.text = "Dataset Size: 211,043 network flow samples."
    p = tf.add_paragraph()
    p.text = "Classes include Benign traffic, Mirai Botnet, Reconnaissance, and DDoS."
    p = tf.add_paragraph()
    p.text = "Data Split:"
    p = tf.add_paragraph()
    p.text = "Training, Validation, and Test splits."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Evaluation Metrics:"
    p = tf.add_paragraph()
    p.text = "Accuracy, Precision, Recall, F1-Score."
    p.level = 1

    # Slide 14: System Implementation Layers
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "System Implementation Layers"
    tf = slide.placeholders[1].text_frame
    tf.text = "Edge Gateway Layer:"
    p = tf.add_paragraph()
    p.text = "Packet capture, protocol decoding, feature extraction."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "AI Inference Service Layer:"
    p = tf.add_paragraph()
    p.text = "Preprocessing, ML inference, hybrid fusion scoring."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Observability Layer:"
    p = tf.add_paragraph()
    p.text = "Elasticsearch, Logstash, Kibana (ELK stack) for threat alert timelines."
    p.level = 1

    # Slide 15: Experimental Results - Anomaly Detection
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Experimental Results: Anomaly Detection"
    tf = slide.placeholders[1].text_frame
    tf.text = "Isolation Forest Performance:"
    p = tf.add_paragraph()
    p.text = "Baseline Accuracy: 54.13%"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Optimized Accuracy: 81.10% (+26.97% improvement)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Precision: 91.48%, Recall: 82.97%"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Supervised Benchmark (XGBoost):"
    p = tf.add_paragraph()
    p.text = "Achieved 99.59% accuracy on labeled test sets."
    p.level = 1

    # Slide 16: Experimental Results - Hybrid Engine
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Results: Hybrid Engine & Edge Resource Usage"
    tf = slide.placeholders[1].text_frame
    tf.text = "Hybrid Fusion Effectiveness:"
    p = tf.add_paragraph()
    p.text = "Successfully reduced false-positive alert fatigue."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Adjusts severity based on multi-source confidence."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Edge Gateway Performance:"
    p = tf.add_paragraph()
    p.text = "Inference latency kept within acceptable bounds for real-time monitoring."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Resource utilization footprint maintained well within Raspberry Pi 4 limits (4GB RAM/Quad-core)."
    p.level = 1

    # Slide 17: MLOps Drift Monitoring
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "MLOps Drift Monitoring"
    tf = slide.placeholders[1].text_frame
    tf.text = "Continuous Model Performance Monitoring:"
    p = tf.add_paragraph()
    p.text = "Protects against concept drift due to new protocols or attack types."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Statistical Tests Used:"
    p = tf.add_paragraph()
    p.text = "Population Stability Index (PSI)"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Kolmogorov-Smirnov (KS) tests"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Jensen-Shannon (JS) divergence"
    p.level = 1

    # Slide 18: Limitations and Future Scope
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Limitations and Future Scope"
    tf = slide.placeholders[1].text_frame
    tf.text = "Current Limitations:"
    p = tf.add_paragraph()
    p.text = "High dependency on correctly engineered features."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Limited zero-day detection bounds vs fully supervised deep learning."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Future Directions:"
    p = tf.add_paragraph()
    p.text = "Hardware-level eBPF/XDP acceleration."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Federated learning across distributed edge gateways."
    p.level = 1
    p = tf.add_paragraph()
    p.text = "Adversarial robustness testing."
    p.level = 1

    # Slide 19: Conclusion
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Conclusion"
    tf = slide.placeholders[1].text_frame
    tf.text = "Successfully implemented a containerized, hybrid, edge-native IoT IDS."
    p = tf.add_paragraph()
    p.text = "Bridged deterministic signature matching and probabilistic ML."
    p = tf.add_paragraph()
    p.text = "Optimized Isolation Forest improved unsupervised accuracy by 26.97%."
    p = tf.add_paragraph()
    p.text = "Robust edge deployment strategy achieved low-latency, scalable network defense."
    p = tf.add_paragraph()
    p.text = "MLOps pipeline integration ensures long-term operational resilience."

    # Slide 20: Q&A / References
    slide = prs.slides.add_slide(slide_layout)
    title = slide.shapes.title
    title.text = "Questions?"
    tf = slide.placeholders[1].text_frame
    tf.text = "Thank You!"
    p = tf.add_paragraph()
    p.text = "References:"
    p.level = 1
    p = tf.add_paragraph()
    p.text = "1. Market analyses on global IoT devices."
    p.level = 2
    p = tf.add_paragraph()
    p.text = "2. Mirai and Botnet research (Kolias et al.)"
    p.level = 2
    p = tf.add_paragraph()
    p.text = "3. Isolation Forest algorithm (Liu et al.)"
    p.level = 2

    prs.save(r"c:\Users\Dell\New-IoT-Project\Project_Presentation.pptx")
    print("Presentation generated successfully at c:\\Users\\Dell\\New-IoT-Project\\Project_Presentation.pptx")

if __name__ == "__main__":
    create_presentation()
