# PQCRecon Session Classifier (Phase 2)

This directory contains the machine learning logic for classifying TLS 1.3 sessions into four cryptographic posture categories based on their handshake features.

## Classification Categories

- **Classical**: No PQC in either key exchange or certificate chain.
- **KE-PQC**: PQC (or Hybrid-PQC) key exchange, but a classical certificate chain.
- **Cert-PQC**: Classical key exchange, but PQC-signed certificate(s).
- **Full-PQC**: Both PQC key exchange and a PQC-signed certificate chain.

## How to Run

To train the model and display the classification performance (F1 scores) on the extracted dataset, run the following command from the project root:

```bash
python3 classification/classifier.py --train feature-extract/training_data.csv
```

### What this script does:
1.  **Registry Ground Truth**: It first generates a synthetic "perfect" dataset based on authoritative IANA group IDs and NIST OIDs. This ensures the model recognizes all known PQC algorithms even if they aren't present in your current PCAPs.
2.  **Merging**: It merges the synthetic data with your real-world observations from `training_data.csv`.
3.  **Training**: It trains a Decision Tree classifier to learn the discriminating features (OIDs, group IDs, and byte sizes).
4.  **Evaluation**: It outputs a **Classification Report** including precision, recall, and **F1-score** for each category.
5.  **Visualization**: It saves a visualization of the decision logic to `classification/decision_tree.png`.

## Artifacts
- `classifier.py`: The main training/evaluation script.
- `pqcrecon_model.pkl`: The serialized model used for Phase 3 inference.
- `pqcrecon_lookups.pkl`: Metadata mapping used for feature engineering.
- `decision_tree.png`: A visual representation of the model's decision logic.
