"""nids - Network Intrusion & anomaly Detection System.

The "engine" of the project. Plain Python, no user-interface code, so the
same functions are used by the Jupyter notebooks, the Streamlit GUI and (in
future) a cloud API.

    config         settings loaded from config/*.yaml
    data           dataset collection and loading
    preprocessing  cleaning, target, split, encoding + scaling      (PR5)
    models         the classifiers we compare                       (PR7, PR8, PR11)
    training       training, cross-validation, grid search          (PR11)
    evaluation     metrics, confusion matrix, unseen-attack analysis
    anomaly        Isolation Forest + PCA projection                (PR10)
    plots          charts shared by notebooks and GUI
    detector       the saved, deployable model
"""
