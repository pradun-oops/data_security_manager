"""
modules/anomaly_detector.py
Machine Learning-based User & Entity Behavior Analytics (UEBA) using Isolation Forest.
"""

from typing import Any, Dict, List, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


class BehaviorAnomalyDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
        )
        self.feature_columns = [
            "access_hour",
            "record_query_count",
            "data_volume_mb",
            "restricted_record_ratio",
            "failed_auth_attempts",
        ]
        self.is_trained = False

    def train_baseline(self, num_samples: int = 1000):
        """
        Trains the Isolation Forest baseline on modeled benign behavioral telemetry:
        - Work hours predominantly 08:00 to 18:00
        - Moderate queries (5-50 records)
        - Low data transfer (0.5 to 15 MB)
        - Low restricted ratio (0.0 to 0.2)
        - Few or zero failed auth attempts (0-1)
        """
        np.random.seed(42)

        # 95% benign routine activity
        normal_count = int(num_samples * 0.95)
        normal_hours = np.random.normal(loc=13.0, scale=2.5, size=normal_count).clip(8, 18)
        normal_queries = np.random.exponential(scale=15, size=normal_count).clip(1, 80)
        normal_volume = np.random.exponential(scale=5.0, size=normal_count).clip(0.1, 25.0)
        normal_restricted_ratio = np.random.beta(a=1, b=8, size=normal_count).clip(0.0, 0.25)
        normal_failed_auth = np.random.choice([0, 1], size=normal_count, p=[0.9, 0.1])

        # 5% synthetic anomalous baseline noise
        anomaly_count = num_samples - normal_count
        anom_hours = np.random.choice([1, 2, 3, 22, 23], size=anomaly_count)
        anom_queries = np.random.uniform(200, 1000, size=anomaly_count)
        anom_volume = np.random.uniform(100, 1500, size=anomaly_count)
        anom_restricted_ratio = np.random.uniform(0.6, 1.0, size=anomaly_count)
        anom_failed_auth = np.random.choice([3, 4, 5, 8], size=anomaly_count)

        hours = np.concatenate([normal_hours, anom_hours])
        queries = np.concatenate([normal_queries, anom_queries])
        volume = np.concatenate([normal_volume, anom_volume])
        restricted = np.concatenate([normal_restricted_ratio, anom_restricted_ratio])
        failed_auth = np.concatenate([normal_failed_auth, anom_failed_auth])

        baseline_df = pd.DataFrame(
            {
                "access_hour": hours,
                "record_query_count": queries,
                "data_volume_mb": volume,
                "restricted_record_ratio": restricted,
                "failed_auth_attempts": failed_auth,
            }
        )

        self.model.fit(baseline_df[self.feature_columns])
        self.is_trained = True

    def analyze_activity(self, activity_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates an individual user/entity telemetry session.
        Returns:
            - is_anomaly (bool)
            - anomaly_score (-1 to 1 raw decision function)
            - risk_score (0 to 100 scale)
            - threat_level (Normal, Elevated, Suspicious, Critical Threat)
            - root_causes (List of anomalous attributes)
        """
        if not self.is_trained:
            self.train_baseline()

        input_df = pd.DataFrame([activity_record])[self.feature_columns]

        # Isolation Forest prediction: -1 = Anomaly, 1 = Normal
        prediction = self.model.predict(input_df)[0]
        # Raw decision score: lower values indicate higher anomalousness
        raw_score = self.model.decision_function(input_df)[0]

        # Convert to 0 - 100 Risk Score (where 100 is maximum risk)
        # Decision function generally spans [-0.3, 0.3]
        normalized_risk = float(np.clip((0.2 - raw_score) / 0.4 * 100, 0, 100))

        # Threat Categorization
        if normalized_risk >= 75:
            threat_level = "CRITICAL_THREAT"
        elif normalized_risk >= 50:
            threat_level = "SUSPICIOUS"
        elif normalized_risk >= 30:
            threat_level = "ELEVATED"
        else:
            threat_level = "NORMAL"

        # Heuristic explanation of contributing anomalies
        root_causes = []
        if (
            activity_record["access_hour"] < 6
            or activity_record["access_hour"] > 20
        ):
            root_causes.append(
                f"Off-Hours Activity ({activity_record['access_hour']:02d}:00 HRS)"
            )
        if activity_record["record_query_count"] > 150:
            root_causes.append(
                f"Abnormal Bulk Query Volume ({activity_record['record_query_count']} records)"
            )
        if activity_record["data_volume_mb"] > 50.0:
            root_causes.append(
                f"High Data Egress Volume ({activity_record['data_volume_mb']} MB)"
            )
        if activity_record["restricted_record_ratio"] > 0.4:
            root_causes.append(
                f"Disproportionate Restricted Record Access ({int(activity_record['restricted_record_ratio']*100)}%)"
            )
        if activity_record["failed_auth_attempts"] >= 3:
            root_causes.append(
                f"Preceding Multiple Failed Auth Attempts ({activity_record['failed_auth_attempts']})"
            )

        return {
            "User": activity_record.get("username", "Unknown"),
            "Is_Anomaly": bool(prediction == -1),
            "Risk_Score": round(normalized_risk, 1),
            "Threat_Level": threat_level,
            "Anomalous_Indicators": root_causes if root_causes else ["None (Matches Typical Profile)"],
        }