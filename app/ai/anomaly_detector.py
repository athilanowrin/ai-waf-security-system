from sklearn.ensemble import IsolationForest
import numpy as np


class AnomalyDetector:
    """
    AI-based anomaly detection using Isolation Forest.

    The model learns normal HTTP request behaviour
    and identifies unusual requests as anomalies.
    """

    def __init__(self):

        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42
        )

        # Decision-function threshold.
        # Lower scores indicate more suspicious behaviour.
        self.anomaly_threshold = 0.07

        self.is_trained = False

    def _extract_features(self, request_data):
        """
        Convert HTTP request data into numerical features.
        """

        if not request_data:
            return np.array([
                [0, 0, 0, 0, 0, 0]
            ])

        request_text = " ".join(
            str(value)
            for value in request_data.values()
        )

        request_length = len(request_text)

        special_characters = sum(
            1
            for char in request_text
            if char in "<>;'\"|&$()"
        )

        digit_count = sum(
            1
            for char in request_text
            if char.isdigit()
        )

        space_count = request_text.count(" ")

        parameter_count = len(request_data)

        special_character_ratio = (
            special_characters / request_length
            if request_length > 0
            else 0
        )

        return np.array([
            [
                request_length,
                special_characters,
                digit_count,
                space_count,
                parameter_count,
                special_character_ratio
            ]
        ])

    def train(self, normal_requests):
        """
        Train the AI model using normal request behaviour.
        """

        features = np.vstack([
            self._extract_features(request)
            for request in normal_requests
        ])

        self.model.fit(features)

        self.is_trained = True

    def detect(self, request_data):
        """
        Detect whether a request is anomalous.
        """

        if not self.is_trained:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "message": "AI model is not trained yet"
            }

        features = self._extract_features(request_data)

        score = self.model.decision_function(features)[0]

        # Lower score = more unusual behaviour
        is_anomaly = score <= self.anomaly_threshold

        return {
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": round(float(score), 4),
            "message": (
                "Anomalous request detected"
                if is_anomaly
                else "Normal request behaviour"
            )
        }