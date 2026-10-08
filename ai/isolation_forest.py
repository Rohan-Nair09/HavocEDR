"""Per-endpoint Isolation Forest trained from prior benign process observations."""

import logging
import math
import ntpath
import threading
from collections import OrderedDict
from datetime import datetime, timezone

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction import DictVectorizer

logger = logging.getLogger(__name__)


class ProcessIsolationForest:
    MIN_TRAINING_PROFILES = 30

    def __init__(self):
        self._lock = threading.RLock()
        self._vectorizer = None
        self._model = None
        self._state = "waiting for process baseline"
        self._training_samples = 0
        self._trained_at = None

    @staticmethod
    def _features(row):
        path = str(row.get("path") or "").casefold()
        name = str(row.get("name") or "unknown").casefold()
        parent = str(row.get("parent_name") or "unknown").casefold()
        signature = str(row.get("digital_signature") or "unknown").casefold()
        if "\\windows\\" in path:
            location = "windows"
        elif "\\program files" in path:
            location = "program_files"
        elif "\\appdata\\local\\temp" in path or "\\windows\\temp" in path:
            location = "temporary"
        elif "\\users\\" in path:
            location = "user_profile"
        elif path:
            location = "other_path"
        else:
            location = "path_unavailable"
        return {
            "process_name": name,
            "parent_name": parent,
            "signature": signature,
            "location": location,
            "cpu_log": math.log1p(max(0.0, float(row.get("cpu_percent") or 0.0))),
            "memory_log": math.log1p(max(0.0, float(row.get("ram_usage_mb") or 0.0))),
            "threads_log": math.log1p(max(0.0, float(row.get("thread_count") or 0))),
            "rule_threat_score": max(0.0, float(row.get("threat_score") or 0.0)) / 100.0,
        }

    @staticmethod
    def _profile_key(row):
        path = str(row.get("path") or "").casefold()
        name = str(row.get("name") or "unknown").casefold()
        return path or name

    def train(self, rows):
        # Keep one recent record per executable to avoid letting two-second polling
        # duplicates dominate the learned baseline.
        profiles = OrderedDict()
        for row in rows:
            if row.get("is_suspicious"):
                continue
            key = self._profile_key(row)
            if key and key not in profiles:
                profiles[key] = row
        profiles = list(profiles.values())
        if len(profiles) < self.MIN_TRAINING_PROFILES:
            with self._lock:
                self._state = f"collecting baseline ({len(profiles)}/{self.MIN_TRAINING_PROFILES} process profiles)"
                self._training_samples = len(profiles)
            return False
        try:
            vectorizer = DictVectorizer(sparse=False)
            matrix = vectorizer.fit_transform([self._features(row) for row in profiles])
            model = IsolationForest(
                n_estimators=150,
                max_samples=min(256, len(profiles)),
                contamination=0.02,
                random_state=42,
                n_jobs=1,
            )
            model.fit(matrix)
        except Exception:
            logger.exception("Could not train the endpoint process anomaly model")
            with self._lock:
                self._state = "training failed"
            return False
        with self._lock:
            self._vectorizer = vectorizer
            self._model = model
            self._training_samples = len(profiles)
            self._trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._state = "trained"
        logger.info("Process Isolation Forest trained on %d endpoint process profiles", len(profiles))
        return True

    def score(self, row):
        with self._lock:
            if self._model is None:
                return None
            vectorizer = self._vectorizer
            model = self._model
            samples = self._training_samples
        matrix = vectorizer.transform([self._features(row)])
        decision = float(model.decision_function(matrix)[0])
        prediction = int(model.predict(matrix)[0])
        if prediction != -1:
            return None
        return {"decision_score": decision, "training_profiles": samples}

    def status(self):
        with self._lock:
            return {"state": self._state, "training_profiles": self._training_samples, "trained_at": self._trained_at}
