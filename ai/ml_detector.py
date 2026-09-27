"""ML-enhanced behavioral threat detection for the SSH Defense Gateway.

``AnomalyAwareDetector`` extends the rule-based ``BehaviorDetector`` with
a lightweight isolation-forest layer: a session is now flagged when
either the classic suspicious-binary score meets its threshold *or* the
machine-learning model judges the session an outlier against the user's
own command baseline, *or* the session deviates from the persisted
``BaselineProfile`` learned in training mode. The mitigation path
(process kill + firewall block, whitelist protection, audit trail) is
reused unchanged.
"""

from ai.anomaly import AnomalyDetector
from ai.detector import BehaviorDetector


class AnomalyAwareDetector(BehaviorDetector):
    """Behavioral detector combining the rule score with a per-user ML model."""

    def __init__(
        self,
        suspicious_commands=None,
        score_threshold=1,
        firewall=None,
        logger=None,
        whitelist=None,
        baseline=None,
        ml_enabled=True,
        anomaly_threshold=0.72,
        forest_trees=16,
        max_memory=150,
        min_train=25,
        retrain_every=24,
        seed=7,
    ):
        super().__init__(
            suspicious_commands=suspicious_commands,
            score_threshold=score_threshold,
            firewall=firewall,
            logger=logger,
            whitelist=whitelist,
            baseline=baseline,
        )
        self.ml_enabled = ml_enabled
        self.anomaly_threshold = anomaly_threshold
        self._anomaly = AnomalyDetector(
            suspicious_commands=self._suspicious_commands,
            forest_trees=forest_trees,
            max_memory=max_memory,
            min_train=min_train,
            retrain_every=retrain_every,
            seed=seed,
        )
        self._last_assessment = None
        self._last_verdict = None

    @classmethod
    def from_config(
        cls, config, firewall=None, logger=None, whitelist=None, baseline=None
    ):
        """Build the detector from a loaded config, honouring optional tuning keys."""
        return cls(
            suspicious_commands=config.get("suspicious_commands"),
            firewall=firewall,
            logger=logger,
            whitelist=whitelist,
            baseline=baseline,
            ml_enabled=bool(config.get("anomaly_enabled", True)),
            anomaly_threshold=float(config.get("anomaly_threshold", 0.72)),
            forest_trees=int(config.get("anomaly_forest_trees", 16)),
            max_memory=int(config.get("anomaly_max_memory", 150)),
            min_train=int(config.get("anomaly_min_train", 25)),
            retrain_every=int(config.get("anomaly_retrain_every", 24)),
        )

    def assess(self, session):
        """Run the ML anomaly check, caching the assessment for inspection."""
        self._last_assessment = self._anomaly.assess(session)
        return self._last_assessment

    @property
    def last_assessment(self):
        """The most recent ML assessment, or None before the first check."""
        return self._last_assessment

    @property
    def last_verdict(self):
        """Why the most recent session was or was not flagged.

        Combines the rule score, the ML outlier score, and the learned
        baseline into one dict the daemon can hand straight to the audit
        store, along with whether the whitelist suppressed the response.
        """
        return self._last_verdict

    def evaluate(self, session):
        """Trigger the response when the rule score or the ML model fires.

        A third signal is added on top of the classic rule score and the
        isolation forest: the trained ``BaselineProfile`` from training
        mode. The return value stays the classic rule score for parity
        with ``BehaviorDetector``; the full ML picture is on
        ``last_assessment`` and the combined decision on ``last_verdict``.
        """
        rule_score = super().score_session(session)
        assessment = self.assess(session)
        baseline = self.evaluate_baseline(session)
        ml_flagged = bool(
            self.ml_enabled
            and assessment["trained"]
            and assessment["anomaly_score"] is not None
            and assessment["anomaly_score"] >= self.anomaly_threshold
        )
        baseline_flagged = bool(baseline and baseline["flagged"])
        flagged = (
            rule_score >= self._score_threshold
            or ml_flagged
            or baseline_flagged
        )
        if flagged:
            self.respond(session)
            if self._logger is not None:
                response = self._last_response or {}
                self._logger.record(
                    "anomaly",
                    session_id=session.get("session_id"),
                    client_address=session.get("client_address"),
                    score=rule_score,
                    threshold=self._score_threshold,
                    ml_score=assessment["anomaly_score"],
                    ml_threshold=self.anomaly_threshold,
                    baseline_score=(
                        baseline["z_max"] if baseline is not None else None
                    ),
                    baseline_threshold=(
                        self._baseline.z_threshold
                        if self._baseline is not None
                        else None
                    ),
                    whitelisted=bool(response.get("whitelisted")),
                    response=response,
                )
        self._last_verdict = {
            "flagged": flagged,
            "score": rule_score,
            "ml_flagged": ml_flagged,
            "baseline_flagged": baseline_flagged,
            "threshold": self._score_threshold,
            "whitelisted": bool(
                flagged and (self._last_response or {}).get("whitelisted")
            ),
        }
        return rule_score