from pydantic import BaseModel
from typing import List, Optional, Any


class PcapMetrics(BaseModel):
    packet_count: int
    protocols_found: List[str]
    vpn_mode_inferred: str
    ike_version: str
    encryption: str
    authentication: str
    key_exchange: str
    flow_features: Optional[dict] = None


class SecurityFinding(BaseModel):
    title: str
    description: str
    severity: str
    recommendation: str
    evidence: str
    risk_contribution: Optional[int] = 0


class RuleRecord(BaseModel):
    """Records a single rule that ran or was skipped during security evaluation."""
    rule: str
    observed_value: Optional[str] = None   # only for rules_evaluated
    reason: Optional[str] = None           # only for rules_skipped
    status: Optional[str] = None           # PASS or FAIL


class SecurityAssessment(BaseModel):
    findings: List[SecurityFinding]
    overall_risk_score: int
    risk_level: str
    score_explanation: str
    rules_evaluated: List[RuleRecord] = []
    rules_skipped: List[RuleRecord] = []


class MLPrediction(BaseModel):
    predicted_category: str
    confidence_score: Optional[float] = None
    model_status: str
    model_note: str
    features_available: List[str] = []
    features_required_missing: List[str] = []
    all_class_probabilities: Optional[dict] = None
    dataset_note: Optional[str] = None


class AnalysisReport(BaseModel):
    id: str
    filename: str
    status: str
    pcap_metrics: PcapMetrics
    security_assessment: SecurityAssessment
    ml_prediction: MLPrediction
