"""
Behavioral Anomaly Detection Engine
Week 1-2 Implementation: Isolation Forest + Local Outlier Factor (LOF)
Detects deviations from normal token access patterns using unsupervised ML
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Tuple, Optional
from app.database import get_db_session
from app.models import AttackLog, AnomalyDetection

logger = logging.getLogger(__name__)

class AnomalyDetectionEngine:
    """
    Detects anomalous patterns in honeytoken access using:
    - Isolation Forest: Isolates anomalies through random feature selection
    - Local Outlier Factor (LOF): Density-based approach for local anomalies
    """
    
    def __init__(self, contamination_rate: float = 0.1):
        """
        Args:
            contamination_rate: Expected ratio of anomalies (0-1)
        """
        self.contamination_rate = contamination_rate
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=contamination_rate,
            random_state=42,
            n_estimators=100
        )
        self.lof = LocalOutlierFactor(
            n_neighbors=20,
            contamination=contamination_rate,
            novelty=False
        )
        self.feature_columns = [
            'hour_of_day',
            'day_of_week',
            'request_frequency_per_hour',
            'unique_ips_accessed_from',
            'avg_time_between_accesses',
            'user_agent_entropy',
            'geolocation_distance_from_baseline'
        ]
    
    def extract_features(self, attack_logs: List[AttackLog], 
                        baseline_hours: int = 72) -> pd.DataFrame:
        """
        Extract behavioral features from attack logs.
        
        Features:
        - Temporal: hour of day, day of week, inter-access time
        - Geographical: access from new regions
        - Technical: user agent changes, access frequency
        """
        if not attack_logs:
            return pd.DataFrame()
        
        features = []
        now = datetime.utcnow()
        baseline_cutoff = now - timedelta(hours=baseline_hours)
        
        # Group logs by source IP
        ip_groups = {}
        for log in attack_logs:
            if log.source_ip not in ip_groups:
                ip_groups[log.source_ip] = []
            ip_groups[log.source_ip].append(log)
        
        for source_ip, logs in ip_groups.items():
            recent_logs = [l for l in logs if l.timestamp >= baseline_cutoff]
            if not recent_logs:
                continue
            
            sorted_logs = sorted(recent_logs, key=lambda x: x.timestamp)
            
            # Temporal features
            last_timestamp = sorted_logs[-1].timestamp
            hour_of_day = last_timestamp.hour
            day_of_week = last_timestamp.weekday()
            
            # Frequency features
            time_span = (sorted_logs[-1].timestamp - sorted_logs[0].timestamp).total_seconds()
            hours_span = max(time_span / 3600, 1)
            request_frequency = len(sorted_logs) / hours_span
            
            # Inter-access time
            access_times = [(l.timestamp - sorted_logs[0].timestamp).total_seconds() 
                          for l in sorted_logs]
            if len(access_times) > 1:
                time_diffs = [access_times[i+1] - access_times[i] 
                            for i in range(len(access_times)-1)]
                avg_time_between_accesses = np.mean(time_diffs)
            else:
                avg_time_between_accesses = 0
            
            # User agent entropy (diversity of user agents)
            user_agents = [l.user_agent or '' for l in sorted_logs]
            unique_agents = len(set(user_agents))
            user_agent_entropy = unique_agents / len(user_agents) if user_agents else 0
            
            # Unique IPs cluster (for lateral movement detection)
            unique_ips = len(set([l.source_ip for l in sorted_logs]))
            
            # Geolocation feature (simplified: flag if IP changed)
            geolocation_distance = 0  # Would integrate with GeoIP service
            
            features.append({
                'source_ip': source_ip,
                'hour_of_day': hour_of_day,
                'day_of_week': day_of_week,
                'request_frequency_per_hour': request_frequency,
                'unique_ips_accessed_from': unique_ips,
                'avg_time_between_accesses': avg_time_between_accesses,
                'user_agent_entropy': user_agent_entropy,
                'geolocation_distance_from_baseline': geolocation_distance,
                'num_accesses': len(sorted_logs),
                'last_timestamp': last_timestamp
            })
        
        return pd.DataFrame(features) if features else pd.DataFrame()
    
    def train(self, attack_logs: List[AttackLog], baseline_hours: int = 72):
        """Train anomaly detectors on historical logs"""
        features_df = self.extract_features(attack_logs, baseline_hours)
        
        if features_df.empty:
            logger.warning("No features extracted for anomaly detector training")
            return
        
        X = features_df[self.feature_columns].copy()
        X_scaled = self.scaler.fit_transform(X)
        
        try:
            self.isolation_forest.fit(X_scaled)
            self.lof.fit(X_scaled)
            logger.info(f"Anomaly detector trained on {len(features_df)} samples")
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}")
    
    def detect(self, attack_log: AttackLog) -> Tuple[float, bool, str]:
        """
        Detect if a single attack log is anomalous.
        
        Returns:
            (anomaly_score, is_anomalous, reason)
        """
        # Get recent logs from same source IP for context
        session = get_db_session()
        try:
            baseline_hours = 72
            cutoff = datetime.utcnow() - timedelta(hours=baseline_hours)
            recent_logs = session.query(AttackLog).filter(
                AttackLog.source_ip == attack_log.source_ip,
                AttackLog.timestamp >= cutoff
            ).all()
            
            if not recent_logs:
                # No baseline, assume normal
                return 0.5, False, "No baseline data available"
            
            features_df = self.extract_features(recent_logs + [attack_log])
            if features_df.empty:
                return 0.5, False, "Unable to extract features"
            
            X = features_df[self.feature_columns].copy()
            X_scaled = self.scaler.transform(X)
            
            # Get latest record (the one we just added)
            latest_point = X_scaled[-1:] if len(X_scaled) > 0 else None
            if latest_point is None:
                return 0.5, False, "No data to analyze"
            
            # Isolation Forest prediction (-1 = outlier, 1 = inlier)
            iso_pred = self.isolation_forest.predict(latest_point)[0]
            iso_score = -self.isolation_forest.score_samples(latest_point)[0]
            
            # LOF prediction
            lof_pred = self.lof.predict(latest_point)[0]
            lof_score = -self.lof.negative_outlier_factor_[0]  # Convert to positive scale
            
            # Combine scores: average of both normalized (0-1)
            iso_score_norm = 1 / (1 + np.exp(-iso_score))  # Sigmoid normalization
            lof_score_norm = 1 / (1 + np.exp(-lof_score))
            
            anomaly_score = (iso_score_norm + lof_score_norm) / 2
            is_anomalous = iso_pred == -1 or lof_pred == -1
            
            # Generate explanation
            reason = self._generate_reason(features_df.iloc[-1], 
                                          features_df.iloc[:-1] if len(features_df) > 1 else None,
                                          is_anomalous)
            
            return float(anomaly_score), bool(is_anomalous), reason
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return 0.5, False, f"Detection error: {str(e)}"
        finally:
            session.close()
    
    def _generate_reason(self, current: pd.Series, 
                        baseline: Optional[pd.DataFrame], 
                        is_anomalous: bool) -> str:
        """Generate human-readable explanation for anomaly"""
        reasons = []
        
        if not is_anomalous:
            return "Access patterns within normal range"
        
        if baseline is None or baseline.empty:
            return "Insufficient baseline for comparison"
        
        baseline_mean = baseline[self.feature_columns].mean()
        baseline_std = baseline[self.feature_columns].std()
        
        for col in self.feature_columns:
            if baseline_std[col] == 0:
                continue
            z_score = abs((current[col] - baseline_mean[col]) / baseline_std[col])
            if z_score > 2:  # 2 sigma deviation
                reasons.append(f"{col}: {z_score:.1f}σ deviation")
        
        if not reasons:
            reasons.append("Anomalous pattern detected by ML models")
        
        return " | ".join(reasons[:3])  # Top 3 reasons
    
    def batch_detect(self, attack_logs: List[AttackLog]) -> List[Tuple[str, float, bool]]:
        """Detect anomalies in multiple logs, return (log_id, score, is_anomalous)"""
        results = []
        for log in attack_logs:
            score, is_anomalous, reason = self.detect(log)
            results.append((log.id, score, is_anomalous))
        return results
    
    def store_results(self, attack_log: AttackLog, anomaly_score: float, 
                     is_anomalous: bool, reason: str, algorithm: str = "ensemble"):
        """Store anomaly detection results in database"""
        session = get_db_session()
        try:
            result = AnomalyDetection(
                attack_log_id=str(attack_log.id),
                anomaly_score=anomaly_score,
                is_anomalous=is_anomalous,
                algorithm=algorithm,
                deviation_type="multi_feature" if is_anomalous else "normal",
                reason=reason,
                detected_at=datetime.utcnow()
            )
            session.add(result)
            session.commit()
            logger.info(f"Stored anomaly detection for log {attack_log.id}: score={anomaly_score:.3f}")
        except Exception as e:
            logger.error(f"Error storing anomaly result: {e}")
        finally:
            session.close()


# Global instance for easy access
anomaly_engine = None

def init_anomaly_engine(baseline_logs: Optional[List[AttackLog]] = None):
    """Initialize the global anomaly detector"""
    global anomaly_engine
    anomaly_engine = AnomalyDetectionEngine()
    if baseline_logs:
        anomaly_engine.train(baseline_logs)
    logger.info("Anomaly detection engine initialized")

def get_anomaly_engine() -> AnomalyDetectionEngine:
    """Get or initialize the anomaly detector"""
    global anomaly_engine
    if anomaly_engine is None:
        init_anomaly_engine()
    return anomaly_engine
