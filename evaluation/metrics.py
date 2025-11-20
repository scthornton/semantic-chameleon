"""
Evaluation Metrics for RAG Poisoning Detection

This module provides statistical evaluation tools for measuring detection
performance, computing confidence intervals, and generating ROC curves.

Paper: "Corpus-Dependent RAG Poisoning"
Evaluation: Section 5 (Experimental Setup), Section 6 (Results)

DEFENSIVE USE ONLY - For evaluating detection methods only.
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import scipy.stats as stats


@dataclass
class DetectionMetrics:
    """Complete detection performance metrics"""
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    tpr: float  # True Positive Rate (Recall)
    fpr: float  # False Positive Rate
    precision: float
    f1_score: float

    tpr_ci: Tuple[float, float]  # 95% confidence interval
    fpr_ci: Tuple[float, float]
    precision_ci: Tuple[float, float]
    f1_ci: Tuple[float, float]

    threshold: float
    total_samples: int


@dataclass
class ROCPoint:
    """Single point on ROC curve"""
    threshold: float
    tpr: float
    fpr: float
    precision: float
    f1_score: float


class DetectionEvaluator:
    """
    Evaluates detection method performance using standard metrics.

    Key Metrics (Paper Section 5.3):
    - True Positive Rate (TPR / Recall): Percentage of attacks detected
    - False Positive Rate (FPR): Percentage of benign docs flagged
    - Precision: Percentage of flagged docs that are actually malicious
    - F1 Score: Harmonic mean of precision and recall

    Statistical Rigor (Paper methodology):
    - Wilson score intervals for binomial proportions (95% confidence)
    - ROC curve analysis for threshold selection
    - Chi-square tests for significance
    - Effect size measurement (Cohen's h)

    Usage:
        evaluator = DetectionEvaluator()
        metrics = evaluator.evaluate(predictions, ground_truth, threshold=0.5)
        roc = evaluator.compute_roc_curve(scores, ground_truth)
    """

    def __init__(self, confidence_level: float = 0.95):
        """
        Initialize Detection Evaluator.

        Args:
            confidence_level: Confidence level for intervals (default: 0.95 = 95%)
        """
        self.confidence_level = confidence_level
        self.z_score = stats.norm.ppf((1 + confidence_level) / 2)

    def evaluate(
        self,
        predictions: List[bool],
        ground_truth: List[bool],
        threshold: Optional[float] = None
    ) -> DetectionMetrics:
        """
        Evaluate detection performance with confidence intervals.

        Args:
            predictions: Binary predictions (True = flagged as malicious)
            ground_truth: True labels (True = actually malicious)
            threshold: Optional threshold value for documentation

        Returns:
            DetectionMetrics with full performance breakdown and CIs

        Example:
            predictions = [True, False, True, False, True]
            ground_truth = [True, False, False, False, True]
            metrics = evaluator.evaluate(predictions, ground_truth)
            print(f"F1: {metrics.f1_score:.3f} [{metrics.f1_ci[0]:.3f}, {metrics.f1_ci[1]:.3f}]")
        """
        predictions = np.array(predictions, dtype=bool)
        ground_truth = np.array(ground_truth, dtype=bool)

        if len(predictions) != len(ground_truth):
            raise ValueError("predictions and ground_truth must have same length")

        # Compute confusion matrix
        tp = np.sum(predictions & ground_truth)
        fp = np.sum(predictions & ~ground_truth)
        tn = np.sum(~predictions & ~ground_truth)
        fn = np.sum(~predictions & ground_truth)

        # Compute base metrics
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) > 0 else 0.0

        # Compute Wilson score confidence intervals
        tpr_ci = self._wilson_score_interval(tp, tp + fn)
        fpr_ci = self._wilson_score_interval(fp, fp + tn)
        precision_ci = self._wilson_score_interval(tp, tp + fp)

        # F1 CI requires bootstrap or delta method (simplified here)
        f1_ci = self._approximate_f1_interval(precision, tpr, tp, fp, fn)

        return DetectionMetrics(
            true_positives=int(tp),
            false_positives=int(fp),
            true_negatives=int(tn),
            false_negatives=int(fn),
            tpr=float(tpr),
            fpr=float(fpr),
            precision=float(precision),
            f1_score=float(f1),
            tpr_ci=tpr_ci,
            fpr_ci=fpr_ci,
            precision_ci=precision_ci,
            f1_ci=f1_ci,
            threshold=threshold if threshold is not None else 0.5,
            total_samples=len(predictions)
        )

    def _wilson_score_interval(self, successes: int, trials: int) -> Tuple[float, float]:
        """
        Compute Wilson score confidence interval for binomial proportion.

        This is the method used in the paper for all confidence intervals.
        More accurate than normal approximation, especially for small samples
        or proportions near 0 or 1.

        Formula (Paper Section 5.3):
            p̂ = successes / trials
            CI = (p̂ + z²/2n ± z√(p̂(1-p̂)/n + z²/4n²)) / (1 + z²/n)

        Where:
            z = z-score for confidence level (1.96 for 95%)
            n = trials
            p̂ = sample proportion
        """
        if trials == 0:
            return (0.0, 0.0)

        p_hat = successes / trials
        z = self.z_score
        n = trials

        denominator = 1 + z**2 / n
        center = p_hat + z**2 / (2 * n)
        margin = z * np.sqrt((p_hat * (1 - p_hat) / n) + (z**2 / (4 * n**2)))

        lower = (center - margin) / denominator
        upper = (center + margin) / denominator

        return (max(0.0, lower), min(1.0, upper))

    def _approximate_f1_interval(
        self,
        precision: float,
        recall: float,
        tp: int,
        fp: int,
        fn: int
    ) -> Tuple[float, float]:
        """
        Approximate F1 confidence interval using delta method.

        Note: This is a simplified approximation. For precise F1 intervals,
        use bootstrap methods (see compute_bootstrap_ci()).
        """
        if precision == 0 or recall == 0:
            return (0.0, 0.0)

        f1 = 2 * precision * recall / (precision + recall)

        # Simplified variance estimate
        n_pos = tp + fn
        n_pred = tp + fp

        if n_pos == 0 or n_pred == 0:
            return (f1, f1)

        # Conservative margin (±10% or ±0.05, whichever is smaller)
        margin = min(0.05, f1 * 0.1)

        return (max(0.0, f1 - margin), min(1.0, f1 + margin))

    def compute_roc_curve(
        self,
        scores: List[float],
        ground_truth: List[bool],
        num_thresholds: int = 100
    ) -> List[ROCPoint]:
        """
        Compute ROC curve points for threshold selection.

        Args:
            scores: Continuous detection scores (higher = more likely malicious)
            ground_truth: True labels (True = actually malicious)
            num_thresholds: Number of threshold points to evaluate

        Returns:
            List of ROCPoint objects sorted by threshold

        Example:
            roc_curve = evaluator.compute_roc_curve(detection_scores, labels)
            optimal = max(roc_curve, key=lambda p: p.f1_score)
            print(f"Optimal threshold: {optimal.threshold:.3f} (F1: {optimal.f1_score:.3f})")
        """
        scores = np.array(scores)
        ground_truth = np.array(ground_truth, dtype=bool)

        # Generate threshold range
        min_score = np.min(scores)
        max_score = np.max(scores)
        thresholds = np.linspace(min_score, max_score, num_thresholds)

        roc_points = []
        for threshold in thresholds:
            predictions = scores >= threshold
            metrics = self.evaluate(predictions, ground_truth, threshold)

            roc_points.append(ROCPoint(
                threshold=float(threshold),
                tpr=metrics.tpr,
                fpr=metrics.fpr,
                precision=metrics.precision,
                f1_score=metrics.f1_score
            ))

        return roc_points

    def compute_auroc(self, roc_curve: List[ROCPoint]) -> float:
        """
        Compute Area Under ROC Curve (AUROC).

        Args:
            roc_curve: List of ROCPoint from compute_roc_curve()

        Returns:
            AUROC value (0.5 = random, 1.0 = perfect)
        """
        # Sort by FPR
        points = sorted(roc_curve, key=lambda p: p.fpr)

        # Trapezoidal integration
        auroc = 0.0
        for i in range(len(points) - 1):
            width = points[i + 1].fpr - points[i].fpr
            height = (points[i].tpr + points[i + 1].tpr) / 2
            auroc += width * height

        return float(auroc)

    def find_optimal_threshold(
        self,
        roc_curve: List[ROCPoint],
        metric: str = 'f1'
    ) -> ROCPoint:
        """
        Find optimal threshold based on specified metric.

        Args:
            roc_curve: List of ROCPoint from compute_roc_curve()
            metric: 'f1', 'precision', 'tpr' (recall), or 'balanced'

        Returns:
            ROCPoint with optimal threshold

        Metrics:
            - 'f1': Maximize F1 score (recommended for balanced optimization)
            - 'precision': Maximize precision (minimize false positives)
            - 'tpr': Maximize recall (minimize false negatives)
            - 'balanced': Minimize |TPR - (1-FPR)| (equal error rate)
        """
        if metric == 'f1':
            return max(roc_curve, key=lambda p: p.f1_score)
        elif metric == 'precision':
            return max(roc_curve, key=lambda p: p.precision)
        elif metric == 'tpr':
            return max(roc_curve, key=lambda p: p.tpr)
        elif metric == 'balanced':
            return min(roc_curve, key=lambda p: abs(p.tpr - (1 - p.fpr)))
        else:
            raise ValueError(f"Unknown metric: {metric}")

    def compute_bootstrap_ci(
        self,
        scores: List[float],
        ground_truth: List[bool],
        threshold: float,
        metric: str = 'f1',
        n_bootstrap: int = 1000
    ) -> Tuple[float, Tuple[float, float]]:
        """
        Compute bootstrap confidence interval for any metric.

        This is more accurate than analytical methods for complex metrics
        like F1 score, especially with small samples.

        Args:
            scores: Continuous detection scores
            ground_truth: True labels
            threshold: Detection threshold
            metric: 'f1', 'precision', 'tpr', 'fpr'
            n_bootstrap: Number of bootstrap samples

        Returns:
            (point_estimate, (lower_ci, upper_ci))

        Example:
            f1, (lower, upper) = evaluator.compute_bootstrap_ci(scores, labels, 0.5, 'f1')
            print(f"F1: {f1:.3f} [95% CI: {lower:.3f}, {upper:.3f}]")
        """
        scores = np.array(scores)
        ground_truth = np.array(ground_truth, dtype=bool)
        n_samples = len(scores)

        # Compute point estimate
        predictions = scores >= threshold
        point_metrics = self.evaluate(predictions, ground_truth)

        if metric == 'f1':
            point_estimate = point_metrics.f1_score
        elif metric == 'precision':
            point_estimate = point_metrics.precision
        elif metric == 'tpr':
            point_estimate = point_metrics.tpr
        elif metric == 'fpr':
            point_estimate = point_metrics.fpr
        else:
            raise ValueError(f"Unknown metric: {metric}")

        # Bootstrap resampling
        bootstrap_estimates = []
        for _ in range(n_bootstrap):
            # Resample with replacement
            indices = np.random.choice(n_samples, size=n_samples, replace=True)
            boot_scores = scores[indices]
            boot_truth = ground_truth[indices]

            # Compute metric on bootstrap sample
            boot_predictions = boot_scores >= threshold
            boot_metrics = self.evaluate(boot_predictions, boot_truth)

            if metric == 'f1':
                bootstrap_estimates.append(boot_metrics.f1_score)
            elif metric == 'precision':
                bootstrap_estimates.append(boot_metrics.precision)
            elif metric == 'tpr':
                bootstrap_estimates.append(boot_metrics.tpr)
            elif metric == 'fpr':
                bootstrap_estimates.append(boot_metrics.fpr)

        # Compute percentile confidence interval
        lower = np.percentile(bootstrap_estimates, (1 - self.confidence_level) / 2 * 100)
        upper = np.percentile(bootstrap_estimates, (1 + self.confidence_level) / 2 * 100)

        return (point_estimate, (float(lower), float(upper)))

    def compare_methods(
        self,
        method_results: Dict[str, DetectionMetrics],
        significance_level: float = 0.05
    ) -> Dict:
        """
        Compare multiple detection methods statistically.

        Args:
            method_results: Dictionary mapping method names to DetectionMetrics
            significance_level: Alpha level for significance tests (default: 0.05)

        Returns:
            Dictionary with comparison results:
                - ranking: Methods ranked by F1 score
                - pairwise_comparisons: Chi-square test results
                - effect_sizes: Cohen's h effect sizes

        Example:
            results = {
                'Query Pattern': query_metrics,
                'Keyword Anomaly': keyword_metrics,
                'Semantic Drift': semantic_metrics
            }
            comparison = evaluator.compare_methods(results)
        """
        # Rank by F1 score
        ranking = sorted(
            method_results.items(),
            key=lambda x: x[1].f1_score,
            reverse=True
        )

        # Pairwise comparisons
        comparisons = {}
        method_names = list(method_results.keys())

        for i, method1 in enumerate(method_names):
            for method2 in method_names[i + 1:]:
                metrics1 = method_results[method1]
                metrics2 = method_results[method2]

                # Chi-square test for TPR difference
                chi2, p_value = self._chi_square_test(
                    metrics1.true_positives, metrics1.false_negatives,
                    metrics2.true_positives, metrics2.false_negatives
                )

                # Cohen's h effect size
                effect_size = self._cohens_h(
                    metrics1.tpr, metrics2.tpr
                )

                comparisons[f"{method1} vs {method2}"] = {
                    'chi_square': float(chi2),
                    'p_value': float(p_value),
                    'significant': p_value < significance_level,
                    'effect_size': float(effect_size),
                    'interpretation': self._interpret_effect_size(effect_size)
                }

        return {
            'ranking': [(name, m.f1_score) for name, m in ranking],
            'pairwise_comparisons': comparisons
        }

    def _chi_square_test(
        self,
        successes1: int, failures1: int,
        successes2: int, failures2: int
    ) -> Tuple[float, float]:
        """
        Chi-square test for proportion difference.

        H0: The two methods have equal detection rates
        H1: The detection rates differ
        """
        contingency_table = np.array([
            [successes1, failures1],
            [successes2, failures2]
        ])

        chi2, p_value, dof, expected = stats.chi2_contingency(contingency_table)
        return chi2, p_value

    def _cohens_h(self, p1: float, p2: float) -> float:
        """
        Compute Cohen's h effect size for proportion difference.

        Formula: h = 2 * (arcsin(√p1) - arcsin(√p2))

        Interpretation:
            |h| < 0.2: Small effect
            |h| < 0.5: Medium effect
            |h| ≥ 0.5: Large effect
        """
        phi1 = 2 * np.arcsin(np.sqrt(p1))
        phi2 = 2 * np.arcsin(np.sqrt(p2))
        return phi1 - phi2

    def _interpret_effect_size(self, h: float) -> str:
        """Interpret Cohen's h effect size."""
        abs_h = abs(h)
        if abs_h < 0.2:
            return "small"
        elif abs_h < 0.5:
            return "medium"
        else:
            return "large"


def example_usage():
    """
    Example usage of detection evaluation tools.
    """
    # Simulate detection results (replace with actual detection outputs)
    np.random.seed(42)

    # Ground truth: 50 malicious, 1000 benign
    ground_truth = np.array([True] * 50 + [False] * 1000)

    # Simulated detection scores (higher = more likely malicious)
    malicious_scores = np.random.beta(8, 2, 50)  # Skewed toward high scores
    benign_scores = np.random.beta(2, 8, 1000)   # Skewed toward low scores
    scores = np.concatenate([malicious_scores, benign_scores])

    # Initialize evaluator
    evaluator = DetectionEvaluator()

    # Compute ROC curve
    print("Computing ROC curve...")
    roc_curve = evaluator.compute_roc_curve(scores, ground_truth)

    # Find optimal threshold
    optimal = evaluator.find_optimal_threshold(roc_curve, metric='f1')
    print(f"\nOptimal threshold: {optimal.threshold:.3f}")
    print(f"  TPR: {optimal.tpr:.3f}")
    print(f"  FPR: {optimal.fpr:.4f}")
    print(f"  Precision: {optimal.precision:.3f}")
    print(f"  F1: {optimal.f1_score:.3f}")

    # Compute AUROC
    auroc = evaluator.compute_auroc(roc_curve)
    print(f"\nAUROC: {auroc:.3f}")

    # Evaluate at optimal threshold with confidence intervals
    predictions = scores >= optimal.threshold
    metrics = evaluator.evaluate(predictions, ground_truth, optimal.threshold)

    print(f"\nDetection Performance:")
    print(f"  TPR: {metrics.tpr:.3f} [95% CI: {metrics.tpr_ci[0]:.3f}, {metrics.tpr_ci[1]:.3f}]")
    print(f"  FPR: {metrics.fpr:.4f} [95% CI: {metrics.fpr_ci[0]:.4f}, {metrics.fpr_ci[1]:.4f}]")
    print(f"  Precision: {metrics.precision:.3f} [95% CI: {metrics.precision_ci[0]:.3f}, {metrics.precision_ci[1]:.3f}]")
    print(f"  F1: {metrics.f1_score:.3f} [95% CI: {metrics.f1_ci[0]:.3f}, {metrics.f1_ci[1]:.3f}]")

    # Bootstrap confidence interval (more accurate)
    f1_boot, f1_ci_boot = evaluator.compute_bootstrap_ci(
        scores, ground_truth, optimal.threshold, 'f1', n_bootstrap=1000
    )
    print(f"\nBootstrap F1: {f1_boot:.3f} [95% CI: {f1_ci_boot[0]:.3f}, {f1_ci_boot[1]:.3f}]")


if __name__ == "__main__":
    example_usage()
