# Statistical Anomaly Detection and Mathematical Methods

Bastion integrates rigorous statistical algorithms directly into SQL query execution plans. By avoiding black-box approximations, Bastion produces mathematically auditable anomaly scores, time-series baselines, and behavioral profiles.

## 1. Numerically Stable Running Variance (Welford's Algorithm)

Naively computing sample variance using $\text{Var}(X) = E[X^2] - (E[X])^2$ suffers from catastrophic numerical cancellation when values are large and variance is small. Bastion implements Welford's recurrence relations in SQL window functions:

$$\bar{x}_k = \bar{x}_{k-1} + \frac{x_k - \bar{x}_{k-1}}{k}$$
$$M_{2,k} = M_{2,k-1} + (x_k - \bar{x}_{k-1})(x_k - \bar{x}_k)$$
$$s^2 = \frac{M_{2,n}}{n - 1}$$

In SQL:

```sql
SELECT
    AVG(val) OVER w AS running_mean,
    STDDEV_POP(val) OVER w AS running_stddev,
    (val - AVG(val) OVER w) / NULLIF(STDDEV_POP(val) OVER w, 0.0) AS z_score
FROM telemetry_time_series
WINDOW w AS (ORDER BY timestamp ROWS BETWEEN 60 PRECEDING AND CURRENT ROW);
```

Observations with $|Z| > 3.0$ are classified as 3-sigma statistical outliers.

## 2. Robust Outlier Detection via Median Absolute Deviation (MAD)

Unlike the standard deviation, which is sensitive to extreme adversarial outliers, Median Absolute Deviation (MAD) possesses a 50% breakdown point.

$$\text{MAD} = \text{median}(|x_i - \tilde{x}|)$$
$$\text{Modified } Z\text{-Score} = \frac{0.6745 \cdot (x_i - \tilde{x})}{\text{MAD}}$$

Points with $|\text{Modified } Z| > 3.5$ indicate anomalies even in contaminated telemetry corpora.

## 3. Cumulative Sum (CUSUM) Shift Detection

The CUSUM algorithm detects small, persistent parameter shifts in sequential telemetry metrics (e.g. gradual increase in authentication failures or DNS entropy):

$$S_0 = 0$$
$$S_k^+ = \max(0, S_{k-1}^+ + (x_k - \mu_0 - k))$$
$$S_k^- = \max(0, S_{k-1}^- - (x_k - \mu_0 + k))$$

When $S_k^+$ or $S_k^-$ exceeds decision boundary $H$, an alert is triggered. Bastion implements this recursively in `sql/functions/math_stats.sql`.

## 4. Periodic Command and Control (C2) Beaconing Model

Adversary malware implants communicate on regular intervals (e.g., every 60 seconds with 5% jitter). Bastion detects periodic flows by analyzing the coefficient of variation ($CV$) of inter-arrival time deltas.

### Mathematical Formulation
Given packet timestamps $t_1, t_2, \ldots, t_N$:
1. Inter-arrival time intervals:
   $$\Delta t_i = t_i - t_{i-1}, \quad i = 2, \ldots, N$$
2. Sample mean interval:
   $$\bar{\Delta t} = \frac{1}{N-1} \sum_{i=2}^N \Delta t_i$$
3. Standard deviation of intervals:
   $$\sigma_{\Delta t} = \sqrt{\frac{1}{N-2} \sum_{i=2}^N (\Delta t_i - \bar{\Delta t})^2}$$
4. Coefficient of Variation:
   $$CV = \frac{\sigma_{\Delta t}}{\bar{\Delta t}}$$

### Decision Matrix

| Metric Condition | Traffic Classification | Confidence Score |
|:---|:---|:---|
| $CV \le 0.10$ and $N \ge 8$ | `CRITICAL_HIGH_PRECISION_BEACON` | 98.0 |
| $CV \le 0.20$ and $N \ge 5$ | `HIGH_SUSPICION_BEACON_ACTIVITY` | 85.0 |
| $CV \le 0.35$ and $N \ge 5$ | `EVALUATE_JITTERED_BEACON` | 65.0 |
| $CV > 0.35$ | `BENIGN_RANDOM_TRAFFIC` | 20.0 |

Bastion computes this in `v_c2_beaconing_candidates` in sub-50ms execution latency.

## 5. Impossible Travel Geodesic Velocity

Given two consecutive authentication events $(t_1, \phi_1, \lambda_1)$ and $(t_2, \phi_2, \lambda_2)$ for the same identity principal:

### Haversine Formula
$$\Delta \phi = \phi_2 - \phi_1, \quad \Delta \lambda = \lambda_2 - \lambda_1$$
$$a = \sin^2\left(\frac{\Delta \phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta \lambda}{2}\right)$$
$$d = 2 R \cdot \arcsin(\sqrt{a})$$
where $R = 6371.0\text{ km}$ (mean radius of Earth).

### Velocity Model
$$v = \frac{d}{\Delta t} \quad (\text{km/h})$$

```sql
CASE
    WHEN (geodesic_distance_km / delta_hours) >= 1200.0 THEN 'IMPOSSIBLE_SUPERSONIC_TRAVEL'
    WHEN (geodesic_distance_km / delta_hours) >= 800.0  THEN 'SUSPICIOUS_HIGH_SPEED_TRANSIT'
    ELSE 'PLAUSIBLE_TRAVEL'
END AS travel_classification
```

## 6. Domain Generation Algorithm (DGA) Lexical Entropy

Malware often generates pseudo-random subdomains to bypass static DNS sinkholes. Bastion calculates Shannon entropy $H(S)$ on second-level domain (SLD) strings:

$$H(S) = -\sum_{i=1}^k p(c_i) \log_2 p(c_i)$$

where $p(c_i)$ is the frequency ratio of character $c_i$ in string $S$.

### Features Extracted in SQL:
1. **SLD Length**: $L = \text{length}(S)$
2. **Vowel Ratio**: $R_v = \frac{\text{count}(\text{vowels})}{L}$
3. **Digit Ratio**: $R_d = \frac{\text{count}(\text{digits})}{L}$
4. **Lexical Entropy Proxy**: Calculated via character distribution frequency

Domains with $H(S) \ge 3.5$, $R_v \le 0.20$, and $L \ge 12$ are classified as candidate DGA resolutions in `v_dga_candidate_domains`.

## 7. Benford's Law Chi-Square Goodness-of-Fit

Benford's Law states that the leading digit $d \in \{1, \ldots, 9\}$ in naturally occurring numerical datasets follows:

$$P(d) = \log_{10}\left(1 + \frac{1}{d}\right)$$

Adversaries fabricating synthetic financial transactions or exfiltration payloads generate unnatural uniform digit distributions. Bastion evaluates the Pearson Chi-Square statistic:

$$\chi^2 = \sum_{d=1}^9 \frac{(O_d - E_d)^2}{E_d}$$

where $O_d$ is the observed count and $E_d = N \cdot P(d)$ is the expected count under Benford's Law. Values exceeding critical value $\chi_{0.05, 8}^2 = 15.51$ indicate statistical manipulation.
