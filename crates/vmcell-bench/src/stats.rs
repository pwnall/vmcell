//! Pure rank statistics: median, the tie-corrected Mann-Whitney U test, and the common-language
//! effect size.
//!
//! WHY A RANK TEST AND NOT A DELTA OF MEDIANS. On 2026-08-21 a first single-pass matrix reported
//! six deltas of 10% or more. Under repeats, five of them evaporated and one reversed sign: boot
//! latency on a shared host is heavy-tailed and drifts, so one p50 against another p50 is a
//! coin-flip dressed as a measurement. A rank test over repeated, interleaved samples is the
//! cheapest thing that can say "this did not move" out loud, and it makes no distributional
//! assumption a boot-time sample would violate.
//!
//! WHY THE ARITY FLOOR IS A `None` AND NOT A WARNING. [`mann_whitney`] returns `None` when either
//! arm has fewer than two samples. A verdict from one sample per arm is the exact defect this
//! whole harness exists to prevent, so it is unrepresentable rather than discouraged — there is no
//! `RankTest` value a caller could print for such a comparison.
//!
//! Everything here is pure: no clock, no filesystem, no VM. AGENTS.md's rule for harness math
//! applies — the tests below assert against values worked out by hand from the textbook
//! definitions (the arithmetic is spelled out at each site so a reviewer can re-check it), never
//! against this module's own output.

/// The median of `samples`, or `None` when empty.
///
/// Takes the samples in any order and sorts a copy, so a caller cannot accidentally hand it a
/// half-sorted buffer and get a plausible wrong answer. Even counts average the two middle values.
///
/// Ordering is `f64::total_cmp`, so a NaN sample sorts to one end rather than poisoning the
/// comparison; NaN is not expected in a latency series and is not silently dropped either — it
/// would show up as an absurd median, which is the loud outcome.
#[must_use]
pub fn median(samples: &[f64]) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let mid = n / 2;
    if n % 2 == 1 {
        sorted.get(mid).copied()
    } else {
        // `mid >= 1` here because `n` is even and non-zero.
        let lo = sorted.get(mid - 1)?;
        let hi = sorted.get(mid)?;
        Some((lo + hi) / 2.0)
    }
}

/// The outcome of a two-sample Mann-Whitney U test.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RankTest {
    /// U for the **second** sample: the number of (a, b) pairs with `b > a`, counting a tie as a
    /// half. Equivalently `R_b - n_b(n_b + 1)/2` over midranks. Reporting U for one named sample
    /// rather than `min(U_a, U_b)` is what makes [`RankTest::prob_b_greater`] a direction, not just
    /// a magnitude — which is the whole question when one arm is "after the change".
    pub u: f64,
    /// Two-sided p-value from the tie-corrected normal approximation with a continuity correction.
    ///
    /// The approximation's own error is ~1.5e-7 absolute, so a p below roughly 1e-6 is a floor
    /// rather than a measurement. That is far below any threshold this harness decides on.
    pub p_two_sided: f64,
    /// The **common-language effect size**: the probability that a value drawn at random from `b`
    /// exceeds one drawn at random from `a`, counting ties as half. It is `u / (n_a * n_b)` — the
    /// same U, not a second computation, so the two can never disagree.
    ///
    /// For a latency metric, "b greater" means the second arm was *slower*: 0.5 is no difference,
    /// 1.0 is "every run of b was slower than every run of a".
    pub prob_b_greater: f64,
}

/// The tie-corrected Mann-Whitney U test of `a` against `b`, two-sided.
///
/// Returns `None` unless **both** arms have at least two samples; see the module docs for why that
/// is a `None` and not a caveat in the output.
///
/// The variance carries the standard tie correction
/// `σ² = (n_a·n_b/12)·[(N+1) − Σ(t³−t)/(N(N−1))]`. When every observation is tied the correction
/// drives `σ²` to exactly zero: the ranking then carries no information at all, so the honest
/// answer is `p = 1.0` — the alternative is a division by zero that reaches the report as `NaN`
/// and sorts wherever the comparator's sort happens to put it.
#[must_use]
pub fn mann_whitney(a: &[f64], b: &[f64]) -> Option<RankTest> {
    if a.len() < 2 || b.len() < 2 {
        return None;
    }

    // (value, is_from_b). Sorted by value; midranks are assigned per tie group.
    let mut pooled: Vec<(f64, bool)> = a
        .iter()
        .map(|&v| (v, false))
        .chain(b.iter().map(|&v| (v, true)))
        .collect();
    pooled.sort_by(|x, y| x.0.total_cmp(&y.0));

    let mut rank_sum_b = 0.0_f64;
    let mut tie_term = 0.0_f64; // Σ (t³ − t) over tie groups
    let mut start = 0usize;
    while start < pooled.len() {
        let value = pooled.get(start)?.0;
        let mut end = start;
        while pooled.get(end + 1).is_some_and(|next| next.0 == value) {
            end += 1;
        }
        // Ranks are 1-based, so the group spans ranks `start+1 ..= end+1` and every member takes
        // their average.
        let midrank = ((start + 1) as f64 + (end + 1) as f64) / 2.0;
        let group = end - start + 1;
        for offset in start..=end {
            if pooled.get(offset)?.1 {
                rank_sum_b += midrank;
            }
        }
        let t = group as f64;
        tie_term += t * t * t - t;
        start = end + 1;
    }

    let n_a = a.len() as f64;
    let n_b = b.len() as f64;
    let n_total = n_a + n_b;
    let u_b = rank_sum_b - n_b * (n_b + 1.0) / 2.0;
    let mean = n_a * n_b / 2.0;
    let variance = (n_a * n_b / 12.0) * ((n_total + 1.0) - tie_term / (n_total * (n_total - 1.0)));

    let p_two_sided = if variance <= 0.0 {
        1.0
    } else {
        // Continuity correction, floored at zero: the statistic is discrete, and without the floor
        // a U sitting exactly on the mean would produce a negative z whose |z| is 0.5 — i.e. a
        // p < 1 for a sample with no difference whatsoever.
        let z = ((u_b - mean).abs() - 0.5).max(0.0) / variance.sqrt();
        two_sided_p(z)
    };

    Some(RankTest {
        u: u_b,
        p_two_sided,
        prob_b_greater: u_b / (n_a * n_b),
    })
}

/// Holm-Bonferroni step-down adjusted p-values, returned **in the caller's input order**.
///
/// WHY A CORRECTION AT ALL. `bench-ab`'s default matrix produces about twenty comparable rows, and
/// before this each one got its own uncorrected two-sided test at 0.05. Under a null where nothing
/// changed, the chance that at least one of twenty rows clears 0.05 is `1 - 0.95^20` ≈ 64% — so the
/// *expected* output of a no-op change was a table with a verdict word in it. For a tool whose one
/// job is to stop reporting phantoms (five of six single-pass "deltas" on 2026-08-21 evaporated
/// under repeats), an uncorrected family was the wrong default.
///
/// WHY HOLM AND NOT PLAIN BONFERRONI. Holm controls the same family-wise error rate and is
/// uniformly more powerful: it is never more conservative than Bonferroni for any hypothesis, and
/// it is strictly less conservative for all but the smallest p. A benchmark comparator that misses
/// a real regression is not "safe", so the free power is worth having.
///
/// THE RULE, worked from the definition: sort the p-values ascending; the `i`-th smallest (0-based)
/// is multiplied by `n - i`; then the sequence is made **monotone non-decreasing** by taking a
/// running maximum, and each value is clamped to 1. The running maximum is the step-down half and
/// is not decoration — without it a large raw p can adjust to *less* than a smaller one's
/// adjustment, and a reader sorting by the adjusted column would see the order invert.
///
/// Returns an empty vector for an empty input: a family of nothing needs no correction, and the
/// caller's own emptiness check is a better place to complain than a panic here. Ordering uses
/// `f64::total_cmp`, so a NaN sorts to one end rather than scrambling the comparison.
#[must_use]
pub fn holm_bonferroni(p_values: &[f64]) -> Vec<f64> {
    let n = p_values.len();
    if n == 0 {
        return Vec::new();
    }
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&x, &y| match (p_values.get(x), p_values.get(y)) {
        (Some(a), Some(b)) => a.total_cmp(b),
        _ => std::cmp::Ordering::Equal,
    });
    let mut adjusted = vec![1.0_f64; n];
    let mut running_max = 0.0_f64;
    for (rank, &index) in order.iter().enumerate() {
        let raw = p_values.get(index).copied().unwrap_or(1.0);
        let scaled = (raw * (n - rank) as f64).clamp(0.0, 1.0);
        running_max = running_max.max(scaled);
        if let Some(slot) = adjusted.get_mut(index) {
            *slot = running_max;
        }
    }
    adjusted
}

/// Two-sided p-value for a standard-normal deviate `z`: `erfc(|z| / √2)`.
///
/// Clamped to `0.0..=1.0` because the `erf` approximation below loses its last digits to
/// cancellation far out in the tail, and a p-value printed as `-1e-9` is nonsense a reader would
/// nonetheless believe.
fn two_sided_p(z: f64) -> f64 {
    (1.0 - erf(z.abs() / std::f64::consts::SQRT_2)).clamp(0.0, 1.0)
}

/// `erf(x)` via Abramowitz & Stegun 7.1.26 (maximum absolute error 1.5e-7).
///
/// A polynomial approximation rather than a dependency: the harness's decisions are thresholds at
/// p = 0.05, six orders of magnitude above this error, and a new crate in the dependency graph is
/// a licence scan, a `cargo machete` entry and a supply-chain edge for arithmetic that fits in ten
/// lines.
fn erf(x: f64) -> f64 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let poly = ((((1.061_405_429 * t - 1.453_152_027) * t + 1.421_413_741) * t - 0.284_496_736)
        * t
        + 0.254_829_592)
        * t;
    sign * (1.0 - poly * (-x * x).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute tolerance for values quoted from a standard normal table (four to seven decimals)
    /// against an approximation whose own error is 1.5e-7.
    const TABLE_EPS: f64 = 1e-6;

    #[test]
    fn median_of_odd_even_and_degenerate_samples() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[7.5]), Some(7.5));
        // Unsorted input: the function sorts a copy, which is the whole reason it takes `&[f64]`.
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
        // Even count where the two middles differ by more than rounding: (10+20)/2.
        assert_eq!(median(&[1.0, 10.0, 20.0, 100.0]), Some(15.0));
    }

    #[test]
    fn two_sided_p_matches_the_standard_normal_table() {
        // Textbook table values, not this code's output:
        //   Φ(1)      = 0.8413447  → 2(1−Φ) = 0.3173105
        //   Φ(1.96)   = 0.9750021  → 2(1−Φ) = 0.0499958
        //   Φ(2)      = 0.9772499  → 2(1−Φ) = 0.0455003
        //   Φ(2.5758) = 0.9950000  → 2(1−Φ) = 0.0100000  (the 99% two-sided critical value)
        //   Φ(3)      = 0.9986501  → 2(1−Φ) = 0.0026998
        for (z, expected) in [
            (0.0, 1.0),
            (1.0, 0.317_310_5),
            (1.959_964, 0.05),
            (2.0, 0.045_500_3),
            (2.575_829_3, 0.01),
            (3.0, 0.002_699_8),
        ] {
            let got = two_sided_p(z);
            assert!(
                (got - expected).abs() < TABLE_EPS,
                "two_sided_p({z}) = {got}, table says {expected}"
            );
        }
    }

    #[test]
    fn u_matches_the_tortoise_and_hare_worked_example() {
        // The classic textbook illustration: six tortoises and six hares run one race, finishing
        //     T H H H H H T T T T T H
        // Direct method, worked by hand: the leading tortoise beats all 6 hares; the other five
        // each beat only the hare that finished last → U = 6 + 1 + 1 + 1 + 1 + 1 = 11 (of a
        // maximum n_a·n_b = 36).
        //
        // Same number by the OTHER route, also by hand: with finishing positions as the values the
        // ranks are 1..12, so R_hares = 2+3+4+5+6+12 = 32 and U = 32 − 6·7/2 = 32 − 21 = 11.
        //
        // `a` = tortoise finishing positions, `b` = hare finishing positions. `u` counts pairs with
        // b > a, i.e. pairs where the tortoise finished first — which is what the direct method
        // above counted.
        let tortoises = [1.0, 7.0, 8.0, 9.0, 10.0, 11.0];
        let hares = [2.0, 3.0, 4.0, 5.0, 6.0, 12.0];
        let test = mann_whitney(&tortoises, &hares).expect("six samples per arm");
        assert!((test.u - 11.0).abs() < 1e-12, "U = {}", test.u);
        assert!(
            (test.prob_b_greater - 11.0 / 36.0).abs() < 1e-12,
            "CL effect size = {}",
            test.prob_b_greater
        );
        // The example is the textbook's illustration of a result that is NOT significant.
        assert!(
            test.p_two_sided > 0.05,
            "p = {} for a worked example whose whole point is non-significance",
            test.p_two_sided
        );
    }

    #[test]
    fn identical_samples_are_no_evidence() {
        let a = [1.0, 2.0, 3.0, 4.0];
        let b = [1.0, 2.0, 3.0, 4.0];
        // By hand: each value is tied across the arms, so the midranks are 1.5, 3.5, 5.5, 7.5 and
        // R_b = 18; U = 18 − 4·5/2 = 8, exactly the mean n_a·n_b/2 = 8. z = 0 → p = 1.
        let test = mann_whitney(&a, &b).expect("four samples per arm");
        assert!((test.u - 8.0).abs() < 1e-12, "U = {}", test.u);
        // TABLE_EPS, not exact equality: `erf(0)` under A&S 7.1.26 is 1e-9 rather than 0, so p
        // comes back as 0.999999999. That is the approximation's documented 1.5e-7 error showing
        // its face, and pinning the test to 1e-12 here would have been a demand for precision the
        // module openly does not claim.
        assert!(
            (test.p_two_sided - 1.0).abs() < TABLE_EPS,
            "p = {}",
            test.p_two_sided
        );
        assert!((test.prob_b_greater - 0.5).abs() < 1e-12);
    }

    #[test]
    fn fully_separated_samples_are_significant_at_five_per_arm() {
        let a = [1.0, 2.0, 3.0, 4.0, 5.0];
        let b = [6.0, 7.0, 8.0, 9.0, 10.0];
        // By hand: R_b = 6+7+8+9+10 = 40, U = 40 − 5·6/2 = 25 = n_a·n_b, the maximum.
        // σ² = (25/12)·11 = 22.9167, σ = 4.78714; z = (12.5 − 0.5)/4.78714 = 2.50672;
        // 2(1 − Φ(2.50672)) ≈ 0.0122 — below 0.05, which is the claim the harness makes at n = 5.
        let test = mann_whitney(&a, &b).expect("five samples per arm");
        assert!((test.u - 25.0).abs() < 1e-12, "U = {}", test.u);
        assert!((test.prob_b_greater - 1.0).abs() < 1e-12);
        assert!(
            test.p_two_sided < 0.05,
            "p = {} for two fully separated arms of five",
            test.p_two_sided
        );
        assert!(
            (test.p_two_sided - 0.0122).abs() < 1e-3,
            "p = {}, hand-computed 0.0122",
            test.p_two_sided
        );
        // Direction, not just magnitude: reversing the arms must move the effect size to the other
        // end, or a REGRESSION and an IMPROVEMENT are indistinguishable in the table.
        let reversed = mann_whitney(&b, &a).expect("five samples per arm");
        assert!((reversed.prob_b_greater - 0.0).abs() < 1e-12);
    }

    #[test]
    fn unequal_arm_sizes_are_not_interchangeable() {
        // WHY THIS FIXTURE EXISTS. Every other fixture in this module is equal-sized (6v6, 4v4,
        // 5v5, 3v3), and `n_a` and `n_b` appear in four places in `mann_whitney`: the U
        // subtraction, the mean, the variance, and the effect-size denominator. With n_a == n_b
        // each of those four one-token confusions is a no-op, so the whole suite stayed green
        // through all four of them. An A/B arm that dropped an iteration is unequal by
        // construction, so this is the shape the harness actually meets.
        //
        // Worked by hand, five against three with no ties. Pooled ascending, the a-values take
        // ranks 1..5 and the b-values ranks 6..8:
        //   R_b = 6 + 7 + 8 = 21
        //   U_b = R_b − n_b(n_b+1)/2 = 21 − 3·4/2 = 21 − 6 = 15  = n_a·n_b, the maximum
        //   CL  = U_b / (n_a·n_b) = 15/15 = 1.0
        //   mean = n_a·n_b/2 = 7.5
        //   σ²  = (n_a·n_b/12)·(N+1) = (15/12)·9 = 11.25, σ = 3.354102
        //   z   = (|15 − 7.5| − 0.5)/3.354102 = 7/3.354102 = 2.086997 → p = 0.036888
        //
        // Each of the four confusions lands outside one of the assertions below:
        //   U subtraction with n_a  → U = 21 − 15 = 6   (the `u` assert)
        //   mean with n_a           → z = 2/3.354 = 0.596, p = 0.551  (the `p` assert)
        //   variance with n_a       → σ² = (25/12)·9 = 18.75, p = 0.106  (the `p` assert)
        //   CL denominator n_a·n_a  → 15/25 = 0.6  (the `prob_b_greater` assert)
        let a = [1.0, 2.0, 3.0, 4.0, 5.0];
        let b = [6.0, 7.0, 8.0];
        let test = mann_whitney(&a, &b).expect("five and three samples");
        assert!(
            (test.u - 15.0).abs() < 1e-12,
            "U = {}, hand-worked 15",
            test.u
        );
        assert!(
            (test.prob_b_greater - 1.0).abs() < 1e-12,
            "CL = {}, hand-worked 1.0 (every b above every a)",
            test.prob_b_greater
        );
        assert!(
            (test.p_two_sided - 0.036_888).abs() < 1e-3,
            "p = {}, hand-computed 0.036888",
            test.p_two_sided
        );

        // The same two arms the other way round, which is where a swapped `n_a`/`n_b` in the U
        // subtraction shows up as a *different* wrong number: R_b is now 1+2+3+4+5 = 15 over
        // n_b = 5, so U = 15 − 5·6/2 = 0 and the effect size is 0.0. The p is unchanged — the
        // test is two-sided and the arms are the same two arms.
        let reversed = mann_whitney(&b, &a).expect("three and five samples");
        assert!((reversed.u - 0.0).abs() < 1e-12, "U = {}", reversed.u);
        assert!((reversed.prob_b_greater - 0.0).abs() < 1e-12);
        assert!(
            (reversed.p_two_sided - test.p_two_sided).abs() < 1e-12,
            "a two-sided p must not depend on which arm was named first: {} vs {}",
            reversed.p_two_sided,
            test.p_two_sided
        );
    }

    #[test]
    fn every_observation_tied_does_not_divide_by_zero() {
        let a = [1.0, 1.0, 1.0];
        let b = [1.0, 1.0, 1.0];
        // By hand: all six share midrank 3.5, so R_b = 10.5, U = 10.5 − 3·4/2 = 4.5 = the mean.
        // Σ(t³−t) = 6³ − 6 = 210 and N(N−1) = 30, so the correction is exactly N+1 = 7 and σ² = 0.
        let test = mann_whitney(&a, &b).expect("three samples per arm");
        assert!(test.p_two_sided.is_finite(), "p = {}", test.p_two_sided);
        assert!((test.p_two_sided - 1.0).abs() < 1e-12);
        assert!((test.u - 4.5).abs() < 1e-12, "U = {}", test.u);
        assert!((test.prob_b_greater - 0.5).abs() < 1e-12);
    }

    #[test]
    fn the_tie_correction_is_live_not_decorative() {
        // A heavily tied pair where the correction changes the answer materially, both values
        // computed by hand from the textbook formulae:
        //   a = [1,1,1,2], b = [1,2,2,2]; four 1s take midrank 2.5, four 2s take midrank 6.5.
        //   R_b = 2.5 + 3·6.5 = 22, U = 22 − 4·5/2 = 12, mean = 8.
        //   Σ(t³−t) = (64−4)·2 = 120, N(N−1) = 56 → correction 2.142857.
        //   σ² = (16/12)·(9 − 2.142857) = 9.142857, σ = 3.023716.
        //   z = (|12−8| − 0.5)/3.023716 = 1.157526 → p = 2(1 − Φ(1.157526)) = 0.24706.
        // WITHOUT the tie correction σ² would be (16/12)·9 = 12, σ = 3.4641, z = 1.01036 and
        // p = 0.3124 — so this assertion goes red if the correction term is ever dropped, which a
        // no-ties fixture cannot see.
        let a = [1.0, 1.0, 1.0, 2.0];
        let b = [1.0, 2.0, 2.0, 2.0];
        let test = mann_whitney(&a, &b).expect("four samples per arm");
        assert!((test.u - 12.0).abs() < 1e-12, "U = {}", test.u);
        assert!(
            (test.p_two_sided - 0.247_06).abs() < 1e-3,
            "p = {}, hand-computed 0.24706 (uncorrected would be 0.3124)",
            test.p_two_sided
        );
    }

    #[test]
    fn holm_matches_the_hand_worked_family_of_four() {
        // Worked by hand from the definition, n = 4, input order deliberately unsorted:
        //   raw          0.040   0.010   0.030   0.900
        //   ascending    0.010   0.030   0.040   0.900
        //   multiplier   4       3       2       1
        //   scaled       0.040   0.090   0.080   0.900
        //   running max  0.040   0.090   0.090   0.900   <- the step-down half
        // Back in input order: 0.090, 0.040, 0.090, 0.900.
        //
        // The third entry is the whole reason the running maximum exists: its own scaled value is
        // 0.080, BELOW the 0.090 of the p that was smaller than it. Without the monotone pass a
        // reader sorting by the adjusted column would see 0.030 rank after 0.040.
        let raw = [0.040, 0.010, 0.030, 0.900];
        let adjusted = holm_bonferroni(&raw);
        for (got, expected) in adjusted.iter().zip([0.090, 0.040, 0.090, 0.900]) {
            assert!(
                (got - expected).abs() < 1e-12,
                "holm({raw:?}) = {adjusted:?}, hand-worked [0.090, 0.040, 0.090, 0.900]"
            );
        }
        // The smallest p is the one Holm treats exactly as Bonferroni does — n times itself.
        assert!((adjusted.get(1).copied().unwrap_or_default() - 4.0 * 0.010).abs() < 1e-12);
    }

    // THE STEP-DOWN AS A PROPERTY, not just as one hand-worked row. Sorted by RAW p, the adjusted
    // sequence must be non-decreasing — that is the whole content of the running maximum, and
    // without it the table's `p_adj` column is not a column a reader can sort by: a larger raw p
    // can adjust BELOW a smaller one's adjustment, so the row order inverts between the two
    // columns and the reader cannot tell which finding is stronger.
    //
    // The fixture makes the step-down bite TWICE, and both values were cross-checked against an
    // independent implementation of the same textbook rule (R's `p.adjust(method = "holm")`:
    // `cummax(pmin(1, (n - i + 1) * p))` over the ascending order, then unsorted):
    //   ascending    0.037496  0.069855  0.090713  0.424519  0.433646
    //   multiplier   5         4         3         2         1
    //   scaled       0.187480  0.279420  0.272139  0.849038  0.433646
    //   running max  0.187480  0.279420  0.279420  0.849038  0.849038
    //                                    ^^^^^^^^                ^^^^ the two the max rescued
    // The second is the interesting one: the LARGEST raw p in the family takes the SECOND
    // largest's adjustment, which no "multiply by n - i" alone can produce.
    //
    // RED on the inverse (the running maximum dropped, so each entry keeps its own scaled value):
    // the two rescued entries come back as 0.272139 and 0.433646 and the monotonicity assert fails
    // at the pair it exists for.
    #[test]
    fn holm_is_monotone_in_the_raw_p_which_is_what_the_step_down_buys() {
        let raw = [0.037_496, 0.433_646, 0.069_855, 0.090_713, 0.424_519];
        let adjusted = holm_bonferroni(&raw);
        for (got, expected) in adjusted
            .iter()
            .zip([0.187_48, 0.849_038, 0.279_42, 0.279_42, 0.849_038])
        {
            assert!(
                (got - expected).abs() < 1e-9,
                "holm({raw:?}) = {adjusted:?}, reference [0.18748, 0.849038, 0.27942, 0.27942, \
                 0.849038]"
            );
        }

        // …and the property itself, over the ascending order: no adjusted value may fall below the
        // adjustment of any smaller raw p.
        let mut order: Vec<usize> = (0..raw.len()).collect();
        order.sort_by(|&x, &y| raw[x].total_cmp(&raw[y]));
        let mut previous = 0.0_f64;
        for index in order {
            let value = adjusted[index];
            assert!(
                value >= previous - 1e-12,
                "raw {} adjusted to {value}, BELOW the {previous} a smaller raw p got: \
                 {adjusted:?}",
                raw[index]
            );
            previous = value;
        }
    }

    #[test]
    fn holm_is_never_more_conservative_than_bonferroni_and_is_clamped() {
        // Every adjusted value must sit in [raw, min(1, n*raw)]: at least as large as the raw p
        // (a correction that LOWERED a p would manufacture significance), and never above plain
        // Bonferroni (which is the claim that makes Holm worth using at all).
        let raw = [0.001, 0.02, 0.04, 0.2, 0.5, 0.999];
        let n = raw.len() as f64;
        let adjusted = holm_bonferroni(&raw);
        assert_eq!(adjusted.len(), raw.len());
        for (r, a) in raw.iter().zip(&adjusted) {
            assert!(*a >= *r - 1e-12, "raw {r} adjusted DOWN to {a}");
            assert!(
                *a <= (n * r).min(1.0) + 1e-12,
                "raw {r} adjusted to {a}, above Bonferroni {}",
                (n * r).min(1.0)
            );
            assert!((0.0..=1.0).contains(a), "adjusted p out of range: {a}");
        }
        // A p that is already large clamps at 1 rather than reporting 5.994.
        assert!((adjusted.last().copied().unwrap_or_default() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn holm_of_one_test_is_the_raw_p_and_of_none_is_empty() {
        // A family of one has nothing to correct FOR: n - i = 1, so the adjustment is the identity.
        // This is the floor of the whole scheme, and a harness that ran one spec must not have its
        // single finding silently multiplied by anything.
        let single = holm_bonferroni(&[0.0123]);
        assert_eq!(single.len(), 1);
        assert!((single.first().copied().unwrap_or_default() - 0.0123).abs() < 1e-12);
        assert!(holm_bonferroni(&[]).is_empty());
    }

    #[test]
    fn holm_handles_ties_without_reordering_or_disagreeing() {
        // Three identical p-values, n = 3: scaled 0.03, 0.02, 0.01 by rank, running max 0.03 for
        // all three. Every tied hypothesis must get the SAME adjusted p — a tie broken by input
        // order would make the verdict depend on the table's sort.
        let adjusted = holm_bonferroni(&[0.01, 0.01, 0.01]);
        for a in &adjusted {
            assert!((a - 0.03).abs() < 1e-12, "{adjusted:?}");
        }
    }

    #[test]
    fn holm_over_a_twenty_row_matrix_kills_the_phantom_it_exists_for() {
        // The concrete default case: twenty rows, one of which clears 0.05 on its own (0.03) while
        // nineteen are noise. Uncorrected, that row prints a verdict — and under a true null a
        // twenty-row matrix produces at least one such row 64% of the time (1 - 0.95^20). Holm's
        // smallest multiplier is 20, so 0.03 adjusts to 0.6 and the row reads "no evidence".
        let mut raw = vec![0.03];
        raw.extend(std::iter::repeat_n(0.6, 19));
        let adjusted = holm_bonferroni(&raw);
        assert!(
            adjusted.first().copied().unwrap_or_default() > 0.05,
            "0.03 in a family of 20 must not survive: {:?}",
            adjusted.first()
        );
        assert!((adjusted.first().copied().unwrap_or_default() - 0.6).abs() < 1e-12);
        // …and a genuinely strong finding still survives the same family size: 0.001 * 20 = 0.02.
        let mut strong = vec![0.001];
        strong.extend(std::iter::repeat_n(0.6, 19));
        let strong_adjusted = holm_bonferroni(&strong);
        assert!(
            strong_adjusted.first().copied().unwrap_or_default() < 0.05,
            "the correction must not be a blanket silencer: {:?}",
            strong_adjusted.first()
        );
    }

    #[test]
    fn a_single_sample_arm_yields_no_verdict() {
        let many = [1.0, 2.0, 3.0];
        assert!(mann_whitney(&[1.0], &many).is_none());
        assert!(mann_whitney(&many, &[1.0]).is_none());
        assert!(mann_whitney(&[], &many).is_none());
        assert!(mann_whitney(&[1.0], &[2.0]).is_none());
        // Two per arm is the floor, and it must be reachable — a floor nobody can stand on is an
        // off-by-one nobody notices.
        assert!(mann_whitney(&[1.0, 2.0], &[3.0, 4.0]).is_some());
    }
}
