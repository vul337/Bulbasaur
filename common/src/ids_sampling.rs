use ndarray::{Array1, Array2, Axis};
use ndarray_stats::QuantileExt;
use ndarray_rand::rand_distr::Beta;
use rand::prelude::*;

const SAMPLING_COUNT: usize = 1000;

pub struct IDS {
    arm_count: usize,   // Number of arms.
    sampling_count: usize,  // Number of samples drawn from each Beta distribution.
    beta_values: Vec<(usize, usize)>,   // (successes, failures) for each arm's Beta distribution.
}

impl IDS {
    pub fn new(arm_count: usize, beta_values: Vec<(usize, usize)>) -> Self {
        Self { 
            arm_count,
            sampling_count: SAMPLING_COUNT,
            beta_values,
        }
    }

    pub fn ids_sampling(&self) -> Array1<f64> {
        let beta_dists: Vec<Beta<f64>> = self.beta_values
            .iter()
            .map(|&(s, f)| Beta::new(s as f64, f as f64).unwrap())
            .collect();

        let mut rng = rand::thread_rng();

        let thetas = Array2::from_shape_fn((self.arm_count, self.sampling_count), |(a, _)| {
            beta_dists[a].sample(&mut rng)
        });

        self.compute_ids_score(&thetas)
    }

    fn compute_ids_score(&self, thetas: &Array2<f64>) -> Array1<f64> {
        assert!(thetas.shape()[1] == self.sampling_count);

        // M(a, a'): Expected reward of arm a when a' is assumed to be the optimal arm
        let mut maap = Array2::<f64>::zeros((self.arm_count, self.arm_count));
        // p(a'): Probability that arm a' is the optimal arm
        let mut pa = Array1::<f64>::zeros(self.arm_count);
        // mu(a): Posterior mean reward of each arm
        let mu = thetas.mean_axis(Axis(1)).unwrap().to_owned();
        // theta_hat: For each sample, the index of the arm with the highest sampled value
        let theta_hat = thetas.map_axis(Axis(0), |col| col.argmax().unwrap());

        for a in 0..self.arm_count {
            for ap in 0..self.arm_count {
                // Collect indices where arm a is considered the optimal one
                let mut indices = vec![];
                for (i, &val) in theta_hat.iter().enumerate() {
                    if val == a {
                        indices.push(i);
                    }
                }
                // Extract the values of arm ap when a is optimal
                let t_values: Vec<f64> = indices.iter().map(|&i| thetas[[ap, i]]).collect();
                let avg = if t_values.len() > 0 {
                    t_values.iter().sum::<f64>() / t_values.len() as f64
                } else {
                    0.0
                };
                maap[[ap, a]] = avg;

                // Estimate p(a) as the fraction of samples where arm a is optimal
                if ap == a {
                    pa[a] = t_values.len() as f64 / self.sampling_count as f64;
                }
            }
        }

        // Compute posterior expected reward under the belief about the optimal arm
        let rho_star: f64 = (0..self.arm_count)
            .map(|a| pa[a] * maap[[a, a]])
            .sum();

        // Compute expected regret for each arm
        let regret = Array1::from(
            (0..self.arm_count)
                .map(|a| rho_star - mu[a])
                .collect::<Vec<f64>>(),
        );

        // Compute information gain (expected KL divergence)
        let g: Array1<f64> = Array1::from(
            (0..self.arm_count)
                .map(|a| {
                    (0..self.arm_count)
                        .map(|ap| {
                            let p = pa[ap];
                            let m = maap[[a, ap]];
                            let kl = m * (m / mu[a].max(1e-10) + 1e-10).ln()
                                + (1.0 - m) * ((1.0 - m) / (1.0 - mu[a]).max(1e-10) + 1e-10).ln();
                            p * kl
                        })
                        .sum()
                })
                .collect::<Vec<f64>>(),
        );

        // Compute IDS score
        let score = &regret * &regret / &g.mapv(|x| if x < 1e-10 { 1e-10 } else { x });

        score
    }

}