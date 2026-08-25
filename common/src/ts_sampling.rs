use ndarray::Array1;
use ndarray_rand::rand_distr::Beta;
use rand::prelude::*;

pub struct TS {
    arm_count: usize,   // Number of arms.
    beta_values: Vec<(usize, usize)>,   // (successes, failures) for each arm's Beta distribution.
}

impl TS {
    pub fn new(arm_count: usize, beta_values: Vec<(usize, usize)>) -> Self {
        Self { 
            arm_count,
            beta_values,
        }
    }

    pub fn ts_sampling(&self) -> Array1<f64> {

        let mut rng = rand::thread_rng();

        Array1::from(
            (0..self.arm_count)
                .map(|arm_id| {
                    Beta::new(self.beta_values[arm_id].0 as f64, self.beta_values[arm_id].1 as f64).unwrap().sample(&mut rng)
                })
                .collect::<Vec<f64>>(),
        )
    }
}