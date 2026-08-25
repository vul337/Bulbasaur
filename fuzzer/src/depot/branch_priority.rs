use std::cmp::Ordering;

/// `BranchPriority` is used in the priority queues of the depot.
#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct BranchPriority{
    pub pri: u64,
    timestamp: u64, // Timestamp when the seed entered the queue
}

impl BranchPriority {
    pub fn new(timestamp: u64) -> Self {
        Self {
            pri: 0,
            timestamp,
        }
    }

    pub fn branch_inc(&self) -> Self {
        BranchPriority { pri: self.pri + 1, timestamp: self.timestamp }
    }
}

impl Ord for BranchPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        /*
            The smaller the priority value (pri), the closer to the front.
            If pris are equal, the seed that entered the queue earlier comes first.
         */
        self.pri.cmp(&other.pri)
            .reverse()
            .then_with(|| self.timestamp.cmp(&other.timestamp).reverse())
    }
}

impl PartialOrd for BranchPriority {
    fn partial_cmp(&self, other: &BranchPriority) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}