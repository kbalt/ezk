/// Helper type to calculate packet loss from received & lost events
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct PacketLoss {
    loss: f32,
}

impl PacketLoss {
    const ALPHA: f32 = 0.1;

    pub(super) fn record_received(&mut self) {
        self.record(0.0);
    }

    pub(super) fn record_lost(&mut self, num_lost: u64) {
        for _ in 0..num_lost {
            self.record(1.0);
        }
    }

    pub(crate) fn get(&self) -> f32 {
        self.loss
    }

    fn record(&mut self, v: f32) {
        self.loss = Self::ALPHA * v + (1.0 - Self::ALPHA) * self.loss;
    }
}
