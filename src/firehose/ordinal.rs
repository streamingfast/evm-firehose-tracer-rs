/// Helper structure for tracking ordinal numbers
#[derive(Debug, Default)]
pub(super) struct Ordinal {
    value: u64,
}

impl Ordinal {
    pub(super) fn next(&mut self) -> u64 {
        self.value += 1;
        self.value
    }

    pub(super) fn reset(&mut self) {
        self.value = 0;
    }
}
