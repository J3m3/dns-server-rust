pub struct Config {
    pub target_server: String,
}

impl Config {
    pub fn new(target_server: String) -> Self {
        Self { target_server }
    }
}
