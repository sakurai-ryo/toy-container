pub struct Process {
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub user: String,
    pub cwd: String,
}
