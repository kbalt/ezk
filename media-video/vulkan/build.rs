use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        fd: { target_os = "linux" },
    }
}
