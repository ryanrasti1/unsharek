//! Composition in an intercept guard: the guest's filesystem made from parts, in ordinary Rust.
//!
//! An "app" directory (a Python script and a data file) becomes an erofs image, mapped into the
//! guest and mounted at /app; a config file computed on the host is written into the guest's /etc;
//! then Python runs the script, which reads both. While the guard lives, `std::fs` acts on the
//! guest: this thread's syscalls are the guest's, as its init. Host work and guards interleave.
//!
//!     cargo run -p exobox-examples --bin setup

use std::fs;

use exobox::{Mode, Sandbox, setup};
use exobox_examples as ex;

const SCRIPT: &str = r#"
import os
print("app:", open("/app/data.txt").read().strip())
print("config:", open("/etc/greeter/config").read().strip())
print("/app holds", sorted(os.listdir("/app")), f"(writable: {os.access('/app', os.W_OK)})")
print("the host's", os.environ["HOST_DIR"], "exists here:", os.path.exists(os.environ["HOST_DIR"]))
"#;

fn main() -> Result<(), exobox::Error> {
    let python = ex::nix_program("EXOBOX_TEST_PYTHON");

    // Host work first: the app's tree, and its image. `exobox_erofs::build` is what the store's
    // cache uses for each store path; here it packs an ordinary directory.
    let dir = tempfile::tempdir()?;
    let app = dir.path().join("app");
    fs::create_dir(&app)?;
    fs::write(app.join("main.py"), SCRIPT)?;
    fs::write(app.join("data.txt"), "hello from an erofs image\n")?;
    let image_path = dir.path().join("app.erofs");
    exobox_erofs::build(&app, &image_path)?;

    let mut sb = Sandbox::builder().mode(Mode::Coroutine).build()?;
    let store = sb.map_closure(&python, &[])?;
    {
        let _g = sb.intercept()?;
        // From here on, every syscall of this thread is the guest's.
        setup::mount_closure(&store)?;
        // Output works as anywhere: the guest's fds 0-2 are the host's.
        println!("[guard] the closure mounted");
    }
    // The host's again: host data the guest gets is read out here, and moved in by a guard.
    let config = format!("greeting=hi, written by host pid {}\n", std::process::id());
    // Mapped: the guest's /dev/exobox/app. The mapping is what the guest reads, so the host's
    // files can go now (and must, here: `run` never returns to drop `dir`).
    let image = sb.map_image(&image_path)?;
    let host_dir = dir.path().display().to_string();
    drop(dir);
    {
        let _g = sb.intercept()?;
        setup::mount_erofs(&image, "/app")?;
        fs::create_dir_all("/etc/greeter")?;
        fs::write("/etc/greeter/config", &config)?;
        println!("[guard] {} mounted at /app; /etc/greeter/config written", image.device().display());
    }
    let argv = ex::os(&[python.to_str().unwrap(), "/app/main.py"]);
    let env = ex::os(&[&format!("HOST_DIR={host_dir}")]);
    let Err(e) = sb.run(&argv, &env);
    ex::fail(e)
}
