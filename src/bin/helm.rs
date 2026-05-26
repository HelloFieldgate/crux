//! Helm — Crux Mesh browser UI.
//!
//! Usage:
//!   helm [path]          Start Helm, searching for a mesh from [path] (default: cwd)
//!   helm --mesh <dir>    Use the given directory as the mesh root
//!
//! When launched from Finder with no args, tries in order:
//!   1. ~/.config/helm/last_mesh  (last opened mesh)
//!   2. Upward search from $HOME
//!   3. Falls back to a setup page so the user can enter the path

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let initial_mesh = find_initial_mesh(&args);
    // serve() binds the port first, then opens the browser in a thread —
    // so the page is always ready before the browser connects.
    crux_mesh::helm::serve(initial_mesh);
}

fn find_initial_mesh(args: &[String]) -> Option<std::path::PathBuf> {
    use crux_mesh::helm::{load_last_mesh};
    use crux_mesh::mesh::find_mesh;
    use std::path::PathBuf;

    // 1. Explicit --mesh <dir>
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--mesh" && i + 1 < args.len() {
            return Some(PathBuf::from(&args[i + 1]));
        }
        i += 1;
    }

    // 2. Positional path argument
    if args.len() > 1 && !args[1].starts_with('-') {
        if let Some(root) = find_mesh(&PathBuf::from(&args[1])) {
            return Some(root);
        }
    }

    // 3. Last-used mesh (persisted across sessions)
    if let Some(root) = load_last_mesh() {
        if root.join(".crux-mesh.json").exists() {
            return Some(root);
        }
    }

    // 4. Search upward from cwd
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(root) = find_mesh(&cwd) {
            return Some(root);
        }
    }

    // 5. Search upward from $HOME
    if let Some(home) = std::env::var("HOME").ok().map(std::path::PathBuf::from) {
        if let Some(root) = find_mesh(&home) {
            return Some(root);
        }
    }

    None  // serve() will show the setup page
}
