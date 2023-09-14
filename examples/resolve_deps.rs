use cross_socket::deps::setup;

#[cfg(target_os = "windows")]
fn main() {
    // Resolve dependencies (with interactive mode)
    setup::resolve_dependencies(true);
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("For now, this example is for Windows only. There are no special dependencies for other supported platforms.");
}
