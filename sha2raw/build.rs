fn main() {
    std::env::set_var("CFLAGS", "-march=armv8-a+crypto");

    cc::Build::new()
        .file("src/sha256-arm.c")
        .compile("sha256-arm");
}
