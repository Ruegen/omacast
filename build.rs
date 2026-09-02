use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dir = manifest.join("third_party/fpsap-bridge");
    println!("cargo:rerun-if-changed=third_party/fpsap-bridge/fpsap.go");
    println!("cargo:rerun-if-changed=third_party/fpsap-bridge/go.mod");
    println!("cargo:rerun-if-changed=third_party/fairplay-sap-core");

    let go = find_go();
    let archive = out.join("libfpsap.a");
    let status = Command::new(&go)
        .current_dir(&dir)
        .env("CGO_ENABLED", "1")
        .args([
            "build",
            "-buildmode=c-archive",
            "-o",
            archive.to_str().unwrap(),
            "fpsap.go",
        ])
        .status()
        .unwrap_or_else(|e| panic!("go build fpsap ({go:?}): {e}"));
    if !status.success() {
        panic!("go build -buildmode=c-archive failed (need a Go toolchain)");
    }
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=fpsap");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=m");
}

fn find_go() -> PathBuf {
    if let Ok(p) = env::var("GO") {
        return PathBuf::from(p);
    }
    if let Ok(home) = env::var("HOME") {
        let local = PathBuf::from(home).join(".local/go/bin/go");
        if local.is_file() {
            return local;
        }
    }
    PathBuf::from("go")
}
