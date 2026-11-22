use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const C_SOURCES: &[&str] = &[
    "toob_cloud_submit.c",
    "toob_confirm.c",
    "toob_crc32.c",
    "toob_diag.c",
    "toob_handoff.c",
    "toob_mailbox.c",
    "toob_ota.c",
    "toob_update.c",
];

fn main() {
    println!("cargo:rerun-if-env-changed=TOOB_GENERATED_CONFIG_DIR");
    println!("cargo:rerun-if-env-changed=TOOB_ARM_GCC");
    println!("cargo:rerun-if-env-changed=TOOB_RISCV_GCC");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");

    if env::var_os("CARGO_FEATURE_COMPILE_C").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let libtoob_dir = manifest_dir.join("..").join("..").join("libtoob");
    let libtoob_inc = libtoob_dir.join("include");
    let common_inc = manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .join("common")
        .join("include");

    emit_rerun_dir(&libtoob_dir);
    emit_rerun_dir(&libtoob_inc);
    emit_rerun_dir(&common_inc);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let target = env::var("TARGET").expect("TARGET");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let (compiler, archiver, mut cflags, archive_name, obj_ext) = resolve_toolchain(&target);

    cflags.push("-std=c17".to_string());
    cflags.push("-fno-short-enums".to_string());
    cflags.push("-ffunction-sections".to_string());
    cflags.push("-fdata-sections".to_string());
    cflags.push(format!("-I{}", libtoob_inc.display()));
    cflags.push(format!("-I{}", libtoob_dir.display()));
    cflags.push(format!("-I{}", common_inc.display()));

    if target_os == "windows" {
        cflags.push("-DTOOB_CUSTOM_OS_LOCK".to_string());
        cflags.push("-DTOOB_CUSTOM_CONFIRM_RTC_WRITE".to_string());
    }

    if let Some(cfg_dir) = env::var_os("TOOB_GENERATED_CONFIG_DIR").filter(|s| !s.is_empty()) {
        let cfg_path = PathBuf::from(cfg_dir);
        emit_rerun_dir(&cfg_path);
        cflags.push(format!("-I{}", cfg_path.display()));
    } else if target_os != "none" {
        cflags.push("-DTOOB_HOST_FUZZING".to_string());
    } else {
        let fallback_hdr = out_dir.join("generated_boot_config.h");
        fs::write(&fallback_hdr, "#include \"libtoob_config_sandbox.h\"\n")
            .expect("write fallback generated_boot_config.h");
        cflags.push(format!("-I{}", out_dir.display()));
    }

    let mut objects = Vec::with_capacity(C_SOURCES.len());
    for src_name in C_SOURCES {
        let src_path = libtoob_dir.join(src_name);
        let stem = Path::new(src_name).file_stem().unwrap().to_string_lossy();
        let obj_path = out_dir.join(format!("{stem}.{obj_ext}"));

        let status = Command::new(&compiler)
            .args(&cflags)
            .arg("-c")
            .arg(&src_path)
            .arg("-o")
            .arg(&obj_path)
            .status()
            .unwrap_or_else(|e| panic!("failed to invoke C compiler {}: {e}", compiler.display()));

        assert!(
            status.success(),
            "C compilation failed for {} with {}",
            src_path.display(),
            compiler.display()
        );
        objects.push(obj_path);
    }

    let archive_path = out_dir.join(archive_name);
    let _ = fs::remove_file(&archive_path);
    let status = Command::new(&archiver)
        .arg("crs")
        .arg(&archive_path)
        .args(&objects)
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke archiver {}: {e}", archiver.display()));

    assert!(
        status.success(),
        "archiving {} failed with {}",
        archive_path.display(),
        archiver.display()
    );

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=toob_c");
}

fn emit_rerun_dir(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if ext == "c" || ext == "h" {
                    println!("cargo:rerun-if-changed={}", p.display());
                }
            }
        }
    }
}

fn resolve_toolchain(target: &str) -> (PathBuf, PathBuf, Vec<String>, &'static str, &'static str) {
    let target_env_suffix = target.replace('-', "_");
    let cc_target_var = format!("CC_{target_env_suffix}");
    let ar_target_var = format!("AR_{target_env_suffix}");
    println!("cargo:rerun-if-env-changed={cc_target_var}");
    println!("cargo:rerun-if-env-changed={ar_target_var}");

    if target.starts_with("thumbv") {
        let cc = find_tool(
            &[&cc_target_var, "TOOB_ARM_GCC"],
            &["arm-none-eabi-gcc"],
            "arm-none-eabi",
        );
        let ar = sibling_or_find(&cc, "arm-none-eabi-ar", &ar_target_var);
        let mut flags = vec!["-Os".to_string(), "-fno-common".to_string()];
        match target {
            "thumbv6m-none-eabi" => {
                flags.extend(["-mcpu=cortex-m0plus", "-mthumb", "-mfloat-abi=soft"].map(Into::into));
            }
            "thumbv7m-none-eabi" => {
                flags.extend(["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"].map(Into::into));
            }
            "thumbv7em-none-eabi" => {
                flags.extend(["-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=soft"].map(Into::into));
            }
            "thumbv7em-none-eabihf" => {
                flags.extend(
                    [
                        "-mcpu=cortex-m4",
                        "-mthumb",
                        "-mfpu=fpv4-sp-d16",
                        "-mfloat-abi=hard",
                    ]
                    .map(Into::into),
                );
            }
            "thumbv8m.main-none-eabi" => {
                flags.extend(["-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft"].map(Into::into));
            }
            "thumbv8m.main-none-eabihf" => {
                flags.extend(
                    [
                        "-mcpu=cortex-m33",
                        "-mthumb",
                        "-mfpu=fpv5-sp-d16",
                        "-mfloat-abi=hard",
                    ]
                    .map(Into::into),
                );
            }
            _ => flags.push("-mthumb".to_string()),
        }
        return (cc, ar, flags, "libtoob_c.a", "o");
    }

    if target.starts_with("riscv32") {
        let cc = find_tool(
            &[&cc_target_var, "TOOB_RISCV_GCC"],
            &["riscv32-esp-elf-gcc", "riscv32-unknown-elf-gcc"],
            "riscv32-esp-elf",
        );
        let stem = cc
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("riscv32-esp-elf-gcc");
        let ar_name = stem.strip_suffix("-gcc").unwrap_or("riscv32-esp-elf").to_string() + "-ar";
        let ar = sibling_or_find(&cc, &ar_name, &ar_target_var);
        let arch = if target.starts_with("riscv32imac") {
            "-march=rv32imac"
        } else if target.starts_with("riscv32imc") {
            "-march=rv32imc"
        } else {
            "-march=rv32i"
        };
        let flags = vec![
            "-Os".to_string(),
            "-fno-common".to_string(),
            arch.to_string(),
            "-mabi=ilp32".to_string(),
        ];
        return (cc, ar, flags, "libtoob_c.a", "o");
    }

    if target.ends_with("-windows-msvc") {
        let cc = find_host_tool(
            &[&cc_target_var, "CC"],
            &["clang"],
            &[r"C:\Program Files\LLVM\bin\clang.exe"],
        );
        let ar = find_host_tool(
            &[&ar_target_var, "AR"],
            &["llvm-ar"],
            &[r"C:\Program Files\LLVM\bin\llvm-ar.exe"],
        );
        let flags = vec![format!("--target={target}"), "-O2".to_string()];
        return (cc, ar, flags, "toob_c.lib", "obj");
    }

    let cc = find_host_tool(&[&cc_target_var, "CC"], &["cc", "gcc", "clang"], &[]);
    let ar = find_host_tool(&[&ar_target_var, "AR"], &["ar", "llvm-ar"], &[]);
    (cc, ar, vec!["-O2".to_string()], "libtoob_c.a", "o")
}

fn sibling_or_find(cc: &Path, ar_stem: &str, env_key: &str) -> PathBuf {
    if let Some(val) = env::var_os(env_key).filter(|v| !v.is_empty()) {
        return PathBuf::from(val);
    }
    if let Some(parent) = cc.parent() {
        for cand in [
            parent.join(ar_stem),
            parent.join(format!("{ar_stem}.exe")),
        ] {
            if cand.is_file() {
                return cand;
            }
        }
    }
    PathBuf::from(ar_stem)
}

fn find_host_tool(env_keys: &[&str], path_names: &[&str], fallbacks: &[&str]) -> PathBuf {
    for k in env_keys {
        if let Some(val) = env::var_os(k).filter(|v| !v.is_empty()) {
            return PathBuf::from(val);
        }
    }
    for name in path_names {
        if let Some(found) = search_in_path(name) {
            return found;
        }
    }
    for fb in fallbacks {
        let p = PathBuf::from(fb);
        if p.is_file() {
            return p;
        }
    }
    panic!("required build tool not found (searched {path_names:?})");
}

fn find_tool(env_keys: &[&str], bin_names: &[&str], toob_subdir: &str) -> PathBuf {
    for k in env_keys {
        if let Some(val) = env::var_os(k).filter(|v| !v.is_empty()) {
            return PathBuf::from(val);
        }
    }
    for name in bin_names {
        if let Some(found) = search_in_path(name) {
            return found;
        }
    }

    let mut roots = Vec::new();
    if let Some(home) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) {
        roots.push(PathBuf::from(home).join(".toob").join("toolchains").join(toob_subdir));
    }
    roots.push(PathBuf::from(r"D:\ToobStorage\toolchains").join(toob_subdir));

    for root in roots {
        if let Some(found) = find_executable_recursive(&root, bin_names, 4) {
            return found;
        }
    }
    panic!("cross-compiler for {toob_subdir} not found (searched {bin_names:?})");
}

fn search_in_path(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        for cand in [dir.join(name), dir.join(format!("{name}.exe"))] {
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

fn find_executable_recursive(dir: &Path, bin_names: &[&str], depth: usize) -> Option<PathBuf> {
    if depth == 0 || !dir.is_dir() {
        return None;
    }
    let bin_dir = dir.join("bin");
    if bin_dir.is_dir() {
        for name in bin_names {
            for cand in [bin_dir.join(name), bin_dir.join(format!("{name}.exe"))] {
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if let Some(found) = find_executable_recursive(&p, bin_names, depth - 1) {
                return Some(found);
            }
        }
    }
    None
}
