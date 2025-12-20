fn main() {
    // Only add MSVC host-specific link libraries when building for Windows/MSVC
    // This avoids polluting cross-compiles (e.g., x86_64-unknown-none kernel target).
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("windows-msvc") {
        println!("cargo:rerun-if-env-changed=TARGET");

        // If present, add explicit link-search paths for the Windows SDK UCRT and
        // the MSVC tools. This ensures `ucrt.lib` and `vcruntime.lib` are found
        // even if the environment's LIB paths are incomplete. If env vars are
        // missing, try discovering common install locations.
        if let (Ok(sdkdir), Ok(sdkver)) = (
            std::env::var("WindowsSdkDir"),
            std::env::var("WindowsSDKVersion"),
        ) {
            let ucrt_path = format!("{}Lib\\{}\\ucrt\\x64", sdkdir, sdkver);
            println!("cargo:warning=Adding UCRT search path: {}", ucrt_path);
            println!("cargo:rustc-link-search=native={}", ucrt_path);
        } else {
            println!("cargo:warning=WindowsSdkDir/WindowsSDKVersion not set, trying default SDK path");
            // Fallback: detect the SDK version folder under the default install
            // location and add its ucrt\x64 path if found.
            let sdk_root = "C:\\Program Files (x86)\\Windows Kits\\10\\Lib";
            if let Ok(entries) = std::fs::read_dir(sdk_root) {
                let mut versions: Vec<_> = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .map(|e| e.file_name().into_string().ok().unwrap_or_default())
                    .filter(|s| s.starts_with("10."))
                    .collect();
                versions.sort();
                if let Some(sdkver) = versions.pop() {
                    let ucrt_path = format!("{}\\{}\\ucrt\\x64", sdk_root, sdkver);
                    println!("cargo:warning=Adding discovered UCRT search path: {}", ucrt_path);
                    println!("cargo:rustc-link-search=native={}", ucrt_path);
                } else {
                    println!("cargo:warning=Could not discover Windows SDK version under {}", sdk_root);
                }
            } else {
                println!("cargo:warning=Windows SDK path {} not present", sdk_root);
            }
        }

        if let Ok(vc_tools) = std::env::var("VCToolsInstallDir") {
            let vctools_lib = format!("{}lib\\x64", vc_tools);
            println!("cargo:warning=Adding VC tools lib path: {}", vctools_lib);
            println!("cargo:rustc-link-search=native={}", vctools_lib);
        } else {
            println!("cargo:warning=VCToolsInstallDir not set, trying default MSVC path");
            // Fallback: find a MSVC toolset under Visual Studio 2022 Community
            let msvc_root = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC";
            if let Ok(entries) = std::fs::read_dir(msvc_root) {
                let mut versions: Vec<_> = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .map(|e| e.file_name().into_string().ok().unwrap_or_default())
                    .collect();
                versions.sort();
                if let Some(msvcver) = versions.pop() {
                    let vctools_lib = format!("{}\\{}\\lib\\x64", msvc_root, msvcver);
                    println!("cargo:warning=Adding discovered VC tools lib path: {}", vctools_lib);
                    println!("cargo:rustc-link-search=native={}", vctools_lib);
                } else {
                    println!("cargo:warning=Could not discover MSVC toolset under {}", msvc_root);
                }
            } else {
                println!("cargo:warning=MSVC path {} not present", msvc_root);
            }
        }

        // Link the Universal C Runtime and VC runtime libraries which provide
        // memcpy/memset/memmove/memcmp, math functions (fmod/floor) and C++
        // exception/unwind helpers (e.g., __CxxFrameHandler3, _CxxThrowException).
        println!("cargo:rustc-link-lib=dylib=ucrt");
        println!("cargo:rustc-link-lib=dylib=vcruntime");
        // Prefer MSVC's C++ runtime import library from the toolset (e.g., msvcprt.lib)
        println!("cargo:rustc-link-lib=dylib=msvcprt");
        // Also link the C runtime import lib; some symbols are in MSVCP/VC runtime.
        println!("cargo:rustc-link-lib=dylib=msvcrt");

        // Force the linker to add these specific import libraries by name. This
        // helps when automatic name resolution doesn't pick the right import
        // library even if the lib directories are present.
        println!("cargo:rustc-link-arg=/DEFAULTLIB:ucrt.lib");
        println!("cargo:rustc-link-arg=/DEFAULTLIB:vcruntime.lib");
        println!("cargo:rustc-link-arg=/DEFAULTLIB:msvcprt.lib");
        println!("cargo:rustc-link-arg=/DEFAULTLIB:msvcrt.lib");

        // Force inclusion of our test entrypoint symbol on MSVC hosts. Some
        // archive/object extraction patterns can omit unreferenced COMDATs; the
        // /INCLUDE option forces the linker to pull the object that defines the
        // symbol and /ENTRY makes it the process entry point for the binary.
        println!("cargo:rustc-link-arg=/INCLUDE:mainCRTStartup");
        println!("cargo:rustc-link-arg=/ENTRY:mainCRTStartup");
        // Define subsystem explicitly so the linker can set proper entry/CRT
        // initialization; TEST builds expect console I/O.
        println!("cargo:rustc-link-arg=/SUBSYSTEM:CONSOLE");
    }
}
