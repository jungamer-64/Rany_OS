// Interrupt helper macro for portable interrupt handler declarations.
// Included into both the library crate and the binary crate with
// `#[macro_use] mod interrupt_macros;` so `define_interrupt!` is available
// to modules included by `main.rs` and to the library unit tests.
//
// NOTE: このファイルは `interrupts/` モジュールに移動するのが意味的には適切だが、
// `#[macro_use]` による lib.rs でのクレートルート宣言が必要なため、ここに留置する。
// 主な使用箇所: interrupts/exceptions.rs, interrupts/mod.rs
#[doc(hidden)]
macro_rules! define_interrupt {
    // Handler with arguments and optional return type
    ($(#[$meta:meta])* $vis:vis fn $name:ident($($args:tt)*) $(-> $ret:ty)? $body:block) => {
        // MSVC-hosted builds (x86_64-pc-windows-msvc) use plain C ABI
        #[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
        $(#[$meta])*
        $vis extern "C" fn $name($($args)*) $(-> $ret)? $body

        // Non-MSVC builds use the real x86-interrupt ABI.
        #[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
        $(#[$meta])*
        $vis extern "x86-interrupt" fn $name($($args)*) $(-> $ret)? $body
    };

    // No-arg handler with optional return type
    ($(#[$meta:meta])* $vis:vis fn $name:ident() $(-> $ret:ty)? $body:block) => {
        #[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
        $(#[$meta])*
        $vis extern "C" fn $name() $(-> $ret)? $body

        #[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
        $(#[$meta])*
        $vis extern "x86-interrupt" fn $name() $(-> $ret)? $body
    };
}
