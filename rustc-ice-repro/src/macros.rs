// This macro creates code that references types across files
// The key pattern is that the error diagnostic must span multiple files
// with specific character positions that cause the off-by-one error in
// annotate_snippets.

#[macro_export]
macro_rules! impl_handler {
    ($name:literal => $module:ident) => {
        // The use of $module::Builder where $module doesn't exist creates
        // an unresolved import error that spans this file and the invocation site.
        use $module::Builder;

        pub fn handler() -> Box<dyn $module::Handler> {
            <$module::Builder>::create($name)
        }
    };
}
