use super::*;


#[cfg(test)]
mod tests;

impl ShellNamespace for CapNamespace {
    fn name(&self) -> &str {
        "cap"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        _caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "list" => Self::list(),
                "revoke" => Self::call_revoke(args),
                "grant" => Self::call_grant(args),
                "revoke_all" => Self::call_revoke_all(args),
                "tokens" => Self::call_tokens(args),
                "check" => Self::call_check(args),
                _ => ExoValue::Error(format!(
                    "Unknown method 'cap.{}'\nValid methods: list, tokens, revoke, grant, check",
                    method
                )),
            }
        })
    }
}

