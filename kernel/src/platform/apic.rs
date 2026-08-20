use kernel_api::service::platform::{self as kplatform, ApicServices};

struct BuiltinApicProvider;

static BUILTIN_APIC_PROVIDER: BuiltinApicProvider = BuiltinApicProvider;

impl ApicServices for BuiltinApicProvider {
    fn local_apic_id(&self) -> u32 {
        crate::drivers::apic::local_apic()
            .unwrap_or_else(|error| panic!("local APIC service unavailable: {error}"))
            .id()
    }
}

pub fn register_builtin_service() {
    crate::provider_registry::provider_registry().register_builtin_apic(&BUILTIN_APIC_PROVIDER);
}

pub fn local_apic_id() -> u32 {
    kplatform::try_apic()
        .map(ApicServices::local_apic_id)
        .unwrap_or_else(|| BUILTIN_APIC_PROVIDER.local_apic_id())
}
