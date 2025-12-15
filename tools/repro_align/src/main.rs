#[repr(C)]
pub struct A { pub a: u8, pub b: u8 }

#[repr(C, align(16))]
pub struct B { pub data: [u8; 16] }

#[used]
#[link_section = ".requests"]
static S1: A = A { a: 1, b: 2 };

#[used]
#[link_section = ".requests"]
static S2: B = B { data: [0u8; 16] };

fn main() {
    println!("S1: {} {}", S1.a, S1.b);
    println!("S2 data[0]: {}", S2.data[0]);

    // Print alignment and size of limine request types
    println!("BaseRevision: size={} align={}", core::mem::size_of::<limine::BaseRevision>(), core::mem::align_of::<limine::BaseRevision>());
    println!("HhdmRequest: size={} align={}", core::mem::size_of::<limine::request::HhdmRequest>(), core::mem::align_of::<limine::request::HhdmRequest>());
    println!("MemoryMapRequest: size={} align={}", core::mem::size_of::<limine::request::MemoryMapRequest>(), core::mem::align_of::<limine::request::MemoryMapRequest>());
    println!("FramebufferRequest: size={} align={}", core::mem::size_of::<limine::request::FramebufferRequest>(), core::mem::align_of::<limine::request::FramebufferRequest>());
    println!("StackSizeRequest: size={} align={}", core::mem::size_of::<limine::request::StackSizeRequest>(), core::mem::align_of::<limine::request::StackSizeRequest>());
    println!("RequestsStartMarker: size={} align={}", core::mem::size_of::<limine::request::RequestsStartMarker>(), core::mem::align_of::<limine::request::RequestsStartMarker>());
    println!("RequestsEndMarker: size={} align={}", core::mem::size_of::<limine::request::RequestsEndMarker>(), core::mem::align_of::<limine::request::RequestsEndMarker>());
}
