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
}
