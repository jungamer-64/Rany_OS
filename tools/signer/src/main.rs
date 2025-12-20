// tools/signer/src/main.rs
//! Ed25519 Kernel Signing Tool for RanyOS Secure Boot
//!
//! Commands:
//! - `keygen`: Generate a new Ed25519 keypair
//! - `sign`: Sign a kernel ELF with the secret key (prepends 64-byte signature)
//! - `verify`: Verify a signed kernel (for testing)

use clap::{Parser, Subcommand};
use ed25519_compact::{KeyPair, PublicKey, SecretKey, Signature};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kernel-signer")]
#[command(about = "Ed25519 kernel signing tool for RanyOS secure boot")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair
    Keygen {
        /// Directory to store the keys
        #[arg(short, long, default_value = "keys")]
        output_dir: PathBuf,
    },
    /// Sign a kernel ELF file (prepends 64-byte signature)
    Sign {
        /// Path to the kernel ELF file
        #[arg(short, long)]
        kernel: PathBuf,
        /// Path to the secret key file
        #[arg(short, long)]
        secret_key: PathBuf,
        /// Output path for the signed kernel
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify a signed kernel (for testing)
    Verify {
        /// Path to the signed kernel file
        #[arg(short, long)]
        signed_kernel: PathBuf,
        /// Path to the public key file
        #[arg(short, long)]
        public_key: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output_dir } => {
            keygen(&output_dir);
        }
        Commands::Sign {
            kernel,
            secret_key,
            output,
        } => {
            sign(&kernel, &secret_key, &output);
        }
        Commands::Verify {
            signed_kernel,
            public_key,
        } => {
            verify(&signed_kernel, &public_key);
        }
    }
}

fn keygen(output_dir: &PathBuf) {
    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir).expect("Failed to create output directory");

    // Generate keypair
    let keypair = KeyPair::generate();

    // Paths
    let secret_path = output_dir.join("kernel.key");
    let public_path = output_dir.join("kernel_pub.key");

    // Save secret key (64 bytes: seed + public key)
    fs::write(&secret_path, keypair.sk.as_ref()).expect("Failed to write secret key");
    println!("Secret key saved to: {}", secret_path.display());

    // Save public key (32 bytes)
    fs::write(&public_path, keypair.pk.as_ref()).expect("Failed to write public key");
    println!("Public key saved to: {}", public_path.display());

    println!("\n[WARNING] Keep kernel.key SECRET! Add it to .gitignore!");
    println!("[INFO] Public key (kernel_pub.key) can be shared safely.");
}

fn sign(kernel_path: &PathBuf, secret_key_path: &PathBuf, output_path: &PathBuf) {
    // Read secret key
    let sk_bytes = fs::read(secret_key_path).expect("Failed to read secret key");
    let sk = SecretKey::from_slice(&sk_bytes).expect("Invalid secret key format");

    // Read kernel ELF
    let kernel_data = fs::read(kernel_path).expect("Failed to read kernel file");
    println!(
        "Kernel size: {} bytes ({})",
        kernel_data.len(),
        kernel_path.display()
    );

    // Sign the kernel
    let signature = sk.sign(&kernel_data, None);

    // Create signed output: [Signature (64 bytes)] + [Kernel ELF]
    let mut signed_data = Vec::with_capacity(64 + kernel_data.len());
    signed_data.extend_from_slice(signature.as_ref());
    signed_data.extend_from_slice(&kernel_data);

    // Write output
    fs::write(output_path, &signed_data).expect("Failed to write signed kernel");
    println!(
        "Signed kernel saved to: {} ({} bytes)",
        output_path.display(),
        signed_data.len()
    );
    println!(
        "Signature (first 16 bytes): {:02x?}",
        &signature.as_ref()[..16]
    );
}

fn verify(signed_kernel_path: &PathBuf, public_key_path: &PathBuf) {
    const SIG_SIZE: usize = 64;

    // Read public key
    let pk_bytes = fs::read(public_key_path).expect("Failed to read public key");
    let pk = PublicKey::from_slice(&pk_bytes).expect("Invalid public key format");

    // Read signed kernel
    let signed_data = fs::read(signed_kernel_path).expect("Failed to read signed kernel");
    if signed_data.len() < SIG_SIZE {
        eprintln!("Error: Signed kernel too small (< 64 bytes)");
        std::process::exit(1);
    }

    // Split signature and kernel
    let (sig_bytes, kernel_data) = signed_data.split_at(SIG_SIZE);
    let signature = Signature::from_slice(sig_bytes).expect("Invalid signature format");

    // Verify
    match pk.verify(kernel_data, &signature) {
        Ok(()) => {
            println!("Verification PASSED!");
            println!(
                "Kernel size (without signature): {} bytes",
                kernel_data.len()
            );
        }
        Err(e) => {
            eprintln!("Verification FAILED: {:?}", e);
            std::process::exit(1);
        }
    }
}
