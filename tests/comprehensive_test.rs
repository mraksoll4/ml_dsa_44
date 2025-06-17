use ml_dsa_44::{constants, Keypair, Signature, sign, verify, sign_with_context, verify_with_context, MlDsaError};

/// Test results tracking
#[derive(Debug, Default)]
struct TestResults {
    passed: usize,
    failed: usize,
    tests: Vec<(String, bool)>,
}

impl TestResults {
    fn add_test(&mut self, name: String, passed: bool) {
        if passed {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        self.tests.push((name, passed));
    }

    fn print_summary(&self) {
        println!("\n========================================");
        println!("TEST RESULTS SUMMARY");
        println!("========================================");
        
        for (name, passed) in &self.tests {
            let symbol = if *passed { "✓" } else { "✗" };
            println!("{} {}: {}", symbol, name, if *passed { "PASSED" } else { "FAILED" });
        }
        
        println!("\nTotal Tests: {}", self.tests.len());
        println!("Passed: {}", self.passed);
        println!("Failed: {}", self.failed);
        
        if self.failed == 0 {
            println!("\n🎉 ALL TESTS PASSED! ML-DSA-44 Rust implementation is working correctly.");
        } else {
            println!("\n⚠️  Some tests failed. Please check the implementation.");
        }
    }
}

/// Helper function to print hex data
fn print_hex(label: &str, data: &[u8]) {
    println!("{} ({} bytes):", label, data.len());
    print!("  ");
    for (i, byte) in data.iter().enumerate() {
        print!("{:02x}", byte);
        if (i + 1) % 32 == 0 && i + 1 < data.len() {
            print!("\n  ");
        }
    }
    println!("\n");
}

/// Helper function to print first N bytes of data
fn print_hex_preview(label: &str, data: &[u8], preview_bytes: usize) {
    let preview_len = std::cmp::min(preview_bytes, data.len());
    print!("{}: ", label);
    for (i, byte) in data.iter().take(preview_len).enumerate() {
        print!("{:02x}", byte);
        if (i + 1) % 8 == 0 {
            print!(" ");
        }
    }
    if data.len() > preview_bytes {
        print!("... ({} total bytes)", data.len());
    }
    println!();
}

/// Helper function to print section separator
fn print_separator(title: &str) {
    println!("\n========================================");
    println!("{}", title);
    println!("========================================");
}

/// Helper function to check if a buffer contains only zeros
fn is_all_zeros(data: &[u8]) -> bool {
    data.iter().all(|&x| x == 0)
}

/// Test signature operations with given keypair
fn test_signature_with_keys(
    keypair: &Keypair,
    test_name: &str,
    results: &mut TestResults,
) -> Result<(), MlDsaError> {
    println!("\n--- Testing signature with {} ---", test_name);
    
    let test_message = b"Test message for ML-DSA-44 Rust wrapper";
    println!("Message: \"{}\" ({} bytes)", 
             String::from_utf8_lossy(test_message), test_message.len());
    
    // Test 1: Basic signing
    println!("Signing message...");
    let signature = sign(test_message, &keypair.secret_key)?;
    println!("✓ Message signed successfully (signature length: {} bytes)", signature.data.len());
    
    print_hex_preview("Signature (first 32 bytes)", &signature.data, 32);
    
    // Test 2: Basic verification
    println!("Verifying signature...");
    let is_valid = verify(&signature, test_message, &keypair.public_key)?;
    
    let test_name_verify = format!("{} - signature verification", test_name);
    if is_valid {
        println!("✓ Signature verification successful");
        results.add_test(test_name_verify, true);
    } else {
        println!("✗ Signature verification failed");
        results.add_test(test_name_verify, false);
        return Ok(());
    }
    
    // Test 3: Verification with wrong message
    println!("Testing with modified message...");
    let mut wrong_message = test_message.to_vec();
    wrong_message[0] ^= 0x01; // Flip one bit
    
    let wrong_verify = verify(&signature, &wrong_message, &keypair.public_key)?;
    let test_name_wrong = format!("{} - invalid message rejection", test_name);
    if !wrong_verify {
        println!("✓ Verification correctly rejected modified message");
        results.add_test(test_name_wrong, true);
    } else {
        println!("✗ ERROR: Verification should have failed for modified message!");
        results.add_test(test_name_wrong, false);
    }
    
    // Test 4: Context-aware signing
    println!("Testing context-aware signing...");
    let context = b"test-context-data";
    let ctx_signature = sign_with_context(test_message, context, &keypair.secret_key)?;
    println!("✓ Context-aware signature created ({} bytes)", ctx_signature.data.len());
    
    // Test 5: Context-aware verification
    let ctx_valid = verify_with_context(&ctx_signature, test_message, context, &keypair.public_key)?;
    let test_name_ctx = format!("{} - context-aware verification", test_name);
    if ctx_valid {
        println!("✓ Context-aware verification successful");
        results.add_test(test_name_ctx, true);
    } else {
        println!("✗ Context-aware verification failed");
        results.add_test(test_name_ctx, false);
    }
    
    // Test 6: Context-aware verification with wrong context
    let wrong_context = b"wrong-context";
    let ctx_wrong = verify_with_context(&ctx_signature, test_message, wrong_context, &keypair.public_key)?;
    let test_name_ctx_wrong = format!("{} - wrong context rejection", test_name);
    if !ctx_wrong {
        println!("✓ Verification correctly rejected wrong context");
        results.add_test(test_name_ctx_wrong, true);
    } else {
        println!("✗ ERROR: Verification should have failed for wrong context!");
        results.add_test(test_name_ctx_wrong, false);
    }
    
    // Test 7: Cross-verification (regular vs context)
    let cross_verify = verify(&ctx_signature, test_message, &keypair.public_key)?;
    let test_name_cross = format!("{} - context signature with regular verify", test_name);
    if !cross_verify {
        println!("✓ Regular verification correctly rejected context signature");
        results.add_test(test_name_cross, true);
    } else {
        println!("✗ ERROR: Regular verification should reject context signature!");
        results.add_test(test_name_cross, false);
    }
    
    Ok(())
}

/// Test seed clearing behavior
fn test_seed_clearing(results: &mut TestResults) -> Result<(), MlDsaError> {
    println!("\n--- Testing seed clearing behavior ---");
    
    // Prepare a test seed with known values
    let original_seed = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    ];
    
    print_hex("Original seed", &original_seed);
    
    // Make a copy of the seed to pass to the function
    let mut seed_copy = original_seed;
    println!("Creating keypair from seed (seed will be cleared)...");
    
    let keypair = Keypair::from_seed(&mut seed_copy)?;
    println!("✓ Keypair created successfully");
    
    // Check if the seed was cleared
    println!("Checking if seed was cleared...");
    print_hex("Seed after keypair generation", &seed_copy);
    
    let seed_cleared = is_all_zeros(&seed_copy);
    if seed_cleared {
        println!("✓ Seed was properly cleared (all zeros)");
        results.add_test("seed clearing - zeroed after use".to_string(), true);
    } else {
        println!("✗ ERROR: Seed was not properly cleared!");
        results.add_test("seed clearing - zeroed after use".to_string(), false);
    }
    
    // Verify that the seed is different from the original
    let seed_changed = seed_copy != original_seed;
    if seed_changed {
        println!("✓ Seed buffer was modified (different from original)");
        results.add_test("seed clearing - modified from original".to_string(), true);
    } else {
        println!("✗ ERROR: Seed buffer was not modified!");
        results.add_test("seed clearing - modified from original".to_string(), false);
    }
    
    // Test that the generated keypair still works
    let test_message = b"Test message for cleared seed keypair";
    let signature = sign(test_message, &keypair.secret_key)?;
    let is_valid = verify(&signature, test_message, &keypair.public_key)?;
    
    if is_valid {
        println!("✓ Keypair generated from cleared seed works correctly");
        results.add_test("seed clearing - keypair functionality".to_string(), true);
    } else {
        println!("✗ ERROR: Keypair generated from cleared seed doesn't work!");
        results.add_test("seed clearing - keypair functionality".to_string(), false);
    }
    
    Ok(())
}

/// Test deterministic generation with multiple copies
fn test_deterministic_generation_with_clearing(results: &mut TestResults) -> Result<(), MlDsaError> {
    println!("\n--- Testing deterministic generation with seed clearing ---");
    
    let original_seed = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17,
        0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f
    ];
    
    // Generate first keypair
    let mut seed1 = original_seed;
    println!("Generating first keypair from seed...");
    let keypair1 = Keypair::from_seed(&mut seed1)?;
    println!("✓ First keypair generated");
    
    // Check that first seed was cleared
    let seed1_cleared = is_all_zeros(&seed1);
    if seed1_cleared {
        println!("✓ First seed was cleared");
    } else {
        println!("✗ First seed was not cleared");
    }
    
    // Generate second keypair from the same original seed
    let mut seed2 = original_seed;
    println!("Generating second keypair from same original seed...");
    let keypair2 = Keypair::from_seed(&mut seed2)?;
    println!("✓ Second keypair generated");
    
    // Check that second seed was cleared
    let seed2_cleared = is_all_zeros(&seed2);
    if seed2_cleared {
        println!("✓ Second seed was cleared");
    } else {
        println!("✗ Second seed was not cleared");
    }
    
    // Verify deterministic behavior
    let pk_match = keypair1.public_key.0 == keypair2.public_key.0;
    let sk_match = keypair1.secret_key.0 == keypair2.secret_key.0;
    
    if pk_match && sk_match {
        println!("✓ Deterministic generation works despite seed clearing");
        results.add_test("deterministic with clearing - keypair consistency".to_string(), true);
    } else {
        println!("✗ ERROR: Deterministic generation failed with seed clearing");
        results.add_test("deterministic with clearing - keypair consistency".to_string(), false);
    }
    
    // Test cross-verification
    let test_message = b"Cross-verification with cleared seeds";
    let signature1 = sign(test_message, &keypair1.secret_key)?;
    let cross_valid = verify(&signature1, test_message, &keypair2.public_key)?;
    
    if cross_valid {
        println!("✓ Cross-verification successful with cleared seeds");
        results.add_test("deterministic with clearing - cross verification".to_string(), true);
    } else {
        println!("✗ ERROR: Cross-verification failed with cleared seeds");
        results.add_test("deterministic with clearing - cross verification".to_string(), false);
    }
    
    Ok(())
}

/// Test multiple messages with same keypair
fn test_multiple_messages(keypair: &Keypair, results: &mut TestResults) -> Result<(), MlDsaError> {
    println!("\n--- Testing multiple messages with same keypair ---");
    
    let messages = [
        b"First test message".as_slice(),
        b"Second test message with different length!".as_slice(),
        b"".as_slice(), // Empty message
        b"Message with special chars: !@#$%^&*()".as_slice(),
        &[0u8; 1000], // Large message with zeros
    ];
    
    for (i, message) in messages.iter().enumerate() {
        println!("Testing message {}: {} bytes", i + 1, message.len());
        
        let signature = sign(message, &keypair.secret_key)?;
        let is_valid = verify(&signature, message, &keypair.public_key)?;
        
        let test_name = format!("multiple messages - message {}", i + 1);
        if is_valid {
            println!("✓ Message {} verified successfully", i + 1);
            results.add_test(test_name, true);
        } else {
            println!("✗ Message {} verification failed", i + 1);
            results.add_test(test_name, false);
        }
    }
    
    Ok(())
}

/// Test signature malleability
fn test_signature_malleability(keypair: &Keypair, results: &mut TestResults) -> Result<(), MlDsaError> {
    println!("\n--- Testing signature malleability ---");
    
    let message = b"Malleability test message";
    let signature = sign(message, &keypair.secret_key)?;
    
    // Test with modified signature
    let mut modified_sig = signature.clone();
    if !modified_sig.data.is_empty() {
        modified_sig.data[0] ^= 0x01; // Flip one bit in signature
    }
    
    let modified_valid = verify(&modified_sig, message, &keypair.public_key)?;
    if !modified_valid {
        println!("✓ Modified signature correctly rejected");
        results.add_test("signature malleability - modified signature rejection".to_string(), true);
    } else {
        println!("✗ ERROR: Modified signature was accepted!");
        results.add_test("signature malleability - modified signature rejection".to_string(), false);
    }
    
    // Test with truncated signature
    if signature.data.len() > 10 {
        let mut truncated_sig = signature.clone();
        truncated_sig.data.truncate(signature.data.len() - 10);
        
        let truncated_valid = verify(&truncated_sig, message, &keypair.public_key)?;
        if !truncated_valid {
            println!("✓ Truncated signature correctly rejected");
            results.add_test("signature malleability - truncated signature rejection".to_string(), true);
        } else {
            println!("✗ ERROR: Truncated signature was accepted!");
            results.add_test("signature malleability - truncated signature rejection".to_string(), false);
        }
    }
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut results = TestResults::default();
    
    println!("ML-DSA-44 Comprehensive Rust Test Suite (with Seed Clearing)");
    println!("Public Key Size: {} bytes", constants::PUBLIC_KEY_BYTES);
    println!("Secret Key Size: {} bytes", constants::SECRET_KEY_BYTES);
    println!("Max Signature Size: {} bytes", constants::SIGNATURE_BYTES);
    println!("Seed Size: {} bytes", constants::SEED_BYTES);
    
    // Step 1: Generate random keypair
    print_separator("STEP 1: Generate Random Keypair");
    
    println!("Generating random keypair...");
    let random_keypair = Keypair::generate()
        .map_err(|e| format!("Random keypair generation failed: {}", e))?;
    println!("✓ Random keypair generated successfully\n");
    
    print_hex_preview("Random Public Key", &random_keypair.public_key.0, 64);
    print_hex_preview("Random Secret Key", &random_keypair.secret_key.0, 64);
    
    results.add_test("random keypair generation".to_string(), true);
    
    // Test signature with random keys
    test_signature_with_keys(&random_keypair, "random keys", &mut results)?;
    
    // Step 2: Test seed clearing behavior
    print_separator("STEP 2: Test Seed Clearing Behavior");
    test_seed_clearing(&mut results)?;
    
    // Step 3: Test deterministic generation with clearing
    print_separator("STEP 3: Test Deterministic Generation with Seed Clearing");
    test_deterministic_generation_with_clearing(&mut results)?;
    
    // Step 4: Test deterministic generation edge case
    print_separator("STEP 4: Test Multiple Seeds with Same Content");
    
    let test_seed = [0x42u8; constants::SEED_BYTES];
    
    // Generate multiple keypairs to ensure consistency
    let mut seeds_and_keypairs = Vec::new();
    for i in 0..3 {
        let mut seed = test_seed;
        println!("Generating keypair {} from identical seed...", i + 1);
        let keypair = Keypair::from_seed(&mut seed)?;
        
        // Verify seed was cleared
        if is_all_zeros(&seed) {
            println!("✓ Seed {} was cleared", i + 1);
        } else {
            println!("✗ Seed {} was not cleared", i + 1);
        }
        
        seeds_and_keypairs.push((seed, keypair));
    }
    
    // Verify all keypairs are identical
    let all_pk_same = seeds_and_keypairs.windows(2).all(|w| {
        w[0].1.public_key.0 == w[1].1.public_key.0
    });
    let all_sk_same = seeds_and_keypairs.windows(2).all(|w| {
        w[0].1.secret_key.0 == w[1].1.secret_key.0
    });
    
    if all_pk_same && all_sk_same {
        println!("✓ All keypairs from identical seeds are identical");
        results.add_test("multiple identical seeds - consistency".to_string(), true);
    } else {
        println!("✗ ERROR: Keypairs from identical seeds differ");
        results.add_test("multiple identical seeds - consistency".to_string(), false);
    }
    
    // Step 5: Additional comprehensive tests
    print_separator("STEP 5: Additional Comprehensive Tests");
    
    // Test multiple messages
    test_multiple_messages(&random_keypair, &mut results)?;
    
    // Test signature malleability
    test_signature_malleability(&random_keypair, &mut results)?;
    
    // Step 6: Performance test
    print_separator("STEP 6: Performance Test");
    
    println!("Running performance test (100 sign/verify operations)...");
    let perf_message = b"Performance test message";
    let start = std::time::Instant::now();
    
    for i in 0..100 {
        let signature = sign(perf_message, &random_keypair.secret_key)?;
        let is_valid = verify(&signature, perf_message, &random_keypair.public_key)?;
        if !is_valid {
            println!("✗ Performance test failed at iteration {}", i);
            results.add_test("performance test".to_string(), false);
            break;
        }
        if i == 99 {
            results.add_test("performance test".to_string(), true);
        }
    }
    
    let duration = start.elapsed();
    println!("✓ Performance test completed in {:?} ({:.2} ops/sec)", 
             duration, 200.0 / duration.as_secs_f64());
    
    // Step 7: Security test - verify seed isolation
    print_separator("STEP 7: Security Test - Seed Isolation");
    
    println!("Testing that different seed instances don't interfere...");
    let seed_a = [0xAAu8; constants::SEED_BYTES];
    let seed_b = [0xBBu8; constants::SEED_BYTES];
    
    let mut seed_a_copy = seed_a;
    let mut seed_b_copy = seed_b;
    
    let keypair_a = Keypair::from_seed(&mut seed_a_copy)?;
    let keypair_b = Keypair::from_seed(&mut seed_b_copy)?;
    
    // Verify both seeds were cleared
    let seed_a_cleared = is_all_zeros(&seed_a_copy);
    let seed_b_cleared = is_all_zeros(&seed_b_copy);
    
    if seed_a_cleared && seed_b_cleared {
        println!("✓ Both seeds were properly cleared");
        results.add_test("security test - seed isolation clearing".to_string(), true);
    } else {
        println!("✗ ERROR: Not all seeds were cleared");
        results.add_test("security test - seed isolation clearing".to_string(), false);
    }
    
    // Verify keypairs are different
    let keypairs_different = keypair_a.public_key.0 != keypair_b.public_key.0;
    
    if keypairs_different {
        println!("✓ Different seeds produce different keypairs");
        results.add_test("security test - seed isolation uniqueness".to_string(), true);
    } else {
        println!("✗ ERROR: Different seeds produced identical keypairs");
        results.add_test("security test - seed isolation uniqueness".to_string(), false);
    }
    
    // Final results
    results.print_summary();
    
    if results.failed > 0 {
        std::process::exit(1);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comprehensive_suite() {
        main().expect("Comprehensive test suite should pass");
    }
    
    #[test]
    fn test_seed_clearing_unit() {
        let original_seed = [0x12u8; constants::SEED_BYTES];
        let mut seed_copy = original_seed;
        
        let keypair = Keypair::from_seed(&mut seed_copy).unwrap();
        
        // Seed should be cleared
        assert!(is_all_zeros(&seed_copy));
        assert_ne!(seed_copy, original_seed);
        
        // Keypair should still work
        let message = b"test";
        let signature = sign(message, &keypair.secret_key).unwrap();
        let valid = verify(&signature, message, &keypair.public_key).unwrap();
        assert!(valid);
    }
    
    #[test]
    fn test_deterministic_with_clearing() {
        let seed = [0x99u8; constants::SEED_BYTES];
        
        let mut seed1 = seed;
        let mut seed2 = seed;
        
        let keypair1 = Keypair::from_seed(&mut seed1).unwrap();
        let keypair2 = Keypair::from_seed(&mut seed2).unwrap();
        
        // Both seeds should be cleared
        assert!(is_all_zeros(&seed1));
        assert!(is_all_zeros(&seed2));
        
        // Keypairs should be identical
        assert_eq!(keypair1.public_key.0, keypair2.public_key.0);
        assert_eq!(keypair1.secret_key.0, keypair2.secret_key.0);
    }
    
    #[test]
    fn test_error_handling() {
        // Test with invalid signature data
        let keypair = Keypair::generate().unwrap();
        let message = b"test message";
        let invalid_sig = Signature { data: vec![0u8; 10] }; // Too short
        
        let result = verify(&invalid_sig, message, &keypair.public_key);
        assert!(result.is_ok()); // Should not panic, just return false
        assert!(!result.unwrap()); // Should be invalid
    }
    
    #[test]
    fn test_edge_cases() {
        let keypair = Keypair::generate().unwrap();
        
        // Empty message
        let empty_sig = sign(&[], &keypair.secret_key).unwrap();
        let empty_valid = verify(&empty_sig, &[], &keypair.public_key).unwrap();
        assert!(empty_valid);
        
        // Large message
        let large_message = vec![0xAAu8; 10000];
        let large_sig = sign(&large_message, &keypair.secret_key).unwrap();
        let large_valid = verify(&large_sig, &large_message, &keypair.public_key).unwrap();
        assert!(large_valid);
    }
}