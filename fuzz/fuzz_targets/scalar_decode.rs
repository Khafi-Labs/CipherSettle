#![no_main]
#[path = "../../src/quorum_adversarial/src/fuzz_bodies.rs"]
#[allow(dead_code)]
mod fuzz_bodies;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    fuzz_bodies::scalar_decode(data);
});
