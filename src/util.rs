use alloc::string::{String, ToString};

///
/// 
pub(crate) fn canonicalize_module(name: &str) -> String {
    let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let upper = file.to_ascii_uppercase();
    upper.trim_end_matches(".DLL").to_string()
}

/// Randomly shuffles the elements of a mutable slice in-place using a pseudo-random
/// number generator seeded by the CPU's timestamp counter (`rdtsc`).
///
/// The shuffling algorithm is a variant of the Fisher-Yates shuffle.
///
/// # Arguments
/// 
/// * `list` — A mutable slice of elements to be shuffled.
#[cfg(target_arch = "x86_64")]
pub fn shuffle<T>(list: &mut [T]) {
    let mut seed = unsafe { core::arch::x86_64::_rdtsc() };
    for i in (1..list.len()).rev() {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let j = seed as usize % (i + 1);
        list.swap(i, j);
    }
}
