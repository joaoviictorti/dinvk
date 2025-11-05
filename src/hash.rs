// Copyright (c) 2025 joaoviictorti
// Licensed under the MIT License. See LICENSE file in the project root for details.

//! Runtime hash functions.

/// Computes a CRC32-based hash for a given string.
pub fn crc32ba(string: &str) -> u32 {
    let mut u_hash = 0xFFFF_EFFF;

    for &byte in string.as_bytes() {
        u_hash ^= byte as u32;

        for _ in 0..8 {
            let u_mask = if u_hash & 1 != 0 { 0xFFFF_FFFF } else { 0 };
            u_hash = (u_hash >> 1) ^ (0xEDB8_8320 & u_mask);
        }
    }

    !u_hash
}

/// Computes a Jenkins hash (variant 3) for a given string.
pub fn jenkins3(string: &str) -> u32 {
    let mut a: u32 = 0xDEAD_BEEF + string.len() as u32;
    let mut b: u32 = a;
    let mut c: u32 = a;

    let bytes = string.as_bytes();
    let mut i = 0;

    while i + 12 <= bytes.len() {
        a = a.wrapping_add(u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]));
        b = b.wrapping_add(u32::from_le_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]));
        c = c.wrapping_add(u32::from_le_bytes([bytes[i + 8], bytes[i + 9], bytes[i + 10], bytes[i + 11]]));

        a = a.wrapping_sub(c);
        a ^= c.rotate_left(4);
        c = c.wrapping_add(b);

        b = b.wrapping_sub(a);
        b ^= a.rotate_left(6);
        a = a.wrapping_add(c);

        c = c.wrapping_sub(b);
        c ^= b.rotate_left(8);
        b = b.wrapping_add(a);

        a = a.wrapping_sub(c);
        a ^= c.rotate_left(16);
        c = c.wrapping_add(b);

        b = b.wrapping_sub(a);
        b ^= a.rotate_left(19);
        a = a.wrapping_add(c);

        c = c.wrapping_sub(b);
        c ^= b.rotate_left(4);
        b = b.wrapping_add(a);

        i += 12;
    }

    let remaining = &bytes[i..];
    let mut last_block = [0; 12];
    last_block[..remaining.len()].copy_from_slice(remaining);

    a = a.wrapping_add(u32::from_le_bytes([last_block[0], last_block[1], last_block[2], last_block[3]]));
    b = b.wrapping_add(u32::from_le_bytes([last_block[4], last_block[5], last_block[6], last_block[7]]));
    c = c.wrapping_add(u32::from_le_bytes([last_block[8], last_block[9], last_block[10], last_block[11]]));

    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(24));

    c
}

/// Computes a Jenkins One-at-a-Time hash for a given string.
pub fn jenkins(string: &str) -> u32 {
    let mut hash = 0;

    for &byte in string.as_bytes() {
        hash += byte as u32;
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash = hash.wrapping_add(hash << 15);

    hash
}

/// Computes a DJB2 hash for a given string.
pub fn djb2(string: &str) -> u32 {
    let mut hash = 5381u32;

    for &byte in string.as_bytes() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(byte as u32);
    }

    hash
}

/// Computes an FNV-1a hash for a given string.
pub fn fnv1a(string: &str) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;
    for &byte in string.as_bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

/// Computes a MurmurHash3 (32-bit) for a given string.
pub fn murmur3(string: &str) -> u32 {
    const SEED: u32 = 0x9747B28C;
    const C1: u32 = 0xCC9E_2D51;
    const C2: u32 = 0x1B87_3593;
    
    let mut hash = SEED;
    let bytes = string.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i + 4 <= len {
        let mut k = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);

        hash ^= k;
        hash = hash.rotate_left(13);
        hash = hash.wrapping_mul(5).wrapping_add(0xE654_6B64);

        i += 4;
    }

    let mut k = 0;
    let remainder = &bytes[i..];

    if remainder.len() == 3 { k ^= (remainder[2] as u32) << 16; }
    if remainder.len() >= 2 { k ^= (remainder[1] as u32) << 8; }
    if !remainder.is_empty() { k ^= remainder[0] as u32; }

    if !remainder.is_empty() {
        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);
        hash ^= k;
    }

    hash ^= len as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85EB_CA6B);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xC2B2_AE35);
    hash ^= hash >> 16;

    hash
}

/// Computes an SDBM hash for a given string.
pub fn sdbm(string: &str) -> u32 {
    let mut hash = 0u32;

    for &byte in string.as_bytes() {
        hash = hash.wrapping_shl(6)
            .wrapping_add(hash.wrapping_shl(16))
            .wrapping_sub(hash)
            .wrapping_add(byte as u32);
    }

    hash
}

/// Computes a simple additive hash (Lose-Lose Hash) for a given string.
pub fn loselose(string: &str) -> u32 {
    let mut hash = 0u32;
    
    for c in string.bytes() {
        hash = hash.wrapping_add(c as u32);
    }

    hash
}

/// Computes the PJW hash (Peter J. Weinberger's hash function).
pub fn pjw(string: &str) -> u32 {
    const BITS_IN_UNSIGNED_INT: u32 = 32;
    const THREE_QUARTERS: u32 = (BITS_IN_UNSIGNED_INT * 3) / 4;
    const ONE_EIGHTH: u32 = BITS_IN_UNSIGNED_INT / 8;
    const HIGH_BITS: u32 = 0xF000_0000;

    let mut hash = 0u32;
    let mut test;

    for &byte in string.as_bytes() {
        hash = (hash << ONE_EIGHTH).wrapping_add(byte as u32);
        test = hash & HIGH_BITS;
        if test != 0 {
            hash = (hash ^ (test >> THREE_QUARTERS)) & !HIGH_BITS;
        }
    }

    hash
}

/// JS Hash is a hashing algorithm created by Justin Sobel.
pub fn js(string: &str) -> u32 {
    let mut hash = 1315423911u32;

    for &byte in string.as_bytes() {
        hash ^= (hash << 5).wrapping_add(byte as u32).wrapping_add(hash >> 2);
    }

    hash
}

/// Computes the AP Hash (Arash Partow's hash function).
pub fn ap(string: &str) -> u32 {
    let mut hash = 0xAAAAAAAAu32;

    for (i, &byte) in string.as_bytes().iter().enumerate() {
        if i & 1 == 0 {
            hash ^= (hash << 7) ^ (byte as u32).wrapping_mul(hash >> 3);
        } else {
            hash ^= ((hash << 11) + (byte as u32)) ^ (hash >> 5)
        }
    }

    hash
}

