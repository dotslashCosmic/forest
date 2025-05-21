// Author: dotslashCosmic

use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::ConstantTimeEq;
use std::vec::Vec;
use anyhow::Result; 
pub fn secure_erase_memory<T: AsMut<[u8]>>(mut mem_slice: T) {
    mem_slice.as_mut().zeroize();
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecureData {
    data: Vec<u8>,
    // mlock/VirtualLock/memlock impliment here
}

impl SecureData {
    pub fn new(size: usize) -> Self {
        let mut data = vec![0u8; size];
        data.zeroize(); // Ensure zeroout upon allocation
        SecureData { data }
    }

    pub fn from_vec(plain_data: Vec<u8>) -> Self {
        SecureData { data: plain_data }
    }

    pub fn from_string(plain_string: String) -> Self {
        SecureData {
            data: plain_string.into_bytes(),
        }
    }

    pub fn secure_erase(&mut self) {
        self.data.zeroize();
        self.data.clear();
        self.data.shrink_to_fit();
    }

    pub fn resize(&mut self, new_size: usize) {
        self.secure_erase();
        self.data.resize(new_size, 0);
        self.data.zeroize();
    }

    pub fn data_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    // WARN mutable pointer to raw data, dangerous
    pub fn mutable_data_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    pub fn get_vector(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn empty(&self) -> bool {
        self.data.is_empty()
    }
}

// Constant-time comparison for two byte slices
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub fn constant_time_compare_containers<A, B>(a_container: &A, b_container: &B) -> bool
where
    A: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let a_slice = a_container.as_ref();
    let b_slice = b_container.as_ref();
    constant_time_compare(a_slice, b_slice)
}
