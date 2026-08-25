use libc;
use std::{
    self,
    ops::{Deref, DerefMut},
};
use crate::hash;

// T must be fixed size
pub struct SHM<T: Sized> {
    id: i32,
    size: usize, // Note: this size is in bytes (u8 units), not in number of T elements
    ptr: *mut T,
}

impl<T> SHM<T> {
    pub fn new(ele_num: usize) -> Self {
        let size = std::mem::size_of::<T>() * ele_num;
        assert!(size > 0, "Cannot allocate zero-sized shared memory");

        let id = unsafe {
            libc::shmget(libc::IPC_PRIVATE, size, libc::IPC_CREAT | libc::IPC_EXCL | 0o600)
        };
        assert!(id != -1, "Failed to allocate shared memory");

        let ptr = unsafe { libc::shmat(id, std::ptr::null(), 0) as *mut T };
        assert!(!ptr.is_null(), "Failed to attach shared memory");

        SHM {
            id,
            size,
            ptr,
        }
    }

    pub fn from_id(id: i32, ele_num: usize) -> Self {
        let element_size = std::mem::size_of::<T>();
        let size = element_size * ele_num;
        let ptr = unsafe { libc::shmat(id, std::ptr::null(), 0) as *mut T };
        assert!(!ptr.is_null(), "Failed to attach shared memory from ID");

        SHM { id, size, ptr }
    }

    pub fn clear(&mut self) {
        unsafe { libc::memset(self.ptr as *mut libc::c_void, 0, self.size) };
    }

    pub fn get_id(&self) -> i32 {
        self.id
    }

    pub fn get_ptr(&self) -> *mut T {
        self.ptr
    }

    pub fn is_fail(&self) -> bool {
        -1 == self.ptr as isize
    }
    
    pub fn get_hash(&self) -> u64 {
        unsafe {
            let byte_ptr = self.ptr as *const u8;
            let byte_slice = std::slice::from_raw_parts(byte_ptr, self.size);
            hash::hash_slice(byte_slice)
        }
    }
}

impl<T> Deref for SHM<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size / std::mem::size_of::<T>()) }
    }
}

impl<T> DerefMut for SHM<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size / std::mem::size_of::<T>()) }
    }
}

impl<T> std::fmt::Debug for SHM<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}, {}, {:p}", self.id, self.size, self.ptr)
    }
}

impl<T> Drop for SHM<T> {
    fn drop(&mut self) {
        unsafe { libc::shmctl(self.id, libc::IPC_RMID, std::ptr::null_mut()) };
    }
}