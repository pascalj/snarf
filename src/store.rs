#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::ptr;
use std::{os::raw::c_void, str::FromStr};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

unsafe extern "C" fn my_get_string_cb(
    _: *mut nix_c_context,
    userdata: *mut ::std::os::raw::c_void,
    store_path: *const StorePath,
) {
    unsafe {
        nix_store_real_path(
            ptr::null_mut(),
            userdata as *mut Store,
            store_path as *mut StorePath,
            Some(print_nix_path),
            ptr::null_mut(),
        );
    }
}

unsafe extern "C" fn print_nix_path(
    start: *const ::std::os::raw::c_char,
    _n: ::std::os::raw::c_uint,
    _user_data: *mut ::std::os::raw::c_void,
) {
    unsafe {
        let path = std::ffi::CStr::from_ptr(start);
        println!("Closure {}!", path.to_string_lossy());
    }
}

fn get_closure(path: &str) {
    let cpath = std::ffi::CString::from_str(path).expect("Error converting string");
    unsafe {
        nix_libstore_init_no_load_config(ptr::null_mut());
        let store = nix_store_open(ptr::null_mut(), ptr::null(), ptr::null_mut());
        let store_path = nix_store_parse_path(ptr::null_mut(), store, cpath.as_ptr());
        nix_store_get_fs_closure(
            ptr::null_mut(),
            store,
            store_path,
            false,                  /* flip_direction */
            false,                  /* include outputs */
            false,                  /* include_derivers */
            store as *mut c_void,   /* userdata */
            Some(my_get_string_cb), /* callback */
        );

        nix_store_free(store);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ffi() {
        unsafe {
            nix_libstore_init(core::ptr::null_mut());
        }
    }

    #[test]
    fn check_get_closure() {
        get_closure("/nix/store/sqlnjj8c3n3si3sjnadhdbcwgrk97g2w-clang-wrapper-21.1.2/");
    }
}
