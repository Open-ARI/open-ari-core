// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! Experimental ABI 1. See include/openari.h for the caller memory contract.
use openari_core::{DEFAULT_MAX_INPUT_BYTES, Verifier};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

pub const OK: i32 = 0;
pub const BUFFER_TOO_SMALL: i32 = 1;
pub const INVALID_ARGUMENT: i32 = 2;
pub const RESOURCE_LIMIT: i32 = 3;
pub const INTERNAL_ERROR: i32 = 4;

#[unsafe(no_mangle)]
pub extern "C" fn openari_abi_version() -> u32 {
    1
}

/// Write a schema-versioned UTF-8 JSON report without a terminating NUL.
/// An OK status means the report was written, not that an image was verified.
///
/// # Safety
/// `required` must point to writable, aligned usize storage. For nonzero lengths,
/// `input` and `output` must reference valid memory of the indicated size. All
/// three regions must be disjoint and remain valid for the call. Input must not
/// change concurrently. Null buffers are permitted only with zero length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openari_verify_json_v1(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_capacity: usize,
    required: *mut usize,
) -> i32 {
    if required.is_null()
        || (input.is_null() && input_len != 0)
        || (output.is_null() && output_capacity != 0)
    {
        return INVALID_ARGUMENT;
    }
    // SAFETY: caller guarantees valid, exclusive required storage.
    unsafe {
        required.write(0);
    }
    if input_len > DEFAULT_MAX_INPUT_BYTES
        || input_len > isize::MAX as usize
        || output_capacity > isize::MAX as usize
    {
        return RESOURCE_LIMIT;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller guarantees readable input for the duration of this call.
        let input = if input_len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(input, input_len) }
        };
        let report = match Verifier::default().verify(input) {
            Ok(report) => report,
            Err(_) => return RESOURCE_LIMIT,
        };
        let bytes = match serde_json::to_vec(&report) {
            Ok(bytes) => bytes,
            Err(_) => return INTERNAL_ERROR,
        };
        // SAFETY: same required storage contract as above.
        unsafe {
            required.write(bytes.len());
        }
        if output_capacity < bytes.len() {
            return BUFFER_TOO_SMALL;
        }
        // SAFETY: output is writable, large enough, and disjoint from the owned bytes.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        }
        OK
    })) {
        Ok(status) => status,
        Err(_) => INTERNAL_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sizing_and_output_contract() {
        let input = b"\xff\xd8\xff";
        let mut required = 0;
        unsafe {
            assert_eq!(
                openari_verify_json_v1(
                    input.as_ptr(),
                    input.len(),
                    ptr::null_mut(),
                    0,
                    &mut required
                ),
                BUFFER_TOO_SMALL
            );
            let mut output = vec![0; required];
            assert_eq!(
                openari_verify_json_v1(
                    input.as_ptr(),
                    input.len(),
                    output.as_mut_ptr(),
                    output.len(),
                    &mut required
                ),
                OK
            );
            let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(report["decision"], "indeterminate");
            assert_eq!(
                openari_verify_json_v1(ptr::null(), 1, ptr::null_mut(), 0, &mut required),
                INVALID_ARGUMENT
            );
            assert_eq!(
                openari_verify_json_v1(
                    input.as_ptr(),
                    DEFAULT_MAX_INPUT_BYTES + 1,
                    ptr::null_mut(),
                    0,
                    &mut required
                ),
                RESOURCE_LIMIT
            );
        }
    }
}
