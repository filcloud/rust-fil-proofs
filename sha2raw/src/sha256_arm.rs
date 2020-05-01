use rand::AsByteSliceMut;

extern "C" {
    fn sha256_process_arm(state: *mut u8, data: *const *const u8, num: u32);
}

pub unsafe fn compress256(state: &mut [u32; 8], blocks: &[&[u8]]) {
    assert_eq!(blocks.len() % 2, 0);

    let mut data: Vec<*const u8> = Vec::with_capacity(blocks.len());
    for i in 0..blocks.len() {
        data.push(blocks[i].as_ptr());
    }

    sha256_process_arm(state.as_byte_slice_mut().as_mut_ptr(), data.as_ptr(), blocks.len() as u32);
}
