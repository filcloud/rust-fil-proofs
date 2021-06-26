use storage_proofs_core::error::{Error, Result};
use log::{info, error};

pub fn get_all_nvidia_bus_ids() -> Option<Vec<u32>> {
    let mut bus_ids = Vec::new();
    for dev in rust_gpu_tools::opencl::Device::by_brand(rust_gpu_tools::opencl::Brand::Nvidia)? {
        bus_ids.push(dev.bus_id()?);
    }
    bus_ids.sort_unstable();
    bus_ids.dedup();
    Some(bus_ids)
}

pub fn get_gpu_index() -> Result<u32, Error> {
    let bus_ids = match get_all_nvidia_bus_ids() {
        Some(bus_ids) => bus_ids,
        None => vec![],
    };
    if bus_ids.is_empty() {
        return Err(Error::Unclassified(format!("No working GPUs found!")));
    }
    let index: usize = std::env::var("P2_GPU_INDEX").or::<std::env::VarError>(Ok(String::from("0")))
        .and_then(|v| match v.parse() {
            Ok(val) => Ok(val),
            Err(_) => {
                error!("Invalid P2_GPU_INDEX! Defaulting to 0...");
                Ok(0)
            }
        }).unwrap();
    info!("use gpu with index {} bus id {}", index, bus_ids[index]);
    Ok(bus_ids[index])
}
