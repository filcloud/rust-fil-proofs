use storage_proofs_core::error::{Error, Result};
use neptune::cl;
use log::{info, error};

pub fn get_gpu_index() -> Result<u32, Error> {
    let bus_ids = match cl::get_all_nvidia_bus_ids() {
        Ok(bus_ids) => Ok(bus_ids),
        Err(err) => Err(Error::Unclassified(format!("{}", err))),
    }?;
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
