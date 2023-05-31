use anyhow::{ Result};
use serde::Serialize;
use serde_json::Value;
use ws_sdk::log::log_info;
use ws_sdk::database::sql::*;
use ws_sdk::crypto::secp256k1::verify;
use ws_sdk::stream::get_data;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use package::{BinPackage, SensorData};
use protobuf::{EnumOrUnknown, Message};

#[no_mangle]
pub extern "C" fn start_raspi(rid: i32) -> i32 {
    match handle_raspi(rid) {
        Ok(_) => return 0,
        _ => return -1,
    };
}

fn handle_raspi(rid: i32) -> Result<()> {
    let raspi_pub_key: &str = "049CB6BACB289669E2F838513FC2CFA3058C9836C2540C264A1F2678E226412B1B889AAAAAEC21F97EF9DDD0B48B690DDBDB1DB89EA20CAD7F98361E0C6AB6083C";

    log_info(&format!("start rid: {}", rid))?;

    log_info(&format!("payload: {:?}", &get_data(rid as _)?))?;

    let payload = get_data(rid as _)?;

    let bin_package = BinPackage::parse_from_bytes(&payload).unwrap();

    let sign : String = bin_package.signature.iter().map(|b| format!("{:02x}", b).to_string()).collect::<Vec<String>>().join("");

    log_info(&format!("signature: {}", &sign))?;

    log_info(&format!("sensor_data len: {:?}", &bin_package.data.len()))?;

    let sensor_data = SensorData::parse_from_bytes(&bin_package.data).unwrap();

    log_info(&format!("snr: {:?}", &sensor_data.snr))?;

    let mut msg_bytes = bin_package.type_.value().to_be_bytes().to_vec();

    msg_bytes.append(&mut bin_package.data.to_vec());

    msg_bytes.append(&mut bin_package.timestamp.to_be_bytes().to_vec());

    log_info(&format!("data to be sign"))?;
    log_info(&format!("{:02x?} ", &msg_bytes))?;

    if verify(raspi_pub_key, &msg_bytes, &sign).is_ok() {
        log_info(&format!("messamge verify ok"))?;
        execute("INSERT INTO raspi (snr,timestamp) VALUES (?,?);", &[&(sensor_data.snr.to_string().as_str()), &(bin_package.timestamp.to_string().as_str())])?;
    }
    else {
        log_info(&format!("messamge verify failed"))?;
    }

    Ok(())
}

#[derive(Serialize)]
struct Person {
    name: String,
}