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

#[derive(Serialize)]
struct Person {
    name: String,
}

#[no_mangle]
pub extern "C" fn start_pebble(rid: i32) -> i32 {
    match handle_pebble(rid) {
        Ok(_) => return 0,
        _ => return -1,
    };
}

fn handle_pebble(rid: i32) -> Result<()> {
    let pebble_pub_key: &str = "044ea9fa6257aed7800b679cd7087c9a9ed589f57f83923575ce52ecc501d6d6a16d6153bc55d8888aca8fe7bfe612e23b1e95ab034a7ced05f5f2f910e7315ed1";

    log_info(&format!("start rid: {}", rid))?;

    log_info(&format!("payload: {:?}", &get_data(rid as _)?))?;

    let payload = get_data(rid as _)?;

    let bin_package = BinPackage::parse_from_bytes(&payload).unwrap();

    let sign : String = bin_package.signature.iter().map(|b| format!("{:02x}", b).to_string()).collect::<Vec<String>>().join("");

    log_info(&format!("sig: {}", &sign))?;

    log_info(&format!("sensor_data len: {:?}", &bin_package.data.len()))?;

    let sensor_data = SensorData::parse_from_bytes(&bin_package.data).unwrap();

    log_info(&format!("snr: {:?}", &sensor_data.snr))?;

    //let msg_bytes = &payload[..(payload.len()-bin_package.signature.len())];

    let mut msg_bytes = bin_package.type_.value().to_be_bytes().to_vec();

    msg_bytes.append(&mut bin_package.data.to_vec());

    msg_bytes.append(&mut bin_package.timestamp.to_be_bytes().to_vec());

    log_info(&format!("to be sign"))?;
    log_info(&format!("{:02x?} ", &msg_bytes))?;

    if verify(pebble_pub_key, &msg_bytes, &sign).is_ok() {
        log_info(&format!("messamge verify ok"))?;
        execute("INSERT INTO pebble (snr,timestamp) VALUES (?,?);", &[&(sensor_data.snr.to_string().as_str()), &(bin_package.timestamp.to_string().as_str())])?;
    }
    else {
        log_info(&format!("messamge verify failed"))?;
    }

    Ok(())
}