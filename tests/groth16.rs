use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

type GrothBn = Groth16<Bn254>;

use num_bigint::BigInt;
use serde_json::Value;
use std::str::FromStr;
use std::time::Instant;

fn value_to_bigint(v: &Value) -> Vec<BigInt> {
    match v {
        Value::String(inner) => vec![BigInt::from_str(inner).unwrap()],
        Value::Array(inner) => {
            let mut res = Vec::new();
            for item in inner.iter() {
                res.extend(value_to_bigint(item));
            }
            res
        },
        _ => panic!("unsupported type"),
    }
}

#[test]
#[cfg(feature = "circom-2")]
fn groth16_proof() -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/fibonacci.final.wasm",
        "./test-vectors/fibonacci.final.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    
    //1-setup
    let start_time0 = Instant::now();
    let start_time0_1 = Instant::now();
    // create an empty instance for setting it up
    let circom = builder.setup();
    let elapsed_time0_1 = start_time0_1.elapsed();
    println!("Time taken for builder.setup: {:?}", elapsed_time0_1);

    let start_time0_2 = Instant::now();
    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;
    let elapsed_time0_2 = start_time0_2.elapsed();
    println!("Time taken for GrothBn::generate_random_parameters_with_reduction {:?}", elapsed_time0_2);
    let elapsed_time0 = start_time0.elapsed();
    println!("1-(setup) time cost: {:?}", elapsed_time0);

    //2-prove
    let start_time1 = Instant::now();
    let start_time1_1 = Instant::now();
    let inputs_path = "./test-vectors/final_input.zkin.json";
    let inputs_str = std::fs::read_to_string(inputs_path).unwrap();
    let inputs: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(&inputs_str).unwrap();
    let inputs = inputs
        .iter()
        .map(|(key, value)| {
            let res = match value {
                Value::String(inner) => {
                    vec![BigInt::from_str(inner).unwrap()]
                }
                Value::Array(inner) => inner.iter().flat_map(value_to_bigint).collect(),
                _ => panic!(),
            };
    
            (key.clone(), res)
        })
        .collect::<std::collections::HashMap<_, _>>();

    for (key, values) in &inputs {
        for value in values {
            builder.push_input(key, value.clone());
        }
    }
    let elapsed_time1_1 = start_time1_1.elapsed();
    println!("Time taken for builder.push_input: {:?}", elapsed_time1_1);

    let start_time1_2 = Instant::now();
    let circom = builder.build()?;
    let elapsed_time1_2 = start_time1_2.elapsed();
    println!("Time taken for generate witness: {:?}", elapsed_time1_2);
    
    let start_time1_3 = Instant::now();
    let proof = GrothBn::prove(&params, circom, &mut rng)?;
    let elapsed_time1_3 = start_time1_3.elapsed();
    println!("Time taken for GrothBn::prove: {:?}", elapsed_time1_3);
    
    let elapsed_time1 = start_time1.elapsed();
    println!("2-(prove) time cost: {:?}", elapsed_time1);

    //3-generate verification_key
    let start_time2 = Instant::now();
    let pvk = GrothBn::process_vk(&params.vk).unwrap();
    let elapsed_time2 = start_time2.elapsed();
    println!("3-(generate verification_key) time cost: {:?}", elapsed_time2);

    //4-verify
    let start_time3 = Instant::now();
    let inputs = circom.get_public_inputs().unwrap();
    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;
    let elapsed_time3 = start_time3.elapsed();
    println!("4-(verify) time cost: {:?}", elapsed_time3);

    assert!(verified);

    Ok(())
}