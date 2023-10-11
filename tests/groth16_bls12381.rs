use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

type GrothBls = Groth16<Bls12_381>;

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
    let cfg = CircomConfig::<Bls12_381>::new(
        "./test-vectors/fibonacci_bls12381.final.wasm",
        "./test-vectors/fibonacci_bls12381.final.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    let inputs_path = "./test-vectors/final_input_bls12381.zkin.json";
    let inputs_str = std::fs::read_to_string(inputs_path).unwrap();
    let inputs: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(&inputs_str).unwrap();
    
    let start_time0 = Instant::now();
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
    let elapsed_time0 = start_time0.elapsed();
    println!("Time taken for builder.push_input: {:?}", elapsed_time0);

    let start_time1 = Instant::now();
    // create an empty instance for setting it up
    let circom = builder.setup();
    let elapsed_time1 = start_time1.elapsed();
    println!("Time taken for builder.setup: {:?}", elapsed_time1);

    let start_time2 = Instant::now();
    let mut rng = thread_rng();
    let params = GrothBls::generate_random_parameters_with_reduction(circom, &mut rng)?;
    let elapsed_time2 = start_time2.elapsed();
    println!("Time taken for GrothBls::generate_random_parameters_with_reduction {:?}", elapsed_time2);

    let start_time3 = Instant::now();
    let circom = builder.build()?;
    let elapsed_time3 = start_time3.elapsed();
    println!("Time taken for generate witness: {:?}", elapsed_time3);

    let inputs = circom.get_public_inputs().unwrap();

    let start_time = Instant::now();
    let proof = GrothBls::prove(&params, circom, &mut rng)?;
    let elapsed_time = start_time.elapsed();
    println!("Time taken for GrothBls::prove: {:?}", elapsed_time);

    let pvk = GrothBls::process_vk(&params.vk).unwrap();

    let verified = GrothBls::verify_with_processed_vk(&pvk, &inputs, &proof)?;

    assert!(verified);

    Ok(())
}