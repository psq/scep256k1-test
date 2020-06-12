// see
// https://github.com/rust-bitcoin/rust-secp256k1/blob/master/examples/sign_verify_recovery.rs
// https://github.com/rust-bitcoin/rust-secp256k1/blob/master/examples/sign_verify.rs


// msg            de5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04
// privKey        510f96a8efd0b11e211733c1ac5e3fa6f3d3fcdd62869e376c47decb3e14fea1
// pubKeyAsBuffer 03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110
// sigObj         8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a13 1

extern crate secp256k1;
extern crate hex;
extern crate hex_slice;

use hex_slice::AsHex;

use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Message, Signature};
use secp256k1::recovery::{RecoverableSignature};
// use secp256k1::recovery::{RecoverableSignature, RecoveryId};


fn main() {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    let (_seckey2, pubkey2) = secp.generate_keypair(&mut rng);

    let secret: [u8; 32] = [
      0x51,0x0f,0x96,0xa8,0xef,0xd0,0xb1,0x1e,0x21,0x17,0x33,0xc1,0xac,0x5e,0x3f,0xa6,
      0xf3,0xd3,0xfc,0xdd,0x62,0x86,0x9e,0x37,0x6c,0x47,0xde,0xcb,0x3e,0x14,0xfe,0xa1
    ];

    let expected_pub: &[u8] = &[
      0x03,0xad,0xb8,0xde,0x4b,0xfb,0x65,0xdb,0x2c,0xfd,0x61,0x20,0xd5,0x5c,0x65,0x26,
      0xae,0x9c,0x52,0xe6,0x75,0xdb,0x7e,0x47,0x30,0x86,0x36,0x53,0x4b,0xa7,0x78,0x61,
      0x10
    ];

    let message_arr: [u8; 32] = [
      0xde,0x5b,0x9e,0xb9,0xe7,0xc5,0x59,0x29,0x30,0xeb,0x2e,0x30,0xa0,0x13,0x69,0xc3,
      0x65,0x86,0xd8,0x72,0x08,0x2e,0xd8,0x18,0x1e,0xe8,0x3d,0x2a,0x0e,0xc2,0x0f,0x04
    ];

    let expected_sig: &[u8] = &[
      0x87,0x38,0x48,0x7e,0xbe,0x69,0xb9,0x3d,0x8e,0x51,0x58,0x3b,0xe8,0xee,0xe5,0x0b,
      0xb4,0x21,0x3f,0xc4,0x9c,0x76,0x7d,0x32,0x96,0x32,0x73,0x0c,0xc1,0x93,0xb8,0x73,
      0x55,0x44,0x28,0xfc,0x93,0x6c,0xa3,0x56,0x9a,0xfc,0x15,0xf1,0xc9,0x36,0x5f,0x65,
      0x91,0xd6,0x25,0x1a,0x89,0xfe,0xe9,0xc9,0xac,0x66,0x11,0x16,0x82,0x4d,0x3a,0x13
    ];

    let seckey = SecretKey::from_slice(&secret).expect("32 bytes, within curve order");
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);
    let serialized = pubkey.serialize();  // 33 bytes version

    let pubkey_a: &[u8] = &serialized;
    assert_eq!(expected_pub, pubkey_a);
    assert_eq!(pubkey, PublicKey::from_secret_key(&secp, &seckey));

    println!("message_arr     {:02x}", message_arr.as_hex());
    println!("message_arr.len {:#?}", message_arr.len());

    println!("seckey          {:02x}", secret.as_hex());
    println!("seckey.len      {:#?}", secret.len());

    println!("serialized      {:02x}", serialized.as_hex());
    println!("serialized.len  {:#?}", serialized.len());

    let message = Message::from_slice(&message_arr).unwrap();
    let signature = secp.sign(&message, &seckey);
    let serialized_sig = signature.serialize_compact();
    println!("signature       {:02x}", serialized_sig.as_hex());
    println!("signature.len   {:#?}", serialized_sig.len());

    let sig_a: &[u8] = &serialized_sig;
    assert_eq!(expected_sig, sig_a);

    let expanded_sig = Signature::from_compact(&serialized_sig).unwrap();
    assert!(secp.verify(&message, &expanded_sig, &pubkey).is_ok());
    assert!(secp.verify(&message, &expanded_sig, &pubkey2).is_err());

    // const pub_key_recoverd = secp256k1.ecdsaRecover(sigObj.signature, sigObj.recid, msg)

    let recoverable_sig = secp.sign_recoverable(&message, &seckey);
    let (rec_id, rec_sig) = recoverable_sig.serialize_compact();

    let recovered_sig = RecoverableSignature::from_compact(&rec_sig, rec_id).unwrap();
    let recovered_pub = secp.recover(&message, &recovered_sig).unwrap();
    let recovered_serialized = recovered_pub.serialize();  // 33 bytes version

    let recovered_serialized_a: &[u8] = &recovered_serialized;
    assert_eq!(recovered_serialized_a, pubkey_a);

}


