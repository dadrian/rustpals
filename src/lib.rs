extern crate rustc_serialize;

use rustc_serialize::base64::*;
use rustc_serialize::hex::*;

use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::fs::File;

pub fn hex_to_base64(s: &str) -> Result<String, FromHexError> {
    let raw = try!(s.from_hex());
    let b64 = raw.to_base64(STANDARD);
    return Ok(b64)
}

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let zipped_iter = a.iter().zip(b.iter());
    let res: Vec<u8> = zipped_iter.map(|(i, j)| { i ^ j }).collect();
    return res;
}

pub fn score_english_spaces(s: &[u8]) -> f64 {
    let mut count = 0;
    for b in s {
        if *b == ' ' as u8 {
            count +=1
        }
    }
    return count as f64
}

pub fn decrypt_single_xor(c: &[u8]) -> (Vec<u8>, u8, f64) {
    let mut best_score = 0.0;
    let mut best_candidate: Vec<u8> = vec![];
    let mut best_key: u8 = 0;
    for _b in 0..256 {
        let b = _b as u8;
        let key_candidate = vec![b; c.len()];
        let candidate = xor_bytes(c, key_candidate.as_slice());
        let score = score_english_spaces(candidate.as_slice());
        if score > best_score {
            best_key = b;
            best_score = score;
            best_candidate = candidate.clone();
        }
    }
    return (best_candidate, best_key, best_score);
}

#[test]
fn cryptopals_s1c1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64 = hex_to_base64(input).unwrap();
    assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", b64);
}

#[test]
fn xor_equal_length() {
    let a = vec![1,2,3,4];
    let b = vec![5,6,7,8];
    let ret = xor_bytes(a.as_slice(), b.as_slice());
    assert_eq!(vec![4, 4, 4, 12], ret);
}

#[test]
fn cryptopals_s1c2() {
    let a = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
    let b = "686974207468652062756c6c277320657965".from_hex().unwrap();
    let ret = xor_bytes(a.as_slice(), b.as_slice());
    let encoded_ret = ret.to_hex();
    assert_eq!("746865206b696420646f6e277420706c6179", encoded_ret);
}

#[test]
fn cryptopals_s1c3() {
    let ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ciphertext = ciphertext_hex.from_hex().unwrap();
    let (decrypted, key, score) = decrypt_single_xor(ciphertext.as_slice());
    match String::from_utf8(decrypted.clone()) {
        Ok(p) => {
            assert_eq!("Cooking MC's like a pound of bacon", p);
            assert_eq!(88, key);
            assert_eq!(6, score as i32);
        },
        Err(_) => { assert!(false); }
    }
}

#[test]
fn cryptopals_s1c4() {
    let input_file_name = "4.txt";
    let f = File::open(input_file_name).expect("unable to open file");
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let ciphertext_hex = line.unwrap();
        let ciphertext = ciphertext_hex.from_hex().expect("non-hex ciphertext");
        //println!("{}", ciphertext_hex);
        let (plaintext, key, score) = decrypt_single_xor(ciphertext.as_slice());
        if score > 3.0 {
            match String::from_utf8(plaintext) {
                Ok(p) => {
                    assert_eq!("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f", ciphertext_hex);
                    assert_eq!("Now that the party is jumping\n", p);
                    assert_eq!(53, key);
                },
                Err(_) => {  }
            }
        }
    }


}
