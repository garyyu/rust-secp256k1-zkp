// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Lib Features Demo


#[cfg(test)]
mod tests {
    use ::{Message, Secp256k1};
    use ContextFlag;
    use key::{SecretKey, PublicKey};
    use aggsig::{sign_single, verify_single, export_secnonce_single};
    use rand::{Rng, thread_rng, OsRng};
    use std::time::{SystemTime};

    const LENGTH: usize = 100_000;

    #[test]
    fn bench_ecdsa_sign_efficiency() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let mut secret = SecretKey([0; 32]);
        thread_rng().fill_bytes(&mut secret.0);

        let now = SystemTime::now();

        for _ in 1..LENGTH+1 {
            secp.sign(&msg, &secret).unwrap();
        }

        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} signing)", used_time, LENGTH);
        }
    }

    #[test]
    fn bench_ecdsa_check_efficiency() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let mut secret = SecretKey([0; 32]);
        thread_rng().fill_bytes(&mut secret.0);
        let pubkey = PublicKey::from_secret_key(&secp, &secret).unwrap();

        let sig = secp.sign(&msg, &secret).unwrap();

        let now = SystemTime::now();

        let mut ok_count = 0;
        for _ in 1..LENGTH+1 {
            if let Ok(_) = secp.verify(&msg, &sig, &pubkey){
                ok_count += 1;
            }
        }
        println!("ecdsa check ok:\t{}/{}", ok_count, LENGTH);
        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} verify)", used_time, LENGTH);
        }
    }

    #[test]
    fn bench_aggsig_sign_efficiency() {
        let secp = Secp256k1::with_caps(ContextFlag::Full);
        let (sk, _pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let now = SystemTime::now();

        for _ in 1..LENGTH+1 {
            sign_single(&secp, &msg, &sk, None, None, None).unwrap();
        }

        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} signing)", used_time, LENGTH);
        }
    }

    #[test]
    fn bench_aggsig_check_efficiency() {
        let secp = Secp256k1::with_caps(ContextFlag::Full);
        let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig=sign_single(&secp, &msg, &sk, None, None, None).unwrap();

        let now = SystemTime::now();

        let mut ok_count = 0;
        for _ in 1..LENGTH+1 {
            if true == verify_single(&secp, &sig, &msg, None, &pk, false){
                ok_count += 1;
            }
        }
        println!("aggsig check ok:\t{}/{}", ok_count, LENGTH);
        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} verify)", used_time, LENGTH);
        }
    }

    #[test]
    fn bench_aggsig_check_with_pubnonce_efficiency() {
        let secp = Secp256k1::with_caps(ContextFlag::Full);
        let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let secnonce = export_secnonce_single(&secp).unwrap();
        let pubnonce = PublicKey::from_secret_key(&secp, &secnonce).unwrap();

        let sig=sign_single(&secp, &msg, &sk, Some(&secnonce), Some(&pubnonce), Some(&pubnonce)).unwrap();

        let now = SystemTime::now();

        let mut ok_count = 0;
        for _ in 1..LENGTH+1 {
            if true == verify_single(&secp, &sig, &msg, Some(&pubnonce), &pk, false){
                ok_count += 1;
            }
        }
        println!("aggsig check ok:\t{}/{}", ok_count, LENGTH);
        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} verify with pubnonce)", used_time, LENGTH);
        }
    }

    #[test]
    fn bench_bullet_proof_wt_extra() {
        const BP_LENGTH: usize = 1_000;

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let value = 12345678;
        let commit = secp.commit(value, blinding).unwrap();

        let mut now = SystemTime::now();
        let mut bullet_proof = secp.bullet_proof(value, blinding, blinding, None);

        for _ in 1..BP_LENGTH+1 {
            bullet_proof = secp.bullet_proof(value, blinding, blinding, None);
        }

        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} bullet proof)", used_time, BP_LENGTH);
        }

        now = SystemTime::now();
        let mut ok_count = 0;
        for _ in 1..BP_LENGTH+1 {
            let proof_range = secp.verify_bullet_proof(commit, bullet_proof, None).unwrap();
            if proof_range.min==0{
                ok_count += 1;
            }
        }
        println!("verify_bullet_proof ok:\t{}/{}", ok_count, BP_LENGTH);
        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} verify bullet proof)", used_time, BP_LENGTH);
        }
    }


    #[test]
    fn bench_bullet_proof_with_extra_msg() {
        const BP_LENGTH: usize = 1_000;

        let extra_data = [0u8;64].to_vec();

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let value = 12345678;
        let commit = secp.commit(value, blinding).unwrap();

        let mut now = SystemTime::now();
        let mut bullet_proof = secp.bullet_proof(value, blinding, blinding, Some(extra_data.clone()));

        for _ in 1..BP_LENGTH+1 {
            bullet_proof = secp.bullet_proof(value, blinding, blinding, Some(extra_data.clone()));
        }

        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} bullet proof with extra msg)", used_time, BP_LENGTH);
        }

        now = SystemTime::now();
        let mut ok_count = 0;
        for _ in 1..BP_LENGTH+1 {
            let proof_range = secp.verify_bullet_proof(commit, bullet_proof, Some(extra_data.clone())).unwrap();
            if proof_range.min==0{
                ok_count += 1;
            }
        }
        println!("verify_bullet_proof ok:\t{}/{}", ok_count, BP_LENGTH);
        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} verify bullet proof with extra msg)", used_time, BP_LENGTH);
        }
    }

}
