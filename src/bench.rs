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
    use pedersen::{Commitment, RangeProof};
    use rand::{Rng, thread_rng, OsRng};
    use std::time::{SystemTime};

    use constants;
    use ffi;

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

    #[test]
    fn bench_bulletproof_batch_verify() {
        const BP_LENGTH: usize = 1_000;

        let mut commits:Vec<Commitment> = vec![];
        let mut proofs:Vec<RangeProof> = vec![];

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let value = 12345678;

        let mut now = SystemTime::now();

        for i in 1..BP_LENGTH+1 {
            commits.push(secp.commit(value + i as u64, blinding).unwrap());
            proofs.push(secp.bullet_proof(value + i as u64, blinding, blinding, None));
        }

        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            let used_time_subsec_millis = elapsed.subsec_millis();
            println!("spent time:\t{}.{:0<3}(s)/({} bullet proof creation w/o extra message)",
                     used_time, used_time_subsec_millis, BP_LENGTH);
        }

        now = SystemTime::now();
        let proof_range = secp.verify_bullet_proof_multi(commits, proofs, None);
        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            let used_time_subsec_millis = elapsed.subsec_millis();
            println!("spent time:\t{}.{:0<3}(s)/(1 batch verify for {} bullet proofs w/o extra message)",
                     used_time, used_time_subsec_millis, BP_LENGTH);
        }
        println!("\nproof_range:\t{:#x?}", proof_range.unwrap());
    }

    #[test]
    fn bench_bulletproof_with_extra_batch_verify() {
        const BP_LENGTH: usize = 1_000;

        let mut commits:Vec<Commitment> = vec![];
        let mut proofs:Vec<RangeProof> = vec![];
        let mut extra_data_vec = vec![];

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let value = 12345678;
        let mut extra_data = [0u8;64];
        thread_rng().fill_bytes(&mut extra_data);

        let mut now = SystemTime::now();

        for i in 1..BP_LENGTH+1 {
            commits.push(secp.commit(value + i as u64, blinding).unwrap());
            extra_data_vec.push(extra_data.to_vec().clone());

            proofs.push(secp.bullet_proof(
                value + i as u64,
                blinding,
                blinding,
                Some(extra_data.to_vec().clone())));
        }

        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            let used_time_subsec_millis = elapsed.subsec_millis();
            println!("spent time:\t{}.{:0<3}(s)/({} bullet proof creation w/ extra data)",
                     used_time, used_time_subsec_millis, BP_LENGTH);
        }

        now = SystemTime::now();
        let proof_range = secp.verify_bullet_proof_multi(
            commits,
            proofs,
            Some(extra_data_vec.clone()));

        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            let used_time_subsec_millis = elapsed.subsec_millis();
            println!("spent time:\t{}.{:0<3}(s)/(1 batch verify for {} bullet proofs w/ extra data)",
                     used_time, used_time_subsec_millis, BP_LENGTH);
        }
        println!("\nproof_range:\t{:#x?}", proof_range.unwrap());
    }

    #[ignore]
    #[test]
    fn bench_generator_h_efficiency() {
        const PC_LENGTH: usize = 1_000_000;

        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        /// Generator H' (as compressed curve point (3))
        const GENERATOR_H_V2 : [u8;33] = [
            0x0a,
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
            0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
            0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
            0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0
        ];

        // Creates a pedersen commitment, with another 'H'
        fn commit_v2(secp: *const Secp256k1, value: u64, blind: SecretKey) -> Option<Commitment> {

            let mut commit = [0; 33];

            unsafe {
                if (*secp).caps != ContextFlag::Commit {
                    return None;
                }

                ffi::secp256k1_pedersen_commit(
                    (*secp).ctx,
                    commit.as_mut_ptr(),
                    blind.as_ptr(),
                    value,
                    GENERATOR_H_V2.as_ptr(),
                    constants::GENERATOR_G.as_ptr(),
                )
            };

            Some(Commitment(commit))
        }

        let mut r = SecretKey([0;32]);
        thread_rng().fill_bytes(&mut r.0);
        let value: u64 = 12345678;

        //--- H1

        let now = SystemTime::now();

        for i in 1..PC_LENGTH+1 {
            let _commit = secp.commit(value+i as u64, r);
        }

        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} pedersen commitment with H1)", used_time, PC_LENGTH);
        }

        //--- H2

        let now = SystemTime::now();

        for i in 1..PC_LENGTH+1 {
            let _commit = commit_v2(&secp, value+i as u64, r);
        }

        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} pedersen commitment with H2)", used_time, PC_LENGTH);
        }
    }

    #[ignore]
    #[test]
    fn bench_pubkey_check_eq() {
        const MAX_LENGTH: usize = 1000_000;

        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        let mut secret = SecretKey([0; 32]);
        thread_rng().fill_bytes(&mut secret.0);
        let pubkey1 = PublicKey::from_secret_key(&secp, &secret).unwrap();

        let now = SystemTime::now();

        let mut ok_count = 0;
        for _ in 1..MAX_LENGTH+1 {
            let pubkey2 = PublicKey::from_secret_key(&secp, &secret).unwrap();
            if pubkey1 == pubkey2{
                ok_count += 1;
            }
            thread_rng().fill_bytes(&mut secret.0);
        }
        println!("pubkey equal check ok:\t{}/{}", ok_count, MAX_LENGTH);
        if let Ok(elapsed) = now.elapsed() {
            let used_time = elapsed.as_secs();
            println!("spent time:\t{}(s)/({} pubkey equal check)", used_time, MAX_LENGTH);
        }
    }

}
