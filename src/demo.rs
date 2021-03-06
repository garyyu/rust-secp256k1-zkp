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
    extern crate chrono;
    extern crate hex;

    use aggsig::{
        add_signatures_single, get_pubnonce_from_signature, export_secnonce_single, sign_single, verify_single, AggSigContext,
    };
    use constants;
    use key::{PublicKey, SecretKey, ONE_KEY, ZERO_KEY};
    use pedersen::Commitment;
    use ContextFlag;
    use {AggSigPartialSignature, Message, Signature, Secp256k1};

    use demo::tests::chrono::prelude::Utc;

    use rand::{thread_rng, Rng};
    const NANO_TO_MILLIS: f64 = 1.0 / 1_000_000.0;

    #[test]
    fn demo_ecdsa_sign() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        let m = hex::decode("d0f756e2d96f49b32579bd9365fde07674629dcab236fd9af8c01085a0cf9201").unwrap();

        // signature
        let mut msg = [0u8; 32];
        msg.copy_from_slice(&m);
        let msg = Message::from_slice(&msg).unwrap();

        let mut secret = SecretKey([0; 32]);
        thread_rng().fill(&mut secret.0);
        let pubkey = PublicKey::from_secret_key(&secp, &secret).unwrap();

        let sig = secp.sign(&msg, &secret).unwrap();

        if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
            println!("msg={:?}", msg);
            println!("sig={:?}", sig);
            println!("ecdsa signature verification OK");
        } else {
            println!("ecdsa signature verification NOK");
        }
    }

    #[test]
    fn demo_ecdsa_verify() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        let m = hex::decode("d0f756e2d96f49b32579bd9365fde07674629dcab236fd9af8c01085a0cf9201").unwrap();
        let mut msg = [0u8; 32];
        msg.copy_from_slice(&m);
        let msg = Message::from_slice(&msg).unwrap();

        let pk = hex::decode("0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3").unwrap();
        let mut pubkey = [0u8; 65];
        pubkey.copy_from_slice(&pk);
        let pubkey = PublicKey::from_slice(&secp, &pubkey).unwrap();

        let s = hex::decode("99cc0d1f4ed3f1e6d18c130df22fece489b4ab016c33ed53db1ce45880bf4e996633f2e0b12c0e192e73ecf20dd0131a30fa31e54314b2e7e4b57a344f76f2a8").unwrap();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&s);
        let sig = Signature::from_compact(&secp, &sig).unwrap();

        if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
            println!("msg: {:?}", msg);
            println!("sig: {:?}", sig);
            println!("pubkey: {:?}", pubkey);
            println!("ecdsa signature verification OK");
        } else {
            println!("ecdsa signature verification NOK");
        }
    }

    #[test]
    fn test_show_g_and_h() {
        println!("G in (X,Y) coordinates form:\n\tX={:02x?}\n\tY={:02x?}\n\nG in compressed form:\n\t{:02x?}\n\nH in compressed form:\n\t{:02x?}",
                 SecretKey(constants::GENERATOR_X),
                 SecretKey(constants::GENERATOR_Y),
                 Commitment(constants::GENERATOR_G),
                 Commitment(constants::GENERATOR_H),
        );
    }

    #[test]
    fn test_show_j() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let pubkey1 = Commitment(constants::GENERATOR_J).to_pubkey(&secp).unwrap();
        println!("J in (X,Y) coordinates form:\n\t{:?}\n\nJ in compressed form:\n\t{:02x?}\n",
                 pubkey1,
                 Commitment(constants::GENERATOR_J),
        );
        let pubkey2 = PublicKey::from_slice(&secp, &constants::GENERATOR_PUB_J).unwrap();
        println!("J in (X,Y) coordinates form:\n\t{:?}\n\n",
                 pubkey2,
        );
        assert_eq!(pubkey1, pubkey2);

        println!("\n----\n");

        let pubkey1 = Commitment(constants::GENERATOR_G).to_pubkey(&secp).unwrap();
        println!("G in (X,Y) coordinates form:\n\t{:?}\n\nG in compressed form:\n\t{:02x?}\n",
                 pubkey1,
                 Commitment(constants::GENERATOR_G),
        );
        let pubkey2 = PublicKey::from_slice(&secp, &constants::GENERATOR_PUB_G).unwrap();
        println!("G in (X,Y) coordinates form:\n\t{:?}\n\n",
                 pubkey2,
        );
        assert_eq!(pubkey1, pubkey2);

        println!("\n----\n");

        let pubkey1 = Commitment(constants::GENERATOR_H).to_pubkey(&secp).unwrap();
        println!("H in (X,Y) coordinates form:\n\t{:?}\n\nH in compressed form:\n\t{:02x?}\n",
                 pubkey1,
                 Commitment(constants::GENERATOR_H),
        );
        let pubkey2 = PublicKey::from_slice(&secp, &constants::GENERATOR_PUB_H).unwrap();
        println!("H in (X,Y) coordinates form:\n\t{:?}\n\n",
                 pubkey2,
        );
        assert_eq!(pubkey1, pubkey2);
    }

    #[test]
    fn test_pedersen_zero_r() {
        fn commit(value: u64) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            let blinding = ZERO_KEY;
            secp.commit(value, blinding).unwrap()
        }

        println!(
            "0*G+1*H:\t{:?}\n0*G+2*H:\t{:?}\n0*G+3*H:\t{:?}",
            commit(1),
            commit(2),
            commit(3),
        );
    }

    #[test]
    fn test_pedersen_zero_r_max_v() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            let blinding = ZERO_KEY;
            secp.commit(value, blinding).unwrap()
        }

        let commit_1 = commit(<u64>::max_value());
        let commit_2 = commit(1);

        let sum12 = secp.commit_sum(vec![commit_1, commit_2], vec![]).unwrap();

        println!(
            "0*G+3*H:\t{:?}\n0*G+2*H:\t{:?}\nsum:\t\t{:?}",
            commit_1, commit_2, sum12,
        );
    }

    #[test]
    fn test_pedersen_zero_neg_v() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: i64, one_or_zero_key: bool) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            let mut blinding = ZERO_KEY;
            if one_or_zero_key {
                blinding = ONE_KEY;
            }

            secp.commit_i(value, blinding).unwrap()
        }

        let commit_1 = commit(-5, false);
        let commit_2 = commit(5, false);

        println!(
            "0*G-5*H:\t{:?}\n0*G+5*H:\t{:?}\n-(0*G-5*H):\t{:?}",
            commit_1,
            commit_2,
            secp.commit_sum(vec![], vec![commit_1]).unwrap(),
        );

        println!("\n");
        let commit_3 = commit(-5, true);
        let commit_4 = commit(5, false);
        let commit_5 = commit(0, true);

        println!(
            "1*G-5*H:\t{:?}\n0*G+5*H:\t{:?}\n1*G+0*H:\t{:?}\nsum first 2:\t{:?}",
            commit_3,
            commit_4,
            commit_5,
            secp.commit_sum(vec![commit_3, commit_4], vec![]).unwrap(),
        );
    }

    #[test]
    fn test_pedersen_blind_sum() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        let mut r1 = SecretKey([0; 32]);
        let mut r2 = SecretKey([0; 32]);

        r1.0[31] = 1;
        r2.0[31] = 2;

        let blind_sum = secp.blind_sum(vec![r1, r2], vec![]);

        println!("r1:\t{:?}\nr2:\t{:?}\nr1+r2:\t{:?}", r1, r2, blind_sum,);

        println!("");

        r1.0[31] = 3;
        r2.0[31] = 1;

        let blind_sum = secp.blind_sum(vec![r1], vec![r2]);

        println!("r1:\t{:?}\nr2:\t{:?}\nr1-r2:\t{:?}", r1, r2, blind_sum,);
    }

    #[test]
    fn test_pedersen_zero_v() {
        fn commit(blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(0, blinding).unwrap()
        }

        let mut r1 = SecretKey([0; 32]);
        let mut r2 = SecretKey([0; 32]);
        let mut r3 = SecretKey([0; 32]);

        r1.0[31] = 1;
        r2.0[31] = 2;
        r3.0[31] = 3;

        println!(
            "1*G+0*H:\t{:?}\n2*G+0*H:\t{:?}\n3*G+0*H:\t{:?}",
            commit(r1),
            commit(r2),
            commit(r3),
        );
    }

    #[test]
    fn test_pedersen_demo_sum() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        let mut r1 = SecretKey([0; 32]);
        let mut r2 = SecretKey([0; 32]);
        let mut r3 = SecretKey([0; 32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;

        let commit_1 = commit(3, r1);
        let commit_2 = commit(2, r2);
        let commit_3 = commit(1, r3);

        let sum23 = secp.commit_sum(vec![commit_2, commit_3], vec![]).unwrap();

        println!(
            "113*G+3*H:\t{:?}\n 71*G+2*H:\t{:?}\n 42*G+1*H:\t{:?}\nsum last2:\t{:?}",
            commit_1, commit_2, commit_3, sum23,
        );
    }

    #[test]
    fn test_pedersen_demo_safe_output() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        let mut r1 = SecretKey([0; 32]);
        let mut r2 = SecretKey([0; 32]);
        let mut r3 = SecretKey([0; 32]);
        let mut r4 = SecretKey([0; 32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;
        r4.0[31] = 28;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, r4], vec![]).unwrap());
        let output2 = commit(1, r3);

        let sum = secp.commit_sum(vec![output1, output2], vec![]).unwrap();

        let excess = secp
            .commit_sum(vec![output1, output2], vec![input])
            .unwrap();

        println!("  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}\n\toutputs sum:\t{:?}\n\texcess :\t{:?}",
                 input,
                 output1,
                 output2,
                 sum,
                 excess,
        );
    }

    #[test]
    fn test_pedersen_demo_sign_for_output() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        let mut r1 = SecretKey([0; 32]);
        let mut r2 = SecretKey([0; 32]);
        let mut r3 = SecretKey([0; 32]);
        let mut r4 = SecretKey([0; 32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;
        r4.0[31] = 28;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, r4], vec![]).unwrap());
        let output2 = commit(1, r3);

        let sum = secp.commit_sum(vec![output1, output2], vec![]).unwrap();

        let excess = secp
            .commit_sum(vec![output1, output2], vec![input])
            .unwrap();

        println!("  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}\n\toutputs sum:\t{:?}\n\texcess :\t{:?}",
                 input,
                 output1,
                 output2,
                 sum,
                 excess,
        );

        // sign it

        let excess = secp
            .commit_sum(vec![output1, output2], vec![input])
            .unwrap();

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &r4).unwrap();

        let pubkey = excess.to_pubkey(&secp).unwrap();

        println!(
            "\nmsg:\t{:?}\npublic key:\t{:?}\nSignature:\t{:?}",
            msg, pubkey, sig,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }
    }

    #[test]
    fn test_pedersen_demo_try_spend_output_without_key() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        let mut r1 = SecretKey([0; 32]);
        let mut r2 = SecretKey([0; 32]);
        let mut r3 = SecretKey([0; 32]);
        let mut r4 = SecretKey([0; 32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;
        r4.0[31] = 28;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, r4], vec![]).unwrap());
        let output2 = commit(1, r3);

        let sum = secp.commit_sum(vec![output1, output2], vec![]).unwrap();

        let excess = secp
            .commit_sum(vec![output1, output2], vec![input])
            .unwrap();

        println!("  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}\n\toutputs sum:\t{:?}\n\texcess :\t{:?}",
                 input,
                 output1,
                 output2,
                 sum,
                 excess,
        );

        println!("\n\n");

        //-------- simulate a hacker try to spend an output without key and value -------//

        // to spend an output, one must prove he/she know the secret and the value,
        // otherwise like this...

        // output1 is included in the existing blocks
        let new_input = output1;

        let mut new_r1 = SecretKey([0; 32]);
        let mut new_r2 = SecretKey([0; 32]);
        let mut new_r3 = SecretKey([0; 32]);
        let mut new_r4 = SecretKey([0; 32]);

        // hacker don't know the real 'r' of input,
        // have to guess or through exhaustive effort (using brute force)
        let guess: u8 = 200;
        new_r1.0[31] = guess;
        new_r2.0[31] = guess - 15; // = r1-r3
        new_r3.0[31] = 15; // suppose hacker choose 15 as his change output private key
        new_r4.0[31] = 88; // suppose the recipient choose 88 as his output private key

        let new_output1 = commit(1, secp.blind_sum(vec![new_r2, new_r4], vec![]).unwrap());
        let new_output2 = commit(1, new_r3);

        let new_excess = secp
            .commit_sum(vec![new_output1, new_output2], vec![new_input])
            .unwrap();

        println!("  input={}*G+2*H:\t{:?}\noutput1={}*G+1*H:\t{:?}\noutput2= 15*G+1*H:\t{:?}\n\texcess :\t{:?}",
                 guess,
                 new_input,
                 new_r2.0[31] as u64 + new_r4.0[31] as u64,
                 new_output1,
                 new_output2,
                 new_excess,
        );

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &new_r4).unwrap();

        let new_pubkey = new_excess.to_pubkey(&secp).unwrap();

        println!(
            "\nmsg:\t{:?}\npublic key:\t{:?}\nSignature:\t{:?}",
            msg, new_pubkey, sig,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &sig, &new_pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }
    }

    #[test]
    fn test_pedersen_subset_sum_problem_fix() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        let mut r1 = SecretKey([0; 32]);
        let mut r2 = SecretKey([0; 32]);
        let mut r3 = SecretKey([0; 32]);
        let mut r4 = SecretKey([0; 32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;
        r4.0[31] = 28;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, r4], vec![]).unwrap());
        let output2 = commit(1, r3);

        let excess = secp
            .commit_sum(vec![output1, output2], vec![input])
            .unwrap();

        println!(
            "  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}",
            input, output1, output2,
        );

        // sign it

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &r4).unwrap();

        let pubkey = excess.to_pubkey(&secp).unwrap();

        println!(
            "\n\tmsg:\t\t{:?}\n\texcess:\t\t{:?}\n\tSignature:\t{:?}",
            msg, excess, sig,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true == secp.verify_commit_sum(vec![output1, output2], vec![input, excess]) {
            println!("\n\"subset sum\" verify OK:\toutput1+output2 = input+excess");
        } else {
            println!("\n\"subset sum\" verify NOK:\toutput1+output2 = input+excess");
        }

        //------	"Subset Sum" problem fixing		-----//

        println!("\n\"Subset Sum\" Problem Fixing...\n");

        // split original r=28 into k1+k2
        let mut k1 = SecretKey([0; 32]);
        let mut k2 = SecretKey([0; 32]);
        k1.0[31] = 13;
        k2.0[31] = 15;

        let new_output1 = commit(2, secp.blind_sum(vec![r2, k1, k2], vec![]).unwrap());
        let tmp = commit(2, secp.blind_sum(vec![r2, k1], vec![]).unwrap());

        // publish k1*G as excess and k2, instead of (k1+k2)*G
        let new_excess = secp.commit_sum(vec![tmp, output2], vec![input]).unwrap();

        println!(
            "  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}",
            input, new_output1, output2,
        );

        // sign it only with k1 instead of (k1+k2)

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let new_sig = secp.sign(&msg, &k1).unwrap();

        let new_pubkey = new_excess.to_pubkey(&secp).unwrap();

        println!(
            "\n\tmsg:\t\t{:?}\n\texcess w/ k1*G:\t{:?}\n\tSignature:\t{:?}\n\tk2:\t\t{:?}",
            msg, new_excess, new_sig, k2,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &new_sig, &new_pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true == secp.verify_commit_sum(vec![new_output1, output2], vec![input, new_excess]) {
            println!("\n\"subset sum\" verify OK:\toutput1+output2 = input+excess");
        } else {
            println!("\n\"subset sum\" verify NOK:\toutput1+output2 != input+excess");
        }
    }

    #[test]
    fn test_demo_aggregate_transactions() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        //------	transaction 1		-----//

        println!("\nFirst transaction...\n");

        let mut r1 = SecretKey([0; 32]);
        let mut r2 = SecretKey([0; 32]);
        let mut r3 = SecretKey([0; 32]);

        r1.0[31] = 113; // input
        r3.0[31] = 42; // for change
        r2.0[31] = 113 - 42; // total blinding factor from sender

        // split original r=28 into k1+k2
        let mut k1 = SecretKey([0; 32]);
        let mut k2 = SecretKey([0; 32]);
        k1.0[31] = 13;
        k2.0[31] = 15;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, k1, k2], vec![]).unwrap());
        let output2 = commit(1, r3);
        let tmp = commit(2, secp.blind_sum(vec![r2, k1], vec![]).unwrap());

        // publish k1*G as excess and k2, instead of (k1+k2)*G
        let excess = secp.commit_sum(vec![tmp, output2], vec![input]).unwrap();

        println!(
            "  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}",
            input, output1, output2,
        );

        // sign it only with k1 instead of (k1+k2)

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &k1).unwrap();

        let pubkey = excess.to_pubkey(&secp).unwrap();

        println!(
            "\n\tmsg:\t\t{:?}\n\texcess w/ k1*G:\t{:?}\n\tSignature:\t{:?}\n\tk2:\t\t{:?}",
            msg, excess, sig, k2,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true == secp.verify_commit_sum(vec![output1, output2], vec![input, excess]) {
            println!("\n\"subset sum\" verify OK:\toutput1+output2 = input+excess");
        } else {
            println!("\n\"subset sum\" verify NOK:\toutput1+output2 != input+excess");
        }

        if true
            == secp.verify_commit_sum(vec![output1, output2], vec![input, excess, commit(0, k2)])
        {
            println!("\nsum with k2*G verify OK:\toutput1 + output2 = input + excess + k2*G");
        } else {
            println!("\nsum with k2*G verify NOK:\toutput1 + output2 != input + excess + k2*G");
        }

        //------	transaction 2		-----//

        println!("\nSecond transaction...\n");

        let mut new_r1 = SecretKey([0; 32]);
        let mut new_r2 = SecretKey([0; 32]);
        let mut new_r3 = SecretKey([0; 32]);

        new_r1.0[31] = 205; // input
        new_r3.0[31] = 68; // for change
        new_r2.0[31] = 205 - 68; // total blinding factor from sender

        // split original r=79 into k1+k2
        let mut new_k1 = SecretKey([0; 32]);
        let mut new_k2 = SecretKey([0; 32]);
        new_k1.0[31] = 55;
        new_k2.0[31] = 24;

        let new_input = commit(10, new_r1);
        let new_output1 = commit(
            6,
            secp.blind_sum(vec![new_r2, new_k1, new_k2], vec![])
                .unwrap(),
        );
        let new_output2 = commit(4, new_r3);
        let new_tmp = commit(6, secp.blind_sum(vec![new_r2, new_k1], vec![]).unwrap());

        // publish k1*G as excess and k2, instead of (k1+k2)*G
        let new_excess = secp
            .commit_sum(vec![new_tmp, new_output2], vec![new_input])
            .unwrap();

        println!(
            "  input=205*G+10*H:\t{:?}\noutput1= 216*G+6*H:\t{:?}\noutput2= 68*G+4*H:\t{:?}",
            new_input, new_output1, new_output2,
        );

        // sign it only with k1 instead of (k1+k2)

        let mut new_msg = [0u8; 32];
        thread_rng().fill(&mut new_msg);
        let new_msg = Message::from_slice(&new_msg).unwrap();

        let new_sig = secp.sign(&new_msg, &new_k1).unwrap();

        let new_pubkey = new_excess.to_pubkey(&secp).unwrap();

        println!(
            "\n\tmsg:\t\t{:?}\n\texcess w/ k1*G:\t{:?}\n\tSignature:\t{:?}\n\tk2:\t\t{:?}",
            new_msg, new_excess, new_sig, new_k2,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&new_msg, &new_sig, &new_pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true
            == secp.verify_commit_sum(vec![new_output1, new_output2], vec![new_input, new_excess])
        {
            println!("\n\"subset sum\" verify OK:\toutput1+output2 = input+excess");
        } else {
            println!("\n\"subset sum\" verify NOK:\toutput1+output2 != input+excess");
        }

        if true == secp.verify_commit_sum(
            vec![new_output1, new_output2],
            vec![new_input, new_excess, commit(0, new_k2)],
        ) {
            println!("\nsum with k2*G verify OK:\toutput1 + output2 = input + excess + k2*G");
        } else {
            println!("\nsum with k2*G verify NOK:\toutput1 + output2 != input + excess + k2*G");
        }

        //------	aggregate transactions		-----//

        println!("\naggregate these 2 transactions...\n");

        println!(" input1=113*G+3*H:\t{:?}\n input2=205*G+10*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}",
                 input,
                 new_input,
                 output1,
                 output2,
        );
        println!(
            "output3= 216*G+6*H:\t{:?}\noutput4= 68*G+4*H:\t{:?}",
            new_output1, new_output2,
        );
        println!(
            "\n\tmsg1:\t\t{:?}\n\texcess1:\t{:?}\n\tSignature1:\t{:?}",
            msg, excess, sig,
        );
        println!(
            "\n\tmsg2:\t\t{:?}\n\texcess2:\t{:?}\n\tSignature1:\t{:?}\n\n\tsum(k2):\t{:?}",
            new_msg,
            new_excess,
            new_sig,
            secp.blind_sum(vec![k2, new_k2], vec![]).unwrap(),
        );

        // now let's check this "aggregated transaction":

        if true == secp.verify_commit_sum(
            vec![output1, output2, new_output1, new_output2],
            vec![
                input,
                new_input,
                excess,
                new_excess,
                commit(0, secp.blind_sum(vec![k2, new_k2], vec![]).unwrap()),
            ],
        ) {
            println!("\ntotal sum balance verify OK:\toutput1 + output2 + output3 + output4 = input1 + input2 + excess1 + excess2 + sum(k2)*G");
        } else {
            println!("\ntotal sum balance verify NOK:\toutput1 + output2 + output3 + output4 = input1 + input2 + excess1 + excess2 + sum(k2)*G");
        }
    }

    #[test]
    fn test_demo_fraud_transactions() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: i64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);

            secp.commit_i(value, blinding).unwrap()
        }

        let mut r1 = SecretKey([0; 32]);
        let mut r2 = SecretKey([0; 32]);
        let mut r3 = SecretKey([0; 32]);

        r1.0[31] = 113; // input
        r3.0[31] = 42; // for change
        r2.0[31] = 113 - 42; // total blinding factor from sender

        // split original r=28 into k1+k2
        let mut k1 = SecretKey([0; 32]);
        let mut k2 = SecretKey([0; 32]);
        k1.0[31] = 13;
        k2.0[31] = 15;

        let input = commit(3, r1);
        let output1 = commit(103, secp.blind_sum(vec![r2, k1, k2], vec![]).unwrap());
        let output2 = commit(-100, r3);
        let tmp = commit(103, secp.blind_sum(vec![r2, k1], vec![]).unwrap());

        // publish k1*G as excess and k2, instead of (k1+k2)*G
        // k component:
        //     (r2+k1+r3-r1)*G = (113-42+13+42-113)*G = 13*G
        //      ~~~~~ ~~ ~~       ~~~~~~~~~ ~~ ~~~
        // v component:
        //     (103+(-100)-3)*H = 0*H
        //
        let excess = secp.commit_sum(vec![tmp, output2], vec![input]).unwrap();

        println!(
            "  input=113*G+3*H:\t{:?}\noutput1= 99*G+103*H:\t{:?}\noutput2= 42*G-100*H:\t{:?}",
            input, output1, output2,
        );

        // sign it only with k1 instead of (k1+k2)

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &k1).unwrap();

        let pubkey = excess.to_pubkey(&secp).unwrap();

        println!(
            "\n\tmsg:\t\t{:?}\n\texcess w/ k1*G:\t{:?}\n\tSignature:\t{:?}\n\tk2:\t\t{:?}",
            msg, excess, sig, k2,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true
            == secp.verify_commit_sum(vec![output1, output2], vec![input, excess, commit(0, k2)])
        {
            println!("\nsum with k2*G verify OK:\toutput1 + output2 = input + excess + k2*G");
        } else {
            println!("\nsum with k2*G verify NOK:\toutput1 + output2 != input + excess + k2*G");
        }
    }

    #[test]
    fn test_demo_bullet_proof() {
        println!("Demo Bullet Proof without extra message data...\n");

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let blinding = SecretKey::new(&secp, &mut thread_rng());
        let value = 12345678;
        let commit = secp.commit(value, blinding).unwrap();
        let bullet_proof = secp.bullet_proof(value, blinding, blinding, None, None);

        println!(
            "Value:\t\t{}\nBlinding:\t{:?}\nCommitment:\t{:?}\n\nBullet Proof:\t{:?}",
            value, blinding, commit, bullet_proof,
        );

        let proof_range = secp
            .verify_bullet_proof(commit, bullet_proof, None)
            .unwrap();
        println!("\nVerification:\t{:#?}", proof_range);

        //-----

        println!("\nDemo Bullet Proof with extra message data...\n");

        let extra_data = [0u8; 32].to_vec();
        let blinding = SecretKey::new(&secp, &mut thread_rng());
        let value = 12345678;
        let commit = secp.commit(value, blinding).unwrap();
        let bullet_proof =
            secp.bullet_proof(value, blinding, blinding, Some(extra_data.clone()), None);

        println!("Value:\t\t{}\nBlinding:\t{:?}\nExtra data:\t{:?}\nCommitment:\t{:?}\n\nBullet Proof:\t{:?}",
                 value,
                 blinding,
                 (extra_data),
                 commit,
                 bullet_proof,
        );

        let proof_range = secp
            .verify_bullet_proof(commit, bullet_proof, Some(extra_data.clone()))
            .unwrap();
        println!("\nVerification:\t{:#?}", proof_range);

        //-----

        println!("\nDemo rewinding. Extracts the value and blinding factor...\n");

        let blinding = SecretKey::new(&secp, &mut thread_rng());
        let nonce = SecretKey::new(&secp, &mut thread_rng());
        let value = 12345678;
        let commit = secp.commit(value, blinding).unwrap();
        let bullet_proof =
            secp.bullet_proof(value, blinding, nonce, Some(extra_data.clone()), None);

        println!("Value:\t\t{}\nBlinding:\t{:?}\nExtra data:\t{:?}\nNonce:\t{:?}\nCommitment:\t{:?}\n\nBullet Proof:\t{:?}",
                 value,
                 blinding,
                 (extra_data),
                 nonce,
                 commit,
                 bullet_proof,
        );

        // Extracts the value and blinding factor from a single-commit rangeproof,
        // given a secret 'nonce'.
        //
        let proof_info = secp
            .rewind_bullet_proof(commit, nonce, Some(extra_data.clone()), bullet_proof)
            .unwrap();
        println!("\nRewind_bullet_proof:\t{:#?}", proof_info);

        println!("Bullet Proof:\t{:?}", bullet_proof,);

        let proof_range = secp
            .verify_bullet_proof(commit, bullet_proof, Some(extra_data.clone()))
            .unwrap();
        println!("\nVerification:\t{:#?}", proof_range);
    }

    #[test]
    fn test_demo_aggregated_bullet_proof() {
        println!("Demo Bullet Proof Aggregation w/o extra message data...\n");

        println!("MAX_PROOF_SIZE: {}\n", constants::MAX_PROOF_SIZE);

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let blinds = vec![
            SecretKey::new(&secp, &mut thread_rng()),
            SecretKey::new(&secp, &mut thread_rng()),
        ];
        let nonce = SecretKey::new(&secp, &mut thread_rng());
        let values = vec![12345678, 87654321];
        let commits = vec![
            secp.commit(values[0], blinds[0]).unwrap(),
            secp.commit(values[1], blinds[1]).unwrap(),
        ];
        let bullet_proof = secp.bullet_proof_agg(values.clone(), blinds.clone(), nonce, None, None);

        println!(
            "Values:\t\t{:#?}\nBlinds:\t{:#?}\nCommits:\t{:#?}\n\nBullet Proof:\t{:?}",
            values, blinds, commits, bullet_proof,
        );

        let proof_range = secp
            .verify_bullet_proof_agg(commits.clone(), bullet_proof, None)
            .unwrap();
        println!("\nVerification:\t{:#?}", proof_range);

        //-----

        println!("\nDemo Bullet Proof Aggregation w/ extra message data...\n");

        let extra_data = [0u8; 32].to_vec();
        let bullet_proof = secp.bullet_proof_agg(
            values.clone(),
            blinds.clone(),
            nonce,
            Some(extra_data.clone()),
            None,
        );

        println!("Values:\t\t{:#?}\nBlinds:\t{:#?}\nExtra data:\t{:?}\nCommits:\t{:#?}\n\nBullet Proof:\t{:?}",
                 values,
                 blinds,
                 (extra_data),
                 commits,
                 bullet_proof,
        );

        let proof_range = secp
            .verify_bullet_proof_agg(commits.clone(), bullet_proof, Some(extra_data.clone()))
            .unwrap();
        println!("\nVerification:\t{:#?}", proof_range);

        //----

        println!("Demo Bullet Proof Aggregation for 4 commits...\n");

        let mut blinds = vec![];
        for _ in 0..4 {
            blinds.push( SecretKey::new(&secp, &mut thread_rng()) );
        }
        let nonce = SecretKey::new(&secp, &mut thread_rng());
        let mut values = vec![];
        for i in 0..4 {
            values.push(10001+i);
        }
        let mut commits = vec![];
        for i in 0..4 {
            commits.push(secp.commit(values[i], blinds[i]).unwrap());
        }
        let bullet_proof = secp.bullet_proof_agg(values.clone(), blinds.clone(), nonce, None, None);

        println!(
            "Values:\t\t{:#?}\nBlinds:\t{:#?}\nCommits:\t{:#?}\n\nBullet Proof:\t{:?}",
            values, blinds, commits, bullet_proof,
        );

        let proof_range = secp.verify_bullet_proof_agg(commits.clone(), bullet_proof, None);
        println!("\nVerification:\t{:#?}", proof_range);

        //----

        println!("Demo Bullet Proof Aggregation for 8 commits...\n");

        let mut blinds = vec![];
        for _ in 0..8 {
            blinds.push( SecretKey::new(&secp, &mut thread_rng()) );
        }
        let nonce = SecretKey::new(&secp, &mut thread_rng());
        let mut values = vec![];
        for i in 0..8 {
            values.push(10001+i);
        }
        let mut commits = vec![];
        for i in 0..8 {
            commits.push(secp.commit(values[i], blinds[i]).unwrap());
        }
        let bullet_proof = secp.bullet_proof_agg(values.clone(), blinds.clone(), nonce, None, None);

        println!(
            "Values:\t\t{:#?}\nBlinds:\t{:#?}\nCommits:\t{:#?}\n\nBullet Proof:\t{:?}",
            values, blinds, commits, bullet_proof,
        );

        let proof_range = secp.verify_bullet_proof_agg(commits.clone(), bullet_proof, None);
        println!("\nVerification:\t{:#?}", proof_range);

        //----

        println!("Demo Bullet Proof Aggregation for 16 commits...\n");

        let mut blinds = vec![];
        for _ in 0..16 {
            blinds.push( SecretKey::new(&secp, &mut thread_rng()) );
        }
        let nonce = SecretKey::new(&secp, &mut thread_rng());
        let mut values = vec![];
        for i in 0..16 {
            values.push(10001+i);
        }
        let mut commits = vec![];
        for i in 0..16 {
            commits.push(secp.commit(values[i], blinds[i]).unwrap());
        }
        let bullet_proof = secp.bullet_proof_agg(values.clone(), blinds.clone(), nonce, None, None);

        println!(
            "Values:\t\t{:#?}\nBlinds:\t{:#?}\nCommits:\t{:#?}\n\nBullet Proof:\t{:?}",
            values, blinds, commits, bullet_proof,
        );

        let proof_range = secp.verify_bullet_proof_agg(commits.clone(), bullet_proof, None);
        println!("\nVerification:\t{:#?}", proof_range);

        //----

        println!("Demo Bullet Proof Aggregation for 1024 commits...\n");
        let start = Utc::now().timestamp_nanos();

        let mut blinds = vec![];
        for _ in 0..1024 {
            blinds.push( SecretKey::new(&secp, &mut thread_rng()) );
        }
        let nonce = SecretKey::new(&secp, &mut thread_rng());
        let mut values = vec![];
        for i in 0..1024 {
            values.push(10001+i);
        }
        let mut commits = vec![];
        for i in 0..1024 {
            commits.push(secp.commit(values[i], blinds[i]).unwrap());
        }
        let bullet_proof = secp.bullet_proof_agg(values.clone(), blinds.clone(), nonce, None, None);
        let fin = Utc::now().timestamp_nanos();
        let dur_ms = (fin - start) as f64 * NANO_TO_MILLIS;

        println!("spent time:\t{}ms/(1024 bullet proof aggregation)", dur_ms);

        println!(
            "Values:\t\t{:#?}\nBlinds:\t{:#?}\nCommits:\t{:#?}\n\nBullet Proof:\t{:?}",
            values, blinds, commits, bullet_proof,
        );

        let start = Utc::now().timestamp_nanos();
        let proof_range = secp.verify_bullet_proof_agg(commits.clone(), bullet_proof, None);
        let fin = Utc::now().timestamp_nanos();
        let dur_ms = (fin - start) as f64 * NANO_TO_MILLIS;

        println!("spent time:\t{}ms/(agg bullet proof verification)", dur_ms);
        println!("\nVerification:\t{:#?}", proof_range);

        //-----

        println!("\nDemo rewinding skipped. Rewind only support single-commit rangeproof!\n");
    }

    #[test]
    fn test_demo_aggregated_bullet_proof_124() {
        println!("Demo Bullet Proof Aggregation w/o extra message data...\n");

        println!("MAX_PROOF_SIZE: {}\n", constants::MAX_PROOF_SIZE);

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let mut blinds = vec![
            SecretKey::new(&secp, &mut thread_rng()),
        ];
        let nonce = SecretKey::new(&secp, &mut thread_rng());
        let mut values = vec![12345678];
        let mut commits = vec![
            secp.commit(values[0], blinds[0]).unwrap(),
        ];
        let bullet_proof = secp.bullet_proof_agg(values.clone(), blinds.clone(), nonce.clone(), None, None);

        println!(
            "Values:\t\t{:#?}\nBlinds:\t{:#?}\nCommits:\t{:#?}\n\nBullet Proof:\t{:?}",
            values, blinds, commits, bullet_proof,
        );

        let proof_range = secp
            .verify_bullet_proof_agg(commits.clone(), bullet_proof, None)
            .unwrap();
        println!("\nVerification:\t{:#?}", proof_range);

        //----

        println!("Demo Bullet Proof Aggregation for 2 commits...\n");

        blinds.push( SecretKey::new(&secp, &mut thread_rng()) );
        values.push(87654321);
        commits.push(secp.commit(values[1], blinds[1]).unwrap());
        let bullet_proof = secp.bullet_proof_agg(values.clone(), blinds.clone(), nonce.clone(), None, None);

        println!(
            "Values:\t\t{:#?}\nBlinds:\t{:#?}\nCommits:\t{:#?}\n\nBullet Proof:\t{:?}",
            values, blinds, commits, bullet_proof,
        );

        let proof_range = secp.verify_bullet_proof_agg(commits.clone(), bullet_proof, None);
        println!("\nVerification:\t{:#?}", proof_range);

        //----

        println!("Demo Bullet Proof Aggregation for 4 commits...\n");

        for _ in 0..2 {
            blinds.push( SecretKey::new(&secp, &mut thread_rng()) );
        }
        for i in 0..2 {
            values.push(10001+i);
        }
        for i in 2..4 {
            commits.push(secp.commit(values[i], blinds[i]).unwrap());
        }
        let bullet_proof = secp.bullet_proof_agg(values.clone(), blinds.clone(), nonce.clone(), None, None);

        println!(
            "Values:\t\t{:#?}\nBlinds:\t{:#?}\nCommits:\t{:#?}\n\nBullet Proof:\t{:?}",
            values, blinds, commits, bullet_proof,
        );

        let proof_range = secp.verify_bullet_proof_agg(commits.clone(), bullet_proof, None);
        println!("\nVerification:\t{:#?}", proof_range);
    }

    #[test]
    fn demo_aggsig_single() {
        let secp = Secp256k1::with_caps(ContextFlag::Full);
        let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk, sk);

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let sig = sign_single(&secp, &msg, &sk, None, None, None, None, None).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig:\t\t{:?}", sig);

        let result = verify_single(&secp, &sig, &msg, None, &pk, None, None, false);
        if true == result {
            println!("signature check:\tOK");
        } else {
            println!("signature check:\tNOK");
        }
    }

    #[test]
    fn demo_aggsig_multi() {
        let numkeys = 3;
        let secp = Secp256k1::with_caps(ContextFlag::Full);

        let mut keypairs: Vec<(SecretKey, PublicKey)> = vec![];
        for _ in 0..numkeys {
            keypairs.push(secp.generate_keypair(&mut thread_rng()).unwrap());
        }

        let pks: Vec<PublicKey> = keypairs.clone().into_iter().map(|(_, p)| p).collect();

        println!("aggsig context with {} pubkeys: {:#?}", pks.len(), pks);

        let aggsig = AggSigContext::new(&secp, &pks);

        println!("Generating nonces for each index");
        for i in 0..numkeys {
            let retval = aggsig.generate_nonce(i);
            println!("{} returned {}", i, retval);
        }

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let mut partial_sigs: Vec<AggSigPartialSignature> = vec![];
        for i in 0..numkeys {
            println!(
                "\nPartial sign:\n\tmessage:\t{:?} at index {}\n\tPubkey:\t\t{:?}",
                msg, i, keypairs[i].1
            );

            let result = aggsig.partial_sign(msg, keypairs[i].0, i);
            match result {
                Ok(ps) => {
                    println!("\tPartial sig:\t{:?}", ps);
                    partial_sigs.push(ps);
                }
                Err(e) => panic!("Partial sig failed: {}", e),
            }
        }

        let result = aggsig.combine_signatures(&partial_sigs);

        let combined_sig = match result {
            Ok(cs) => {
                println!("\nCombined sig: {:?}", cs);
                cs
            }
            Err(e) => panic!("\nCombining partial sig failed: {}", e),
        };

        println!(
            "\nCombined sig: {:?}\n\tmsg:\t{:?}\n\tpks:\t{:#?}",
            combined_sig, msg, pks
        );
        let result = aggsig.verify(combined_sig, msg, &pks);
        if true == result {
            println!("\nSignature verification:\tOK");
        } else {
            println!("\nSignature verification:\tNOK");
        }
    }

    #[test]
    fn demo_aggsig_batch_verify() {
        /*
         * Signature Aggregation (Batch Verification):
         * All the signatures in the block can be removed and only keep an aggregated one.
         * Signature aggregation can be done by a miner and save a lot of space in the block.
         */

        let secp = Secp256k1::with_caps(ContextFlag::Full);

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        //--- Generate nonce: k1,k2,k3
        let secnonce_1 = export_secnonce_single(&secp).unwrap();
        let secnonce_2 = export_secnonce_single(&secp).unwrap();
        let secnonce_3 = export_secnonce_single(&secp).unwrap();

        //--- Calculate public nonce: R1,R2,R3
        let pubnonce_1 = PublicKey::from_secret_key(&secp, &secnonce_1).unwrap();
        let pubnonce_2 = PublicKey::from_secret_key(&secp, &secnonce_2).unwrap();
        let pubnonce_3 = PublicKey::from_secret_key(&secp, &secnonce_3).unwrap();

        //--- And sum public nonce: R = R1+R2+R3
        let nonce_sum =
            PublicKey::from_combination(&secp, vec![&pubnonce_1, &pubnonce_2, &pubnonce_3])
                .unwrap();

        //--- sig1
        println!("\n--- sig1 ---");

        let (sk1, pk1) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk1, sk1);

        // e=hash(R.x, m)    s=k1+e*p1    sig1=(s,r1)
        let sig1 = sign_single(
            &secp,
            &msg,
            &sk1,
            Some(&secnonce_1),
            None,
            Some(&nonce_sum),
            None,
            Some(&nonce_sum),
        ).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig1:\t\t{:?}", sig1);

        // sig1.s*G-e*P1 = k1*G+e*p1*G-e*P1 = R1,   check R1.x == sig1.r ?
        let result = verify_single(&secp, &sig1, &msg, Some(&nonce_sum), &pk1, None, None, true);
        if true == result {
            println!("sig1 signature check:\tOK");
        } else {
            println!("sig1 signature check:\tNOK");
        }

        //--- sig2

        println!("\n--- sig2 ---");

        let (sk2, pk2) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk2, sk2);

        // e=hash(R.x, m)    s=k2+e*p2    sig2=(s,r2)
        let sig2 = sign_single(
            &secp,
            &msg,
            &sk2,
            Some(&secnonce_2),
            None,
            Some(&nonce_sum),
            None,
            Some(&nonce_sum),
        ).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig2:\t\t{:?}", sig2);

        // sig2.s*G-e*P2 = k2*G+e*p2*G-e*P2 = R2,   check R2.x == sig2.r ?
        let result = verify_single(&secp, &sig2, &msg, Some(&nonce_sum), &pk2, None, None, true);
        if true == result {
            println!("sig2 signature check:\tOK");
        } else {
            println!("sig2 signature check:\tNOK");
        }

        //--- sig3

        println!("\n--- sig3 ---");

        let (sk3, pk3) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk3, sk3);

        // e=hash(R.x, m)    s=k3+e*p3    sig3=(s,r3)
        let sig3 = sign_single(
            &secp,
            &msg,
            &sk3,
            Some(&secnonce_3),
            None,
            Some(&nonce_sum),
            None,
            Some(&nonce_sum),
        ).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig3:\t\t{:?}", sig3);

        // sig3.s*G-e*P3 = k3*G+e*p3*G-e*P3 = R3,   check R3.x == sig3.r ?
        let result = verify_single(&secp, &sig3, &msg, Some(&nonce_sum), &pk3, None, None, true);
        if true == result {
            println!("sig3 signature check:\tOK");
        } else {
            println!("sig3 signature check:\tNOK");
        }

        //--- Batch Verification

        println!("\n--- Batch Verification ---");

        let sig_vec = vec![&sig1, &sig2, &sig3];
        let combined_sig = add_signatures_single(&secp, sig_vec, &nonce_sum).unwrap();

        // Sum public keys: P = P1+P2+P3
        let pk_sum = PublicKey::from_combination(&secp, vec![&pk1, &pk2, &pk3]).unwrap();

        println!(
            "\nCombined sig:\t{:?}\n\tmsg:\t{:?}\n\tpk_sum:\t{:?}",
            combined_sig, msg, pk_sum
        );
        // sig.s*G-e*P = k*G+e*p*G-e*P = R,   check R.x == sig.r ?
        let result = verify_single(
            &secp,
            &combined_sig,
            &msg,
            Some(&nonce_sum),
            &pk_sum,
            None,
            None,
            false,
        );
        if true == result {
            println!("\nSignature Batch Verification:\tOK");
        } else {
            println!("\nSignature Batch Verification:\tNOK");
        }
    }

    #[test]
    fn demo_aggsig_batch_fail_verify() {
        /*
         * Signature Aggregation (Batch Verification):
         * All the signatures in the block can be removed and only keep an aggregated one.
         * Signature aggregation can be done by a miner and save a lot of space in the block.
         */

        let secp = Secp256k1::with_caps(ContextFlag::Full);

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        //--- Generate nonce: k1,k2,k3
        let secnonce_1 = export_secnonce_single(&secp).unwrap();
        let secnonce_2 = export_secnonce_single(&secp).unwrap();
        let secnonce_3 = export_secnonce_single(&secp).unwrap();

        //--- Calculate public nonce: R1,R2,R3
        let pubnonce_1 = PublicKey::from_secret_key(&secp, &secnonce_1).unwrap();
        let pubnonce_2 = PublicKey::from_secret_key(&secp, &secnonce_2).unwrap();
        let pubnonce_3 = PublicKey::from_secret_key(&secp, &secnonce_3).unwrap();

        //--- And sum public nonce: R = R1+R2+R3
        let nonce_sum =
            PublicKey::from_combination(&secp, vec![&pubnonce_1, &pubnonce_2, &pubnonce_3])
                .unwrap();

        //--- sig1
        println!("\n--- sig1 ---");

        let (sk1, pk1) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk1, sk1);

        // e=hash(R.x, m)    s=k1+e*p1    sig1=(s,r1)
        let sig1 =
            sign_single(&secp, &msg, &sk1, Some(&secnonce_1), None, None, None, None).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig1:\t\t{:?}", sig1);

        // sig1.s*G-e*P1 = k1*G+e*p1*G-e*P1 = R1,   check R1.x == sig1.r ?
        let result = verify_single(&secp, &sig1, &msg, None, &pk1, None, None, false);
        if true == result {
            println!("sig1 signature check:\tOK");
        } else {
            println!("sig1 signature check:\tNOK");
        }

        //--- sig2

        println!("\n--- sig2 ---");

        let (sk2, pk2) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk2, sk2);

        // e=hash(R.x, m)    s=k2+e*p2    sig2=(s,r2)
        let sig2 =
            sign_single(&secp, &msg, &sk2, Some(&secnonce_2), None, None, None, None).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig2:\t\t{:?}", sig2);

        // sig2.s*G-e*P2 = k2*G+e*p2*G-e*P2 = R2,   check R2.x == sig2.r ?
        let result = verify_single(&secp, &sig2, &msg, None, &pk2, None, None, false);
        if true == result {
            println!("sig2 signature check:\tOK");
        } else {
            println!("sig2 signature check:\tNOK");
        }

        //--- sig3

        println!("\n--- sig3 ---");

        let (sk3, pk3) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk3, sk3);

        // e=hash(R.x, m)    s=k3+e*p3    sig3=(s,r3)
        let sig3 =
            sign_single(&secp, &msg, &sk3, Some(&secnonce_3), None, None, None, None).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig3:\t\t{:?}", sig3);

        // sig3.s*G-e*P3 = k3*G+e*p3*G-e*P3 = R3,   check R3.x == sig3.r ?
        let result = verify_single(&secp, &sig3, &msg, None, &pk3, None, None, false);
        if true == result {
            println!("sig3 signature check:\tOK");
        } else {
            println!("sig3 signature check:\tNOK");
        }

        //--- Batch Verification

        println!("\n--- Batch Verification ---");

        // e1=hash(R1.x, m)    s1=k1+e1*p1    sig1=(s1,R1.x)
        // e2=hash(R2.x, m)    s2=k2+e2*p2    sig2=(s2,R2.x)
        // e3=hash(R3.x, m)    s3=k3+e3*p3    sig3=(s3,R3.x)
        // s=s1+s2+s3 = (k1+k2+k3)+(e1*p1+e2*p2+e3*p3),     R.x = (R1+R2+R3).x
        //
        let sig_vec = vec![&sig1, &sig2, &sig3];
        let combined_sig = add_signatures_single(&secp, sig_vec, &nonce_sum).unwrap();

        // Sum public keys: P = P1+P2+P3
        let pk_sum = PublicKey::from_combination(&secp, vec![&pk1, &pk2, &pk3]).unwrap();

        println!(
            "\nCombined sig:\t{:?}\n\tmsg:\t{:?}\n\tpk_sum:\t{:?}",
            combined_sig, msg, pk_sum
        );
        // sig = (s,R.x) = (s1+s2+s3, R.x)
        //   e = hash(R.x, m)
        //
        // sig.s*G-e*P
        // = (k1+k2+k3)*G+(e1*p1+e2*p2+e3*p3)*G - e*P
        // = R + e1*P1+e2*P2+e3*P3 - e*P
        // = R + hash(R1.x, m)*P1 + hash(R2.x, m)*P2 + hash(R3.x, m)*P3 - hash(R.x, m)*P
        //
        // Because hash() is not a linear function, above equation not equal to R
        // This signature will definitely fail
        let result = verify_single(
            &secp,
            &combined_sig,
            &msg,
            Some(&nonce_sum),
            &pk_sum,
            None,
            None,
            false,
        );
        if true == result {
            println!("\nSignature Batch Verification:\tOK");
        } else {
            println!("\nSignature Batch Verification:\tNOK");
        }
    }

    /// Construct msg bytes from tx fee and lock_height
    pub fn kernel_sig_msg(fee: u64, lock_height: u64) -> [u8; 32] {
        let mut bytes = [0; 32];

        //--- Big Endian
        for i in 16..24 {
            let k = (i % 8) as u32;
            bytes[i] = (fee >> k) as u8;
        }
        for i in 24..32 {
            let k = (i % 8) as u32;
            bytes[i] = (lock_height >> k) as u8;
        }
        bytes
    }

    #[test]
    #[allow(non_snake_case)]
    fn demo_mutual_procedure() {
        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        println!("\nCT Mutual Procedure: Round 1 (on sender side)");

        let sender_sk; // private key of sender
        let sender_kS; // secretnonce of sender

        let (input, change_output, fee, amount, lock_height, kSG, xSG, oS) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            let in_amount: u64 = 10 * 1_000_000_000;
            let out_amount: u64 = 8 * 1_000_000_000;

            //--- step 2. Set lock_height for transaction kernel (current chain height)
            let lock_height: u64 = 10_000; // just for example

            //--- step 3. Select inputs using desired selection strategy
            //simulate an UTXO as the input
            let blinding_input = SecretKey::new(&secp, &mut thread_rng());
            let input = commit(in_amount, blinding_input);

            //--- step 7. Skipped.
            //--- step 8. Calculate fee: tx_weight * 1_000_000 nG
            let fee: u64 = 8 * 1_000_000;

            //--- step 4. Create change_output
            //--- step 5. Select blinding factor for change_output
            let blinding_change_output = SecretKey::new(&secp, &mut thread_rng());
            let change_output = commit(in_amount - out_amount - fee, blinding_change_output);

            //--- step 9. Calculate total blinding excess sum xS1 (private scalar), for all inputs(-) and outputs(+)
            let xS1 = secp
                .blind_sum(vec![blinding_change_output], vec![blinding_input])
                .unwrap();

            //--- step 10. Select a random nonce kS (private scalar)
            let kS = SecretKey::new(&secp, &mut thread_rng());

            //--- step 11. Subtract random value oS (kernel offset) from xS1. Calculate xS = xS1 - oS
            let oS = SecretKey::new(&secp, &mut thread_rng());
            let xS = secp.blind_sum(vec![xS1], vec![oS]).unwrap();

            sender_sk = xS; // save for final round
            sender_kS = kS; // save for final round

            //--- step 12. Multiply xS and kS by generator G to create public curve points xSG and kSG
            let xSG = PublicKey::from_secret_key(&secp, &xS).unwrap();
            let kSG = PublicKey::from_secret_key(&secp, &kS).unwrap();

            //--- step 13. Add values to Slate for passing to other participants: UUID, inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS
            (
                input,
                change_output,
                fee,
                out_amount,
                lock_height,
                kSG,
                xSG,
                oS,
            )
        };

        println!("\nCT Mutual Procedure: Round 1 Done. Sender post to Receiver: inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS");

        println!("\nCT Mutual Procedure: Round 2 (on receiver side)");

        let (sR, xRG, kRG, receiver_output) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- step 1. Check fee against number of inputs, change_outputs +1 * receiver_output)
            //skipped.

            //--- step 2. Create receiver_output
            //--- step 3. Choose random blinding factor for receiver_output xR (private scalar)
            let xR = SecretKey::new(&secp, &mut thread_rng());
            let output = commit(amount, xR);

            //--- step 4. Calculate message M = fee | lock_height
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();

            //--- step 5. Choose random nonce kR (private scalar)
            let kR = SecretKey::new(&secp, &mut thread_rng());

            //--- step 6. Multiply xR and kR by generator G to create public curve points xRG and kRG
            let xRG = PublicKey::from_secret_key(&secp, &xR).unwrap();
            let kRG = PublicKey::from_secret_key(&secp, &kR).unwrap();

            let xG = PublicKey::from_combination(&secp, vec![&xRG, &xSG]).unwrap();
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            if true == secp.verify_commit_sum(
                vec![
                    output,
                    change_output,
                    commit(fee, secp.blind_sum(vec![], vec![oS]).unwrap()),
                ],
                vec![input, excess_commit],
            ) {
                println!("\ntotal sum balance OK:\toutput + change_output + (-offset*G + fee*H) = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output + (-offset*G + fee*H) != input + excess");
            }

            //--- step 7. Compute Schnorr challenge e = SHA256(M | kRG + kSG)
            //--- step 8. Compute Recipient Schnorr signature sR = kR + e * xR
            let nonce_sum = PublicKey::from_combination(&secp, vec![&kRG, &kSG]).unwrap();
            let sR = sign_single(
                &secp,
                &msg,
                &xR,
                Some(&kR),
                None,
                Some(&nonce_sum),
                None,
                Some(&nonce_sum),
            ).unwrap();

            //--- step 9. Add sR, xRG, kRG to Slate
            //--- step 10. Create wallet output function rF that stores receiver_output in wallet
            //             with status "Unconfirmed" and identifying transaction log entry TR linking
            //             receiver_output with transaction.

            (sR, xRG, kRG, output)
        };

        println!("\nCT Mutual Procedure: Round 2 Done. Receiver post to Sender: sR, xRG, kRG, receiver_output");

        println!("\nCT Mutual Procedure: Final Round (on sender side)");

        let (s, excess_commit, fee, lock_height, oS) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- step 1. Calculate message M = fee | lock_height
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();

            //--- step 2. Compute Schnorr challenge e = SHA256(M | kRG + kSG)
            //--- step 3. Verify sR by verifying kRG = sRG - e * xRG
            let nonce_sum = PublicKey::from_combination(&secp, vec![&kRG, &kSG]).unwrap();
            let result = verify_single(&secp, &sR, &msg, Some(&nonce_sum), &xRG, None, None, true);
            if true == result {
                println!("Signature 'sR' Verification:\tOK");
            } else {
                println!("Signature 'sR' Verification:\tNOK");
            }

            //--- step 4. Compute Sender Schnorr signature sS = kS + e * xS
            let xS = sender_sk; // load sender's private key , which is saved in 1st round
            let kS = sender_kS; // load sender's secret nonce, which is saved in 1st round
            let sS = sign_single(
                &secp,
                &msg,
                &xS,
                Some(&kS),
                None,
                Some(&nonce_sum),
                None,
                Some(&nonce_sum),
            ).unwrap();

            //--- step 5. Calculate final signature s = (sS+sR, kSG+kRG)
            let sig_vec = vec![&sR, &sS];
            let s = add_signatures_single(&secp, sig_vec, &nonce_sum).unwrap();

            //--- step 6. Calculate public key for s: xG = xRG + xSG
            let xG = PublicKey::from_combination(&secp, vec![&xRG, &xSG]).unwrap();
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            if true == secp.verify_commit_sum(
                vec![
                    receiver_output,
                    change_output,
                    commit(fee, secp.blind_sum(vec![], vec![oS]).unwrap()),
                ],
                vec![input, excess_commit],
            ) {
                println!("\ntotal sum balance OK:\toutput + change_output + (-offset*G + fee*H) = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output + (-offset*G + fee*H) != input + excess");
            }

            //--- step 7. Verify s against excess values in final transaction using xG
            let result = verify_single(&secp, &s, &msg, None, &xG, None, None, false);
            if true == result {
                println!("Signature 's' Verification:\tOK");
            } else {
                println!("Signature 's' Verification:\tNOK");
            }

            //--- step 8. Create Transaction Kernel Containing:
            //            Signature: s, Public key: xG, fee, lock_height, excess value: oS
            (s, excess_commit, fee, lock_height, oS)
        };

        println!("\nCT Mutual Procedure: Final Round Done. Sender post to mempool: s, 'public excess', fee, lock_height, oS, and input,outputs");

        println!(
            "\ns:\t\t{:?}\nxG 2 commit:\t{:?}\nfee:\t\t{:?}\nlock_height:\t{:?}\noS:\t\t{:?}\n",
            s, excess_commit, fee, lock_height, oS
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn simulate_public_output() {
        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        println!("\nCT Mutual Procedure: Round 1 (on sender side)");

        let sender_sk; // private key of sender
        let sender_kS; // secretnonce of sender

        let (input, change_output, fee, amount, lock_height, kSG, xSG, oS) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            let in_amount: u64 = 10 * 1_000_000_000;
            let out_amount: u64 = 8 * 1_000_000_000;

            //--- step 2. Set lock_height for transaction kernel (current chain height)
            let lock_height: u64 = 10_000; // just for example

            //--- step 3. Select inputs using desired selection strategy
            //simulate an UTXO as the input
            let blinding_input = SecretKey::new(&secp, &mut thread_rng());
            let input = commit(in_amount, blinding_input);

            //--- step 7. Skipped.
            //--- step 8. Calculate fee: tx_weight * 1_000_000 nG
            let fee: u64 = 8 * 1_000_000;

            //--- step 4. Create change_output
            //--- step 5. Select blinding factor for change_output
            let blinding_change_output = SecretKey::new(&secp, &mut thread_rng());
            let change_output = commit(in_amount - out_amount - fee, blinding_change_output);

            //--- step 9. Calculate total blinding excess sum xS1 (private scalar), for all inputs(-) and outputs(+)
            let xS1 = secp
                .blind_sum(vec![blinding_change_output], vec![blinding_input])
                .unwrap();

            //--- step 10. Select a random nonce kS (private scalar)
            let kS = SecretKey::new(&secp, &mut thread_rng());

            //--- step 11. Subtract random value oS (kernel offset) from xS1. Calculate xS = xS1 - oS
            let oS = SecretKey::new(&secp, &mut thread_rng());
            let xS = secp.blind_sum(vec![xS1], vec![oS]).unwrap();

            sender_sk = xS; // save for final round
            sender_kS = kS; // save for final round

            //--- step 12. Multiply xS and kS by generator G to create public curve points xSG and kSG
            let xSG = PublicKey::from_secret_key(&secp, &xS).unwrap();
            let kSG = PublicKey::from_secret_key(&secp, &kS).unwrap();

            //--- step 13. Add values to Slate for passing to other participants: UUID, inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS
            (
                input,
                change_output,
                fee,
                out_amount,
                lock_height,
                kSG,
                xSG,
                oS,
            )
        };

        println!("\nCT Mutual Procedure: Round 1 Done. Sender post to Receiver: inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS");

        println!("\nCT Mutual Procedure: Round 2 (on receiver side)");

        let (sR, xRG, kRG, receiver_output) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- step 1. Check fee against number of inputs, change_outputs +1 * receiver_output)
            //skipped.

            //--- step 2. Create receiver_output
            //--- step 3. Choose random blinding factor for receiver_output xR (private scalar)
            let xR = SecretKey::new(&secp, &mut thread_rng());
            let output = commit(0, xR);

            //--- step 4. Calculate message M = fee | lock_height
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();

            //--- step 5. Choose random nonce kR (private scalar)
            let kR = SecretKey::new(&secp, &mut thread_rng());

            //--- step 6. Multiply xR and kR by generator G to create public curve points xRG and kRG
            let xRG = PublicKey::from_secret_key(&secp, &xR).unwrap();
            let kRG = PublicKey::from_secret_key(&secp, &kR).unwrap();

            let xG = PublicKey::from_combination(&secp, vec![&xRG, &xSG]).unwrap();
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            if true == secp.verify_commit_sum(
                vec![
                    output,
                    change_output,
                    commit(amount + fee, secp.blind_sum(vec![], vec![oS]).unwrap()),
                ],
                vec![input, excess_commit],
            ) {
                println!("\ntotal sum balance OK:\toutput + change_output + (-offset*G + (amount+fee)*H) = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output + (-offset*G + (amount+fee)*H) != input + excess");
            }

            //--- step 7. Compute Schnorr challenge e = SHA256(M | kRG + kSG)
            //--- step 8. Compute Recipient Schnorr signature sR = kR + e * xR
            let nonce_sum = PublicKey::from_combination(&secp, vec![&kRG, &kSG]).unwrap();
            let sR = sign_single(
                &secp,
                &msg,
                &xR,
                Some(&kR),
                None,
                Some(&nonce_sum),
                None,
                Some(&nonce_sum),
            ).unwrap();

            //--- step 9. Add sR, xRG, kRG to Slate
            //--- step 10. Create wallet output function rF that stores receiver_output in wallet
            //             with status "Unconfirmed" and identifying transaction log entry TR linking
            //             receiver_output with transaction.

            (sR, xRG, kRG, output)
        };

        println!("\nCT Mutual Procedure: Round 2 Done. Receiver post to Sender: sR, xRG, kRG, receiver_output");

        println!("\nCT Mutual Procedure: Final Round (on sender side)");

        let (s, _excess_commit, fee, lock_height, oS) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- step 1. Calculate message M = fee | lock_height
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();

            //--- step 2. Compute Schnorr challenge e = SHA256(M | kRG + kSG)
            //--- step 3. Verify sR by verifying kRG = sRG - e * xRG
            let nonce_sum = PublicKey::from_combination(&secp, vec![&kRG, &kSG]).unwrap();
            let result = verify_single(&secp, &sR, &msg, Some(&nonce_sum), &xRG, None, None, true);
            if true == result {
                println!("Signature 'sR' Verification:\tOK");
            } else {
                println!("Signature 'sR' Verification:\tNOK");
            }

            //--- step 4. Compute Sender Schnorr signature sS = kS + e * xS
            let xS = sender_sk; // load sender's private key , which is saved in 1st round
            let kS = sender_kS; // load sender's secret nonce, which is saved in 1st round
            let sS = sign_single(
                &secp,
                &msg,
                &xS,
                Some(&kS),
                None,
                Some(&nonce_sum),
                None,
                Some(&nonce_sum),
            ).unwrap();

            //--- step 5. Calculate final signature s = (sS+sR, kSG+kRG)
            let sig_vec = vec![&sR, &sS];
            let s = add_signatures_single(&secp, sig_vec, &nonce_sum).unwrap();

            //--- step 6. Calculate public key for s: xG = xRG + xSG
            let xG = PublicKey::from_combination(&secp, vec![&xRG, &xSG]).unwrap();
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            if true == secp.verify_commit_sum(
                vec![
                    receiver_output,
                    change_output,
                    commit(amount + fee, secp.blind_sum(vec![], vec![oS]).unwrap()),
                ],
                vec![input, excess_commit],
            ) {
                println!("\ntotal sum balance OK:\toutput + change_output + (-offset*G + (amount+fee)*H) = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output + (-offset*G + (amount+fee)*H) != input + excess");
            }

            //--- step 7. Verify s against excess values in final transaction using xG
            let result = verify_single(&secp, &s, &msg, None, &xG, None, None, false);
            if true == result {
                println!("Signature 's' Verification:\tOK");
            } else {
                println!("Signature 's' Verification:\tNOK");
            }

            //--- step 8. Create Transaction Kernel Containing:
            //            Signature: s, Public key: xG, fee, lock_height, excess value: oS
            (s, excess_commit, fee, lock_height, oS)
        };

        println!("\nCT Mutual Procedure: Final Round Done. Sender post to mempool: s, 'public excess', fee, lock_height, oS, and input,outputs");

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        println!("\ns:\t\t{:?}\nxSG 2 commit:\t{:?}\nxRG 2 commit:\t{:?}\nfee:\t\t{:?}\nlock_height:\t{:?}\noS:\t\t{:?}\n",
                 s,
                 Commitment::from_pubkey(&secp, &xSG).unwrap(),
                 Commitment::from_pubkey(&secp, &xRG).unwrap(),
                 fee, lock_height, oS);

        println!(
            "\nReceiver Output Commit:\t{:?}\nValue:\t{:?}",
            receiver_output, amount
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn simulate_public_transaction() {
        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        println!("\nPT Mutual Procedure: Round 1 (on sender side)");

        let sender_sk; // private key of sender
        let sender_kS; // secretnonce of sender
        let sender_xSG1;

        let (
            input,
            change_output,
            fee,
            in_amount,
            out_amount,
            change_amount,
            lock_height,
            kSG,
            xSG,
            oS,
        ) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            let in_amount: u64 = 10 * 1_000_000_000;
            let out_amount: u64 = 8 * 1_000_000_000;

            //--- step 2. Set lock_height for transaction kernel (current chain height)
            let lock_height: u64 = 10_000; // just for example

            //--- step 3. Select inputs using desired selection strategy
            //simulate an UTXO as the input
            let blinding_input = SecretKey::new(&secp, &mut thread_rng());
            let input = commit(0, blinding_input);

            //--- step 7. Skipped.
            //--- step 8. Calculate fee: tx_weight * 1_000_000 nG
            let fee: u64 = 8 * 1_000_000;

            //--- step 4. Create change_output
            //--- step 5. Select blinding factor for change_output
            let blinding_change_output = SecretKey::new(&secp, &mut thread_rng());
            let change_output = commit(0, blinding_change_output);

            //--- step 9. Calculate total blinding excess sum xS1 (private scalar), for all inputs(-) and outputs(+)
            let xS1 = secp
                .blind_sum(vec![blinding_change_output], vec![blinding_input])
                .unwrap();

            //--- step 10. Select a random nonce kS (private scalar)
            let kS = SecretKey::new(&secp, &mut thread_rng());

            //--- step 11. Subtract random value oS (kernel offset) from xS1. Calculate xS = xS1 - oS
            let oS = SecretKey::new(&secp, &mut thread_rng());
            let xS = secp.blind_sum(vec![xS1], vec![oS]).unwrap();

            sender_sk = xS; // save for final round
            sender_kS = kS; // save for final round

            //--- step 12. Multiply xS and kS by generator G to create public curve points xSG and kSG
            let xSG = PublicKey::from_secret_key(&secp, &xS).unwrap();
            let kSG = PublicKey::from_secret_key(&secp, &kS).unwrap();

            let xSG1 = PublicKey::from_secret_key(
                &secp,
                &secp.blind_sum(vec![], vec![blinding_input, oS]).unwrap(),
            ).unwrap();
            sender_xSG1 = xSG1;

            //--- step 13. Add values to Slate for passing to other participants: UUID, inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS
            (
                input,
                change_output,
                fee,
                in_amount,
                out_amount,
                in_amount - out_amount - fee,
                lock_height,
                kSG,
                xSG,
                oS,
            )
        };

        println!("\nPT Mutual Procedure: Round 1 Done. Sender post to Receiver: inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS");

        println!("\nPT Mutual Procedure: Round 2 (on receiver side)");

        let (sR, xRG, kRG, receiver_output) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- step 1. Check fee against number of inputs, change_outputs +1 * receiver_output)
            //skipped.

            //--- step 2. Create receiver_output
            //--- step 3. Choose random blinding factor for receiver_output xR (private scalar)
            let xR = SecretKey::new(&secp, &mut thread_rng());
            let output = commit(0, xR);

            //--- step 4. Calculate message M = fee | lock_height
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();

            //--- step 5. Choose random nonce kR (private scalar)
            let kR = SecretKey::new(&secp, &mut thread_rng());

            //--- step 6. Multiply xR and kR by generator G to create public curve points xRG and kRG
            let xRG = PublicKey::from_secret_key(&secp, &xR).unwrap();
            let kRG = PublicKey::from_secret_key(&secp, &kR).unwrap();

            let xG = PublicKey::from_combination(&secp, vec![&xRG, &xSG]).unwrap();
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            if true == secp.verify_commit_sum(
                vec![output, change_output],
                vec![
                    input,
                    excess_commit,
                    commit(
                        in_amount - out_amount - change_amount - fee,
                        secp.blind_sum(vec![oS], vec![]).unwrap(),
                    ),
                ],
            ) {
                println!("\ntotal sum balance OK:\toutput + change_output = input + excess - (offset*G + (in_amount-out_amount-change_amount-fee)*H)");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output != input + excess - (offset*G + (in_amount-out_amount-change_amount-fee)*H)");
            }

            //--- step 7. Compute Schnorr challenge e = SHA256(M | kRG + kSG)
            //--- step 8. Compute Recipient Schnorr signature sR = kR + e * xR
            let nonce_sum = PublicKey::from_combination(&secp, vec![&kRG, &kSG]).unwrap();
            let sR = sign_single(
                &secp,
                &msg,
                &xR,
                Some(&kR),
                None,
                Some(&nonce_sum),
                None,
                Some(&nonce_sum),
            ).unwrap();

            //--- step 9. Add sR, xRG, kRG to Slate
            //--- step 10. Create wallet output function rF that stores receiver_output in wallet
            //             with status "Unconfirmed" and identifying transaction log entry TR linking
            //             receiver_output with transaction.

            (sR, xRG, kRG, output)
        };

        println!("\nPT Mutual Procedure: Round 2 Done. Receiver post to Sender: sR, xRG, kRG, receiver_output");

        println!("\nPT Mutual Procedure: Final Round (on sender side)");

        let (s, xSG1, fee, lock_height, oS) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- step 1. Calculate message M = fee | lock_height
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();

            //--- step 2. Compute Schnorr challenge e = SHA256(M | kRG + kSG)
            //--- step 3. Verify sR by verifying kRG = sRG - e * xRG
            let nonce_sum = PublicKey::from_combination(&secp, vec![&kRG, &kSG]).unwrap();
            let result = verify_single(&secp, &sR, &msg, Some(&nonce_sum), &xRG, None, None, true);
            if true == result {
                println!("Signature 'sR' Verification:\tOK");
            } else {
                println!("Signature 'sR' Verification:\tNOK");
            }

            //--- step 4. Compute Sender Schnorr signature sS = kS + e * xS
            let xS = sender_sk; // load sender's private key , which is saved in 1st round
            let kS = sender_kS; // load sender's secret nonce, which is saved in 1st round
            let sS = sign_single(
                &secp,
                &msg,
                &xS,
                Some(&kS),
                None,
                Some(&nonce_sum),
                None,
                Some(&nonce_sum),
            ).unwrap();

            //--- step 5. Calculate final signature s = (sS+sR, kSG+kRG)
            let sig_vec = vec![&sR, &sS];
            let s = add_signatures_single(&secp, sig_vec, &nonce_sum).unwrap();

            //--- step 6. Calculate public key for s: xG = xRG + xSG
            let xSG1 = sender_xSG1; // load
            let xG = PublicKey::from_combination(
                &secp,
                vec![&xRG, &xSG1, &change_output.to_pubkey(&secp).unwrap()],
            ).unwrap();
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            if true == secp.verify_commit_sum(
                vec![receiver_output, change_output],
                vec![
                    input,
                    excess_commit,
                    commit(
                        in_amount - out_amount - change_amount - fee,
                        secp.blind_sum(vec![oS], vec![]).unwrap(),
                    ),
                ],
            ) {
                println!("\ntotal sum balance OK:\toutput + change_output = input + excess - (offset*G + (in_amount-out_amount-change_amount-fee)*H)");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output != input + excess - (offset*G + (in_amount-out_amount-change_amount-fee)*H)");
            }

            //--- step 7. Verify s against excess values in final transaction using xG
            let result = verify_single(&secp, &s, &msg, None, &xG, None, None, false);
            if true == result {
                println!("Signature 's' Verification:\tOK");
            } else {
                println!("Signature 's' Verification:\tNOK");
            }

            //--- step 8. Create Transaction Kernel Containing:
            //            Signature: s, Public key: xG, fee, lock_height, excess value: oS
            (s, xSG1, fee, lock_height, oS)
        };

        println!("\nPT Mutual Procedure: Final Round Done. Sender post to mempool: s, xSG1, fee, lock_height, oS, and input,outputs");

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        println!("\ns:\t\t{:?}\nxSG1 2 commit:\t{:?}\nchange commit:\t{:?}\nxRG 2 commit:\t{:?}\nfee:\t\t{:?}\nlock_height:\t{:?}\noS:\t\t{:?}\n",
                 s,
                 Commitment::from_pubkey(&secp, &xSG1).unwrap(),
                 change_output,
                 Commitment::from_pubkey(&secp, &xRG).unwrap(),
                 fee, lock_height, oS);

        println!(
            "\nReceiver Output Commit:\t{:?}\nValue:\t{:?}",
            receiver_output, out_amount
        );
        println!(
            "\nChange Output Commit:\t{:?}\nValue:\t{:?}",
            change_output, change_amount
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn simple_public_transaction() {
        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        println!("\nPT Mutual Procedure: Round 1 (on sender side)");

        let sender_sk; // private key of sender
        let sender_kS; // secretnonce of sender

        let (
            input,
            change_output,
            fee,
            in_amount,
            out_amount,
            change_amount,
            lock_height,
            kSG,
            xSG,
        ) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            let in_amount: u64 = 10 * 1_000_000_000;
            let out_amount: u64 = 8 * 1_000_000_000;

            //--- step 2. Set lock_height for transaction kernel (current chain height)
            let lock_height: u64 = 10_000; // just for example

            //--- step 3. Select inputs using desired selection strategy
            //simulate an UTXO as the input
            let blinding_input = SecretKey::new(&secp, &mut thread_rng());
            let input = commit(0, blinding_input);

            //--- step 7. Skipped.
            //--- step 8. Calculate fee: tx_weight * 1_000_000 nG
            let fee: u64 = 8 * 1_000_000;

            //--- step 4. Create change_output
            //--- step 5. Select blinding factor for change_output
            let blinding_change_output = SecretKey::new(&secp, &mut thread_rng());
            let change_output = commit(0, blinding_change_output);

            //--- step 9. Calculate total blinding excess sum xS (private scalar), for all inputs(-) and outputs(+)
            let xS = secp
                .blind_sum(vec![blinding_change_output], vec![blinding_input])
                .unwrap();

            //--- step 10. Select a random nonce kS (private scalar)
            let kS = SecretKey::new(&secp, &mut thread_rng());

            sender_sk = xS; // save for final round
            sender_kS = kS; // save for final round

            //--- step 12. Multiply xS and kS by generator G to create public curve points xSG and kSG
            let xSG = PublicKey::from_secret_key(&secp, &xS).unwrap();
            let kSG = PublicKey::from_secret_key(&secp, &kS).unwrap();

            //--- step 13. Add values to Slate for passing to other participants: UUID, inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS
            (
                input,
                change_output,
                fee,
                in_amount,
                out_amount,
                in_amount - out_amount - fee,
                lock_height,
                kSG,
                xSG,
            )
        };

        println!("\nPT Mutual Procedure: Round 1 Done. Sender post to Receiver: inputs, change_outputs, fee, amount, lock_height, kSG, xSG");

        println!("\nPT Mutual Procedure: Round 2 (on receiver side)");

        let (sR, xRG, kRG, receiver_output) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- step 1. Check fee against number of inputs, change_outputs +1 * receiver_output)
            //skipped.

            //--- step 2. Create receiver_output
            //--- step 3. Choose random blinding factor for receiver_output xR (private scalar)
            let xR = SecretKey::new(&secp, &mut thread_rng());
            let output = commit(0, xR);

            //--- step 4. Calculate message M = fee | lock_height
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();

            //--- step 5. Choose random nonce kR (private scalar)
            let kR = SecretKey::new(&secp, &mut thread_rng());

            //--- step 6. Multiply xR and kR by generator G to create public curve points xRG and kRG
            let xRG = PublicKey::from_secret_key(&secp, &xR).unwrap();
            let kRG = PublicKey::from_secret_key(&secp, &kR).unwrap();

            let xG = PublicKey::from_combination(&secp, vec![&xRG, &xSG]).unwrap();
            let excess = Commitment::from_pubkey(&secp, &xG).unwrap();
            let balance = in_amount - out_amount - change_amount - fee;
            if balance == 0
                && secp.verify_commit_sum(vec![output, change_output], vec![input, excess])
            {
                println!("\ntotal sum balance OK:\toutput + change_output = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output != input + excess");
            }

            //--- step 7. Compute Schnorr challenge e = SHA256(M | kRG + kSG)
            //--- step 8. Compute Recipient Schnorr signature sR = kR + e * xR
            let nonce_sum = PublicKey::from_combination(&secp, vec![&kRG, &kSG]).unwrap();
            let sR = sign_single(
                &secp,
                &msg,
                &xR,
                Some(&kR),
                None,
                Some(&nonce_sum),
                None,
                Some(&nonce_sum),
            ).unwrap();

            //--- step 9. Add sR, xRG, kRG to Slate
            //--- step 10. Create wallet output function rF that stores receiver_output in wallet
            //             with status "Unconfirmed" and identifying transaction log entry TR linking
            //             receiver_output with transaction.

            (sR, xRG, kRG, output)
        };

        println!("\nPT Mutual Procedure: Round 2 Done. Receiver post to Sender: sR, xRG, kRG, receiver_output");

        println!("\nPT Mutual Procedure: Final Round (on sender side)");

        let (s, excess, fee, lock_height) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- step 1. Calculate message M = fee | lock_height
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();

            //--- step 2. Compute Schnorr challenge e = SHA256(M | kRG + kSG)
            //--- step 3. Verify sR by verifying kRG = sRG - e * xRG
            let nonce_sum = PublicKey::from_combination(&secp, vec![&kRG, &kSG]).unwrap();
            let result = verify_single(&secp, &sR, &msg, Some(&nonce_sum), &xRG, None, None, true);
            if true == result {
                println!("Signature 'sR' Verification:\tOK");
            } else {
                println!("Signature 'sR' Verification:\tNOK");
            }

            //--- step 4. Compute Sender Schnorr signature sS = kS + e * xS
            let xS = sender_sk; // load sender's private key , which is saved in 1st round
            let kS = sender_kS; // load sender's secret nonce, which is saved in 1st round
            let sS = sign_single(
                &secp,
                &msg,
                &xS,
                Some(&kS),
                None,
                Some(&nonce_sum),
                None,
                Some(&nonce_sum),
            ).unwrap();

            //--- step 5. Calculate final signature s = (sS+sR, kSG+kRG)
            let sig_vec = vec![&sR, &sS];
            let s = add_signatures_single(&secp, sig_vec, &nonce_sum).unwrap();

            //--- step 6. Calculate public key for s: xG = xRG + xSG
            let xG = PublicKey::from_combination(&secp, vec![&xRG, &xSG]).unwrap();
            let excess = Commitment::from_pubkey(&secp, &xG).unwrap();
            let balance = in_amount - out_amount - change_amount - fee;
            if balance == 0
                && secp.verify_commit_sum(vec![receiver_output, change_output], vec![input, excess])
            {
                println!("\ntotal sum balance OK:\toutput + change_output = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output != input + excess");
            }

            //--- step 7. Verify s against excess values in final transaction using xG
            let result = verify_single(&secp, &s, &msg, None, &xG, None, None, false);
            if true == result {
                println!("Signature 's' Verification:\tOK");
            } else {
                println!("Signature 's' Verification:\tNOK");
            }

            //--- step 8. Create Transaction Kernel Containing:
            //            Signature: s, Public key: excess, fee, lock_height
            (s, excess, fee, lock_height)
        };

        println!("\nPT Mutual Procedure: Final Round Done. Sender post to mempool: s, excess, fee, lock_height, and input,outputs");

        println!(
            "\ns:\t\t{:?}\nexcess:\t{:?}\nfee:\t\t{:?}\nlock_height:\t{:?}\n",
            s, excess, fee, lock_height
        );

        println!("\nInput Commit:\t{:?}\nValue:\t{:?}", input, in_amount);
        println!(
            "\nReceiver Output Commit:\t{:?}\nValue:\t{:?}",
            receiver_output, out_amount
        );
        println!(
            "\nChange Output Commit:\t{:?}\nValue:\t{:?}",
            change_output, change_amount
        );
    }

    // note: this is a wrong design of non-interactive transaction, because signature MUST use public
    // excess as the public key, otherwise anyone can create such kind of transaction for any input.
    #[ignore]
    #[test]
    #[allow(non_snake_case)]
    fn mis_demo_non_interactive_tx() {
        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }
        fn tx_commit(value: u64, blinding: &SecretKey, receiver_pk: &PublicKey, msg: &Message) -> (Commitment,SecretKey) {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.tx_commit(value, blinding, receiver_pk, msg).unwrap()
        }

        // Receiver has well known public key P
        let (recipient_pk, recipient_sk) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);
            let p = SecretKey::new(&secp, &mut thread_rng());
            let P = PublicKey::from_secret_key(&secp, &p).unwrap();
            (P,p)
        };
        println!("\nCT Non-Interactive Tx Procedure: Recipient Public Key: {:?}", recipient_pk);

        println!("\nCT Non-Interactive Tx Procedure: Sending Tx (on sender side)");

        let sender_sk; // private key of sender

        let (input, change_output, amount, output, sender_pk, sS, msg, excess) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            let in_amount: u64 = 10 * 1_000_000_000;
            let out_amount: u64 = 8 * 1_000_000_000;

            //--- Set lock_height for transaction kernel (current chain height)
            let lock_height: u64 = 10_000; // just for example

            //--- Select inputs using desired selection strategy
            //simulate an UTXO as the input
            let blinding_input = SecretKey::new(&secp, &mut thread_rng());
            let input = commit(in_amount, blinding_input);

            //--- Calculate fee: tx_weight * 1_000_000 nG
            let fee: u64 = 8 * 1_000_000;

            //--- Create change_output
            //--- Select blinding factor for change_output
            let blinding_change_output = SecretKey::new(&secp, &mut thread_rng());
            let change_output = commit(in_amount - out_amount - fee, blinding_change_output);

            //--- Calculate total blinding excess sum xS1 (private scalar), for all inputs(-) and outputs(+)
            let xS1 = secp
                .blind_sum(vec![blinding_change_output], vec![blinding_input])
                .unwrap();

            //--- Subtract random value oS (kernel offset) from xS1. Calculate xS = xS1 - oS
            let oS = SecretKey::new(&secp, &mut thread_rng());
            let xS = secp.blind_sum(vec![xS1], vec![oS]).unwrap();

            sender_sk = xS; // sender's private key for this transaction

            //--- Multiply xS and kS by generator G to create public curve points xSG and kSG
            let xSG = PublicKey::from_secret_key(&secp, &xS).unwrap();

            //--- Create receiver_output
            //--- Calculate blinding factor for receiver_output xR (private scalar)
            //---   q = Hash(m, xS*P), ror*G = q*P = (q*p)*G. So, xR = q*p and only recipient know it.
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();
            let (output,q) = tx_commit(out_amount, &sender_sk, &recipient_pk, &msg);

            //--- Calculate xRG = xR*G = q*P
            let mut xRG = recipient_pk;
            assert!(xRG.mul_assign(&secp, &q).is_ok());

            //--- Verify the balance
            let xG = PublicKey::from_combination(&secp, vec![&xRG, &xSG]).unwrap();
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            if true == secp.verify_commit_sum(
                vec![
                    output,
                    change_output,
                    commit(fee, secp.blind_sum(vec![], vec![oS]).unwrap()),
                ],
                vec![input, excess_commit],
            ) {
                println!("\ntotal sum balance OK:\toutput + change_output + (-offset*G + fee*H) = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output + (-offset*G + fee*H) != input + excess");
            }

            //--- Signature
            let sS = sign_single(
                &secp,
                &msg,
                &xS,
                None,
                None,
                None,
                None,
                None,
            ).unwrap();

            //--- Done
            (
                input,
                change_output,
                out_amount,
                output,
                xSG,
                sS,
                msg,
                excess_commit
            )
        };

        println!("\ninput:  \t{:?}\nchange: \t{:?}\noutput: \t{:?}\nsender pk: \t{:?}\nreceiver pk: \t{:?}",
                 input, change_output, output, sender_pk, recipient_pk);

        println!("\nsender signature: {:?}", sS);
        let result = {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            verify_single(&secp, &sS, &msg, None, &sender_pk, None, None, false)
        };
        if true == result {
            println!("Signature 'sS' Verification:\tOK");
        } else {
            println!("Signature 'sS' Verification:\tNOK");
        }

        println!("\nCT Non-Interactive Tx Procedure: Sending Tx Done.");

        println!("\n-------------------------------------------------\n");

        println!("\nCT Non-Interactive Tx Procedure: Receiving Tx (on receiver side)");

        let (sR, xG, msg, input, output, excess) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- Calculate blinding factor of input
            //---   q = Hash(m, p*A), roi*G = q*P = (q*p)*G. So, roi = q*p
            //---       A is the sender's public key
            let mut roi = {
                let secp = Secp256k1::with_caps(ContextFlag::Commit);
                secp.blind_non_interactive_tx(&recipient_sk, &sender_pk, &msg).unwrap()
            };
            assert!(roi.mul_assign(&secp, &recipient_sk).is_ok());

            //--- Double check: roi*G + sender_pk = public_excess
            let roiG = PublicKey::from_secret_key(&secp, &roi).unwrap();
            let xG = PublicKey::from_combination(&secp, vec![&roiG, &sender_pk]).unwrap();
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            assert_eq!(excess_commit, excess);

            //--- Now creating the new transaction to spend this roi*G+amount*H

            let in_amount: u64 = amount;
            let input = output;

            //--- Calculate fee: tx_weight * 1_000_000 nG
            let fee: u64 = 1 * 1_000_000;
            let out_amount: u64 = in_amount - fee;

            //--- Set lock_height for transaction kernel (current chain height)
            let lock_height: u64 = 10_001; // just for example

            //--- Calculate total blinding excess sum xS1 (private scalar), for all inputs(-) and outputs(+)
            let xS1 = secp
                .blind_sum(vec![], vec![roi])
                .unwrap();

            //--- Subtract random value oS (kernel offset) from xS1. Calculate xS = xS1 - oS
            let oS = SecretKey::new(&secp, &mut thread_rng());
            let xS = secp.blind_sum(vec![xS1], vec![oS]).unwrap();
            let xR = SecretKey::new(&secp, &mut thread_rng());

            //--- Multiply xS and xR by generator G to create public curve points xSG and xRG
            let xSG = PublicKey::from_secret_key(&secp, &xS).unwrap();
            let xRG = PublicKey::from_secret_key(&secp, &xR).unwrap();

            //--- Create receiver_output
            let output= commit(out_amount, xR);

            //--- Verify the balance
            let xG = PublicKey::from_combination(&secp, vec![&xRG, &xSG]).unwrap();
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            if true == secp.verify_commit_sum(
                vec![
                    output,
                    commit(fee, secp.blind_sum(vec![], vec![oS]).unwrap()),
                ],
                vec![input, excess_commit],
            ) {
                println!("\ntotal sum balance OK:\toutput + (-offset*G + fee*H) = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + (-offset*G + fee*H) != input + excess");
            }

            //--- Signature
            let mut xSR = xS;
            assert!(xSR.add_assign(&secp, &xR).is_ok());
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();
            let sR = sign_single(
                &secp,
                &msg,
                &xSR,
                None,
                None,
                None,
                None,
                None,
            ).unwrap();

            //--- Done
            (sR, xG, msg, input, output, excess_commit)
        };

        println!("\ninput:  \t{:?}\noutput: \t{:?}\nexcess: \t{:?}",
                 input, output, excess);

        println!("\nreceiver signature: {:?}", sR);
        let result = {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            verify_single(&secp, &sR, &msg, None, &xG, None, None, false)
        };
        if true == result {
            println!("Signature 'sR' Verification:\tOK");
        } else {
            println!("Signature 'sR' Verification:\tNOK");
        }

        println!("\nCT Non-Interactive Tx Procedure: Receiving Tx Done.");
    }

    #[test]
    #[allow(non_snake_case)]
    fn demo_non_interactive_tx() {
        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        println!("\nCT Non-Interactive Tx Procedure: Payment Tx (on sender side)");

        // Receiver has well known public key P
        let (recipient_pk, recipient_sk) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);
            let p = SecretKey::new(&secp, &mut thread_rng());
            let P = PublicKey::from_secret_key(&secp, &p).unwrap();
            (P,p)
        };
        println!("\nRecipient Public Key: {:?}", recipient_pk);

        // private nonce of signature for this transaction
        let (sender_pubnonce, sender_secnonce) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);
            let p = SecretKey::new(&secp, &mut thread_rng());
            let P = PublicKey::from_secret_key(&secp, &p).unwrap();
            (P,p)
        };
        println!("Public Nonce: {:?}", sender_pubnonce);

        let (input, change_output, amount, output, sS, msg, excess, xG, pay2_pubkey) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            let in_amount: u64 = 10 * 1_000_000_000;
            let out_amount: u64 = 8 * 1_000_000_000;

            //--- Set lock_height for transaction kernel (current chain height)
            let lock_height: u64 = 10_000; // just for example

            //--- Select inputs using desired selection strategy
            //simulate an UTXO as the input
            let blinding_input = SecretKey::new(&secp, &mut thread_rng());
            let input = commit(in_amount, blinding_input);

            //--- Calculate fee: tx_weight * 1_000_000 nG
            let fee: u64 = 8 * 1_000_000;

            //--- Create change_output
            //--- Select blinding factor for change_output
            let blinding_change_output = SecretKey::new(&secp, &mut thread_rng());
            let change_output = commit(in_amount - out_amount - fee, blinding_change_output);

            //--- Create receiver_output
            //--- Calculate blinding factor for receiver_output
            //---   q = Hash(m, r*P), ror*G = q*G. Both sender and recipient know this blinding factor.
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();
            let q = {
                let secp = Secp256k1::with_caps(ContextFlag::Commit);
                secp.blind_non_interactive_tx(&sender_secnonce, &recipient_pk, &msg).unwrap()
            };
            let output = commit(out_amount, q);

            //--- Calculate q*P
            let mut pay2_pubkey = recipient_pk;
            assert!(pay2_pubkey.mul_assign(&secp, &q).is_ok());

            //--- Create oS (kernel offset)
            let oS = SecretKey::new(&secp, &mut thread_rng());

            //--- Calculate total blinding excess sum x (private scalar), for all inputs(-) and outputs(+)
            let x = secp
                .blind_sum(vec![blinding_change_output, q], vec![blinding_input, oS])
                .unwrap();

            //--- Calculate public excess: xG = x*G
            let xG = PublicKey::from_secret_key(&secp, &x).unwrap();

            //--- Verify the balance
            let excess_commit = Commitment::from_pubkey(&secp, &xG).unwrap();
            if true == secp.verify_commit_sum(
                vec![
                    output,
                    change_output,
                    commit(fee, secp.blind_sum(vec![], vec![oS]).unwrap()),
                ],
                vec![input, excess_commit],
            ) {
                println!("\ntotal sum balance OK:\toutput + change_output + (-offset*G + fee*H) = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + change_output + (-offset*G + fee*H) != input + excess");
            }

            //--- Signature
            let sS = sign_single(
                &secp,
                &msg,
                &x,
                Some(&sender_secnonce),
                None,
                Some(&sender_pubnonce),
                Some(&xG),
                None,
            ).unwrap();

            //--- Done
            (
                input,
                change_output,
                out_amount,
                output,
                sS,
                msg,
                excess_commit,
                xG,
                pay2_pubkey
            )
        };

        println!("\ninput:  \t{:?}\nchange: \t{:?}\noutput: \t{:?}\nexcess: \t{:?}\npay to pubkey: \t{:?}",
                 input, change_output, output, excess, pay2_pubkey);

        println!("\nsender signature: {:?}", sS);
        let result = {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            verify_single(&secp, &sS, &msg, None, &xG, Some(&xG), None, false)
        };
        if true == result {
            println!("Signature 'sS' Verification:\tOK");
        } else {
            println!("Signature 'sS' Verification:\tNOK");
        }

        println!("\nCT Non-Interactive Tx Procedure: Payment Tx Done.");

        println!("\n-------------------------------------------------\n");

        println!("\nCT Non-Interactive Tx Procedure: Receiving Tx (on receiver side)");

        let (sR, msg, input, output, excess) = {
            let secp = Secp256k1::with_caps(ContextFlag::Full);

            //--- Get the R: payment transaction signature's public nonce
            let mut R = get_pubnonce_from_signature(&secp, &sS, false).unwrap();

            //--- Calculate blinding factor of input
            //---   q = Hash(m, p*R), ri*G = q*G. So, ri = q
            //---       R is the payment transaction signature's public nonce.
            let mut q = {
                let secp = Secp256k1::with_caps(ContextFlag::Commit);
                secp.blind_non_interactive_tx(&recipient_sk, &R, &msg).unwrap()
            };
            let mut ri = q;
            let mut qp = q;
            assert!(qp.mul_assign(&secp, &recipient_sk).is_ok());

            //--- try -R if qp*G not correct (it should be pay2_pubkey)
            if pay2_pubkey != PublicKey::from_secret_key(&secp, &qp).unwrap() {
                R = get_pubnonce_from_signature(&secp, &sS, true).unwrap();
                assert_eq!(sender_pubnonce, R);
                q = {
                    let secp = Secp256k1::with_caps(ContextFlag::Commit);
                    secp.blind_non_interactive_tx(&recipient_sk, &R, &msg).unwrap()
                };
                ri = q;
                qp = q;
                assert!(qp.mul_assign(&secp, &recipient_sk).is_ok());
            }

            let in_amount: u64 = amount;
            let input = output;

            //--- Calculate fee: tx_weight * 1_000_000 nG
            let fee: u64 = 1 * 1_000_000;
            let out_amount: u64 = in_amount - fee;

            //--- Set lock_height for transaction kernel (current chain height)
            let lock_height: u64 = 10_001; // just for example

            //--- Create oS (kernel offset)
            let oS = SecretKey::new(&secp, &mut thread_rng());

            //--- Calculate ror (private scalar)
            let ror = secp
                .blind_sum(vec![qp, ri, oS], vec![])
                .unwrap();

            //--- Create receiver_output
            let output= commit(out_amount, ror);

            //--- Public Excess: either take if from payment transaction kernel, or calculate it from qp*G.
            let excess_commit = Commitment::from_pubkey(&secp, &pay2_pubkey).unwrap();

            //--- Verify the balance
            if true == secp.verify_commit_sum(
                vec![
                    output,
                    commit(fee, secp.blind_sum(vec![], vec![oS]).unwrap()),
                ],
                vec![input, excess_commit],
            ) {
                println!("\ntotal sum balance OK:\toutput + (-offset*G + fee*H) = input + excess");
            } else {
                println!("\ntotal sum balance NOK:\toutput + (-offset*G + fee*H) != input + excess");
            }

            //--- Signature
            let msg = Message::from_slice(&kernel_sig_msg(fee, lock_height)).unwrap();
            let sR = sign_single(
                &secp,
                &msg,
                &qp,
                None,
                None,
                None,
                Some(&pay2_pubkey),
                None,
            ).unwrap();

            //--- Done
            (sR, msg, input, output, excess_commit)
        };

        println!("\ninput:  \t{:?}\noutput: \t{:?}\nexcess: \t{:?}",
                 input, output, excess);

        println!("\nreceiver signature: {:?}", sR);
        let result = {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            verify_single(&secp, &sR, &msg, None, &pay2_pubkey, Some(&pay2_pubkey), None, false)
        };
        if true == result {
            println!("Signature 'sR' Verification:\tOK");
        } else {
            println!("Signature 'sR' Verification:\tNOK");
        }

        println!("\nCT Non-Interactive Tx Procedure: Receiving Tx Done.");
    }

}
