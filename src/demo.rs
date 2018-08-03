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

    use pedersen::{Commitment};
    use ::{Message, Secp256k1, AggSigPartialSignature};
    use ContextFlag;
    use constants;
    use key::{ZERO_KEY, ONE_KEY, SecretKey, PublicKey};
    use aggsig::{sign_single, verify_single, AggSigContext, export_secnonce_single, add_signatures_single};

    use rand::{Rng, thread_rng, OsRng};

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
    fn test_pedersen_zero_r() {

        fn commit(value: u64) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            let blinding = ZERO_KEY;
            secp.commit(value, blinding).unwrap()
        }

        println!("0*G+1*H:\t{:?}\n0*G+2*H:\t{:?}\n0*G+3*H:\t{:?}",
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

        println!("0*G+3*H:\t{:?}\n0*G+2*H:\t{:?}\nsum:\t\t{:?}",
                 commit_1,
                 commit_2,
                 sum12,
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

        println!("0*G-5*H:\t{:?}\n0*G+5*H:\t{:?}\n-(0*G-5*H):\t{:?}",
                commit_1,
                commit_2,
                secp.commit_sum(vec![], vec![commit_1]).unwrap(),
        );

        println!("\n");
        let commit_3 = commit(-5, true);
        let commit_4 = commit(5, false);
        let commit_5 = commit(0, true);

        println!("1*G-5*H:\t{:?}\n0*G+5*H:\t{:?}\n1*G+0*H:\t{:?}\nsum first 2:\t{:?}",
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

        println!("r1:\t{:?}\nr2:\t{:?}\nr1+r2:\t{:?}",
                 r1,
                 r2,
                 blind_sum,
        );

        println!("");

        r1.0[31] = 3;
        r2.0[31] = 1;

        let blind_sum = secp.blind_sum(vec![r1], vec![r2]);

        println!("r1:\t{:?}\nr2:\t{:?}\nr1-r2:\t{:?}",
                 r1,
                 r2,
                 blind_sum,
        );
    }


    #[test]
    fn test_pedersen_zero_v() {

        fn commit(blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(0, blinding).unwrap()
        }

        let mut r1 = SecretKey([0;32]);
        let mut r2 = SecretKey([0;32]);
        let mut r3 = SecretKey([0;32]);

        r1.0[31] = 1;
        r2.0[31] = 2;
        r3.0[31] = 3;

        println!("1*G+0*H:\t{:?}\n2*G+0*H:\t{:?}\n3*G+0*H:\t{:?}",
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

        let mut r1 = SecretKey([0;32]);
        let mut r2 = SecretKey([0;32]);
        let mut r3 = SecretKey([0;32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;

        let commit_1 = commit(3, r1);
        let commit_2 = commit(2, r2);
        let commit_3 = commit(1, r3);

        let sum23 = secp.commit_sum(vec![commit_2, commit_3], vec![]).unwrap();

        println!("113*G+3*H:\t{:?}\n 71*G+2*H:\t{:?}\n 42*G+1*H:\t{:?}\nsum last2:\t{:?}",
                 commit_1,
                 commit_2,
                 commit_3,
                 sum23,
        );
    }

    #[test]
    fn test_pedersen_demo_safe_output() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
        }

        let mut r1 = SecretKey([0;32]);
        let mut r2 = SecretKey([0;32]);
        let mut r3 = SecretKey([0;32]);
        let mut r4 = SecretKey([0;32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;
        r4.0[31] = 28;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, r4], vec![]).unwrap());
        let output2 = commit(1, r3);

        let sum = secp.commit_sum(vec![output1, output2], vec![]).unwrap();

        let excess = secp.commit_sum(vec![output1, output2], vec![input]).unwrap();

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

        let mut r1 = SecretKey([0;32]);
        let mut r2 = SecretKey([0;32]);
        let mut r3 = SecretKey([0;32]);
        let mut r4 = SecretKey([0;32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;
        r4.0[31] = 28;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, r4], vec![]).unwrap());
        let output2 = commit(1, r3);

        let sum = secp.commit_sum(vec![output1, output2], vec![]).unwrap();

        let excess = secp.commit_sum(vec![output1, output2], vec![input]).unwrap();

        println!("  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}\n\toutputs sum:\t{:?}\n\texcess :\t{:?}",
                 input,
                 output1,
                 output2,
                 sum,
                 excess,
        );

        // sign it

        let excess = secp.commit_sum(vec![output1, output2], vec![input]).unwrap();

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &r4).unwrap();

        let pubkey = excess.to_pubkey(&secp).unwrap();

        println!("\nmsg:\t{:?}\npublic key:\t{:?}\nSignature:\t{:?}",
                 msg,
                 pubkey,
                 sig,
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

        let mut r1 = SecretKey([0;32]);
        let mut r2 = SecretKey([0;32]);
        let mut r3 = SecretKey([0;32]);
        let mut r4 = SecretKey([0;32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;
        r4.0[31] = 28;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, r4], vec![]).unwrap());
        let output2 = commit(1, r3);

        let sum = secp.commit_sum(vec![output1, output2], vec![]).unwrap();

        let excess = secp.commit_sum(vec![output1, output2], vec![input]).unwrap();

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

        let mut new_r1 = SecretKey([0;32]);
        let mut new_r2 = SecretKey([0;32]);
        let mut new_r3 = SecretKey([0;32]);
        let mut new_r4 = SecretKey([0;32]);

        // hacker don't know the real 'r' of input,
        // have to guess or through exhaustive effort (using brute force)
        let guess :u8 = 200;
        new_r1.0[31] = guess;
        new_r2.0[31] = guess-15;	// = r1-r3
        new_r3.0[31] = 15;	// suppose hacker choose 15 as his change output private key
        new_r4.0[31] = 88;	// suppose the recipient choose 88 as his output private key

        let new_output1 = commit(1, secp.blind_sum(vec![new_r2, new_r4], vec![]).unwrap());
        let new_output2 = commit(1, new_r3);

        let new_excess = secp.commit_sum(vec![new_output1, new_output2], vec![new_input]).unwrap();

        println!("  input={}*G+2*H:\t{:?}\noutput1={}*G+1*H:\t{:?}\noutput2= 15*G+1*H:\t{:?}\n\texcess :\t{:?}",
                 guess,
                 new_input,
                 new_r2.0[31] as u64 + new_r4.0[31] as u64,
                 new_output1,
                 new_output2,
                 new_excess,
        );

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &new_r4).unwrap();

        let new_pubkey = new_excess.to_pubkey(&secp).unwrap();

        println!("\nmsg:\t{:?}\npublic key:\t{:?}\nSignature:\t{:?}",
                 msg,
                 new_pubkey,
                 sig,
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

        let mut r1 = SecretKey([0;32]);
        let mut r2 = SecretKey([0;32]);
        let mut r3 = SecretKey([0;32]);
        let mut r4 = SecretKey([0;32]);

        r1.0[31] = 113;
        r2.0[31] = 71;
        r3.0[31] = 42;
        r4.0[31] = 28;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, r4], vec![]).unwrap());
        let output2 = commit(1, r3);

        let excess = secp.commit_sum(vec![output1, output2], vec![input]).unwrap();

        println!("  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}",
                 input,
                 output1,
                 output2,
        );

        // sign it

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &r4).unwrap();

        let pubkey = excess.to_pubkey(&secp).unwrap();

        println!("\n\tmsg:\t\t{:?}\n\texcess:\t\t{:?}\n\tSignature:\t{:?}",
                 msg,
                 excess,
                 sig,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true==secp.verify_commit_sum(
            vec![output1, output2],
            vec![input, excess],
        ){
            println!("\n\"subset sum\" verify OK:\toutput1+output2 = input+excess");
        }else{
            println!("\n\"subset sum\" verify NOK:\toutput1+output2 = input+excess");
        }

        //------	"Subset Sum" problem fixing		-----//

        println!("\n\"Subset Sum\" Problem Fixing...\n");

        // split original r=28 into k1+k2
        let mut k1 = SecretKey([0;32]);
        let mut k2 = SecretKey([0;32]);
        k1.0[31] = 13;
        k2.0[31] = 15;

        let new_output1 = commit(2, secp.blind_sum(vec![r2, k1, k2], vec![]).unwrap());
        let tmp = commit(2, secp.blind_sum(vec![r2, k1], vec![]).unwrap());

        // publish k1*G as excess and k2, instead of (k1+k2)*G
        let new_excess = secp.commit_sum(vec![tmp, output2], vec![input]).unwrap();

        println!("  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}",
                 input,
                 new_output1,
                 output2,
        );

        // sign it only with k1 instead of (k1+k2)

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let new_sig = secp.sign(&msg, &k1).unwrap();

        let new_pubkey = new_excess.to_pubkey(&secp).unwrap();

        println!("\n\tmsg:\t\t{:?}\n\texcess w/ k1*G:\t{:?}\n\tSignature:\t{:?}\n\tk2:\t\t{:?}",
                 msg,
                 new_excess,
                 new_sig,
                 k2,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &new_sig, &new_pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true==secp.verify_commit_sum(
            vec![new_output1, output2],
            vec![input, new_excess],
        ){
            println!("\n\"subset sum\" verify OK:\toutput1+output2 = input+excess");
        }else{
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

        let mut r1 = SecretKey([0;32]);
        let mut r2 = SecretKey([0;32]);
        let mut r3 = SecretKey([0;32]);

        r1.0[31] = 113;     // input
        r3.0[31] = 42;      // for change
        r2.0[31] = 113-42;  // total blinding factor from sender

        // split original r=28 into k1+k2
        let mut k1 = SecretKey([0;32]);
        let mut k2 = SecretKey([0;32]);
        k1.0[31] = 13;
        k2.0[31] = 15;

        let input = commit(3, r1);
        let output1 = commit(2, secp.blind_sum(vec![r2, k1, k2], vec![]).unwrap());
        let output2 = commit(1, r3);
        let tmp = commit(2, secp.blind_sum(vec![r2, k1], vec![]).unwrap());

        // publish k1*G as excess and k2, instead of (k1+k2)*G
        let excess = secp.commit_sum(vec![tmp, output2], vec![input]).unwrap();

        println!("  input=113*G+3*H:\t{:?}\noutput1= 99*G+2*H:\t{:?}\noutput2= 42*G+1*H:\t{:?}",
                 input,
                 output1,
                 output2,
        );

        // sign it only with k1 instead of (k1+k2)

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &k1).unwrap();

        let pubkey = excess.to_pubkey(&secp).unwrap();

        println!("\n\tmsg:\t\t{:?}\n\texcess w/ k1*G:\t{:?}\n\tSignature:\t{:?}\n\tk2:\t\t{:?}",
                 msg,
                 excess,
                 sig,
                 k2,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true==secp.verify_commit_sum(
            vec![output1, output2],
            vec![input, excess],
        ){
            println!("\n\"subset sum\" verify OK:\toutput1+output2 = input+excess");
        }else{
            println!("\n\"subset sum\" verify NOK:\toutput1+output2 != input+excess");
        }

        if true==secp.verify_commit_sum(
            vec![output1, output2],
            vec![input, excess, commit(0, k2)],
        ){
            println!("\nsum with k2*G verify OK:\toutput1 + output2 = input + excess + k2*G");
        }else{
            println!("\nsum with k2*G verify NOK:\toutput1 + output2 != input + excess + k2*G");
        }

        //------	transaction 2		-----//

        println!("\nSecond transaction...\n");

        let mut new_r1 = SecretKey([0;32]);
        let mut new_r2 = SecretKey([0;32]);
        let mut new_r3 = SecretKey([0;32]);

        new_r1.0[31] = 205;     // input
        new_r3.0[31] = 68;      // for change
        new_r2.0[31] = 205-68;  // total blinding factor from sender

        // split original r=79 into k1+k2
        let mut new_k1 = SecretKey([0;32]);
        let mut new_k2 = SecretKey([0;32]);
        new_k1.0[31] = 55;
        new_k2.0[31] = 24;

        let new_input = commit(10, new_r1);
        let new_output1 = commit(6, secp.blind_sum(vec![new_r2, new_k1, new_k2], vec![]).unwrap());
        let new_output2 = commit(4, new_r3);
        let new_tmp = commit(6, secp.blind_sum(vec![new_r2, new_k1], vec![]).unwrap());

        // publish k1*G as excess and k2, instead of (k1+k2)*G
        let new_excess = secp.commit_sum(vec![new_tmp, new_output2], vec![new_input]).unwrap();

        println!("  input=205*G+10*H:\t{:?}\noutput1= 216*G+6*H:\t{:?}\noutput2= 68*G+4*H:\t{:?}",
                 new_input,
                 new_output1,
                 new_output2,
        );

        // sign it only with k1 instead of (k1+k2)

        let mut new_msg = [0u8; 32];
        thread_rng().fill_bytes(&mut new_msg);
        let new_msg = Message::from_slice(&new_msg).unwrap();

        let new_sig = secp.sign(&new_msg, &new_k1).unwrap();

        let new_pubkey = new_excess.to_pubkey(&secp).unwrap();

        println!("\n\tmsg:\t\t{:?}\n\texcess w/ k1*G:\t{:?}\n\tSignature:\t{:?}\n\tk2:\t\t{:?}",
                 new_msg,
                 new_excess,
                 new_sig,
                 new_k2,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&new_msg, &new_sig, &new_pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true==secp.verify_commit_sum(
            vec![new_output1, new_output2],
            vec![new_input, new_excess],
        ){
            println!("\n\"subset sum\" verify OK:\toutput1+output2 = input+excess");
        }else{
            println!("\n\"subset sum\" verify NOK:\toutput1+output2 != input+excess");
        }

        if true==secp.verify_commit_sum(
            vec![new_output1, new_output2],
            vec![new_input, new_excess, commit(0, new_k2)],
        ){
            println!("\nsum with k2*G verify OK:\toutput1 + output2 = input + excess + k2*G");
        }else{
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
        println!("output3= 216*G+6*H:\t{:?}\noutput4= 68*G+4*H:\t{:?}",
                 new_output1,
                 new_output2,
        );
        println!("\n\tmsg1:\t\t{:?}\n\texcess1:\t{:?}\n\tSignature1:\t{:?}",
                 msg,
                 excess,
                 sig,
        );
        println!("\n\tmsg2:\t\t{:?}\n\texcess2:\t{:?}\n\tSignature1:\t{:?}\n\n\tsum(k2):\t{:?}",
                 new_msg,
                 new_excess,
                 new_sig,
                 secp.blind_sum(vec![k2, new_k2], vec![]).unwrap(),
        );

        // now let's check this "aggregated transaction":

        if true==secp.verify_commit_sum(
            vec![output1, output2, new_output1, new_output2],
            vec![input, new_input, excess, new_excess,
                 commit(0, secp.blind_sum(vec![k2, new_k2], vec![]).unwrap())],
        ){
            println!("\ntotal sum balance verify OK:\toutput1 + output2 + output3 + output4 = input1 + input2 + excess1 + excess2 + sum(k2)*G");
        }else{
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

        let mut r1 = SecretKey([0;32]);
        let mut r2 = SecretKey([0;32]);
        let mut r3 = SecretKey([0;32]);

        r1.0[31] = 113;     // input
        r3.0[31] = 42;      // for change
        r2.0[31] = 113-42;  // total blinding factor from sender

        // split original r=28 into k1+k2
        let mut k1 = SecretKey([0;32]);
        let mut k2 = SecretKey([0;32]);
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

        println!("  input=113*G+3*H:\t{:?}\noutput1= 99*G+103*H:\t{:?}\noutput2= 42*G-100*H:\t{:?}",
                 input,
                 output1,
                 output2,
        );

        // sign it only with k1 instead of (k1+k2)

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let sig = secp.sign(&msg, &k1).unwrap();

        let pubkey = excess.to_pubkey(&secp).unwrap();

        println!("\n\tmsg:\t\t{:?}\n\texcess w/ k1*G:\t{:?}\n\tSignature:\t{:?}\n\tk2:\t\t{:?}",
                 msg,
                 excess,
                 sig,
                 k2,
        );

        // check that we can successfully verify the signature with the public key
        if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
            println!("Signature verify OK");
        } else {
            println!("Signature verify NOK");
        }

        if true==secp.verify_commit_sum(
            vec![output1, output2],
            vec![input, excess, commit(0, k2)],
        ){
            println!("\nsum with k2*G verify OK:\toutput1 + output2 = input + excess + k2*G");
        }else{
            println!("\nsum with k2*G verify NOK:\toutput1 + output2 != input + excess + k2*G");
        }
    }

    #[test]
    fn test_demo_bullet_proof() {

        println!("Demo Bullet Proof without extra message data...\n");

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let value = 12345678;
        let commit = secp.commit(value, blinding).unwrap();
        let bullet_proof = secp.bullet_proof(value, blinding, blinding, None);

        println!("Value:\t\t{}\nBlinding:\t{:?}\nCommitment:\t{:?}\n\nBullet Proof:\t{:?}",
                 value,
                 blinding,
                 commit,
                 bullet_proof,
        );

        let proof_range = secp.verify_bullet_proof(commit, bullet_proof, None).unwrap();
        println!("\nVerification:\t{:#?}", proof_range);

        //-----

        println!("\nDemo Bullet Proof with extra message data...\n");

        let extra_data = [0u8;32].to_vec();
        let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let value = 12345678;
        let commit = secp.commit(value, blinding).unwrap();
        let bullet_proof = secp.bullet_proof(value, blinding, blinding, Some(extra_data.clone()));

        println!("Value:\t\t{}\nBlinding:\t{:?}\nExtra data:\t{:?}\nCommitment:\t{:?}\n\nBullet Proof:\t{:?}",
                 value,
                 blinding,
                 (extra_data),
                 commit,
                 bullet_proof,
        );

        let proof_range = secp.verify_bullet_proof(commit, bullet_proof, Some(extra_data.clone())).unwrap();
        println!("\nVerification:\t{:#?}", proof_range);

        //-----

        println!("\nDemo rewinding. Extracts the value and blinding factor...\n");

        let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let nonce = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let value = 12345678;
        let commit = secp.commit(value, blinding).unwrap();
        let bullet_proof = secp.bullet_proof(value, blinding, nonce, Some(extra_data.clone()));

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
        let proof_info = secp.rewind_bullet_proof(commit, nonce, Some(extra_data.clone()), bullet_proof).unwrap();
        println!("\nRewind_bullet_proof:\t{:#?}", proof_info);

        println!("Bullet Proof:\t{:?}",
                 bullet_proof,
        );

        let proof_range = secp.verify_bullet_proof(commit, bullet_proof, Some(extra_data.clone())).unwrap();
        println!("\nVerification:\t{:#?}", proof_range);
    }

    #[test]
    fn demo_aggsig_single() {
        let secp = Secp256k1::with_caps(ContextFlag::Full);
        let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk, sk);

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let sig = sign_single(&secp, &msg, &sk, None, None, None).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig:\t\t{:?}", sig);

        let result = verify_single(&secp, &sig, &msg, None, &pk, false);
        if true == result {
            println!("signature check:\tOK");
        }else{
            println!("signature check:\tNOK");
        }
    }

    #[test]
    fn demo_aggsig_multi() {

        let numkeys = 3;
        let secp = Secp256k1::with_caps(ContextFlag::Full);

        let mut keypairs:Vec<(SecretKey, PublicKey)> = vec![];
        for _ in 0..numkeys {
            keypairs.push(secp.generate_keypair(&mut thread_rng()).unwrap());
        }

        let pks:Vec<PublicKey> = keypairs.clone().into_iter()
            .map(|(_,p)| p)
            .collect();

        println!("aggsig context with {} pubkeys: {:#?}", pks.len(), pks);

        let aggsig = AggSigContext::new(&secp, &pks);

        println!("Generating nonces for each index");
        for i in 0..numkeys {
            let retval=aggsig.generate_nonce(i);
            println!("{} returned {}", i, retval);
        }

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();

        let mut partial_sigs:Vec<AggSigPartialSignature> = vec![];
        for i in 0..numkeys {
            println!("\nPartial sign:\n\tmessage:\t{:?} at index {}\n\tPubkey:\t\t{:?}", msg, i, keypairs[i].1);

            let result = aggsig.partial_sign(msg,keypairs[i].0,i);
            match result {
                Ok(ps) => {
                    println!("\tPartial sig:\t{:?}", ps);
                    partial_sigs.push(ps);
                },
                Err(e) => panic!("Partial sig failed: {}", e),
            }
        }

        let result = aggsig.combine_signatures(&partial_sigs);

        let combined_sig = match result {
            Ok(cs) => {
                println!("\nCombined sig: {:?}", cs);
                cs
            },
            Err(e) => panic!("\nCombining partial sig failed: {}", e),
        };

        println!("\nCombined sig: {:?}\n\tmsg:\t{:?}\n\tpks:\t{:#?}", combined_sig, msg, pks);
        let result = aggsig.verify(combined_sig, msg, &pks);
        if true==result {
            println!("\nSignature verification:\tOK");
        }else{
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
        thread_rng().fill_bytes(&mut msg);
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
        let nonce_sum = PublicKey::from_combination(&secp, vec![&pubnonce_1, &pubnonce_2, &pubnonce_3]).unwrap();

        //--- sig1
        println!("\n--- sig1 ---");

        let (sk1, pk1) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk1, sk1);

        // e=hash(R.x, m)    s=k1+e*p1    sig1=(s,r1)
        let sig1 = sign_single(&secp, &msg, &sk1, Some(&secnonce_1), Some(&nonce_sum), Some(&nonce_sum)).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig1:\t\t{:?}", sig1);

        // sig1.s*G-e*P1 = k1*G+e*p1*G-e*P1 = R1,   check R1.x == sig1.r ?
        let result = verify_single(&secp, &sig1, &msg, Some(&nonce_sum), &pk1, true);
        if true == result {
            println!("sig1 signature check:\tOK");
        }else{
            println!("sig1 signature check:\tNOK");
        }

        //--- sig2

        println!("\n--- sig2 ---");

        let (sk2, pk2) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk2, sk2);

        // e=hash(R.x, m)    s=k2+e*p2    sig2=(s,r2)
        let sig2 = sign_single(&secp, &msg, &sk2, Some(&secnonce_2), Some(&nonce_sum), Some(&nonce_sum)).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig2:\t\t{:?}", sig2);

        // sig2.s*G-e*P2 = k2*G+e*p2*G-e*P2 = R2,   check R2.x == sig2.r ?
        let result = verify_single(&secp, &sig2, &msg, Some(&nonce_sum), &pk2, true);
        if true == result {
            println!("sig2 signature check:\tOK");
        }else{
            println!("sig2 signature check:\tNOK");
        }

        //--- sig3

        println!("\n--- sig3 ---");

        let (sk3, pk3) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk3, sk3);

        // e=hash(R.x, m)    s=k3+e*p3    sig3=(s,r3)
        let sig3 = sign_single(&secp, &msg, &sk3, Some(&secnonce_3), Some(&nonce_sum), Some(&nonce_sum)).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig3:\t\t{:?}", sig3);

        // sig3.s*G-e*P3 = k3*G+e*p3*G-e*P3 = R3,   check R3.x == sig3.r ?
        let result = verify_single(&secp, &sig3, &msg, Some(&nonce_sum), &pk3, true);
        if true == result {
            println!("sig3 signature check:\tOK");
        }else{
            println!("sig3 signature check:\tNOK");
        }

        //--- Batch Verification

        println!("\n--- Batch Verification ---");

        let sig_vec = vec![&sig1, &sig2, &sig3];
        let combined_sig = add_signatures_single(&secp, sig_vec, &nonce_sum).unwrap();

        // Sum public keys: P = P1+P2+P3
        let pk_sum = PublicKey::from_combination(&secp, vec![&pk1, &pk2, &pk3]).unwrap();

        println!("\nCombined sig:\t{:?}\n\tmsg:\t{:?}\n\tpk_sum:\t{:?}", combined_sig, msg, pk_sum);
        // sig.s*G-e*P = k*G+e*p*G-e*P = R,   check R.x == sig.r ?
        let result = verify_single(&secp, &combined_sig, &msg, Some(&nonce_sum), &pk_sum, false);
        if true==result {
            println!("\nSignature Batch Verification:\tOK");
        }else{
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
        thread_rng().fill_bytes(&mut msg);
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
        let nonce_sum = PublicKey::from_combination(&secp, vec![&pubnonce_1, &pubnonce_2, &pubnonce_3]).unwrap();

        //--- sig1
        println!("\n--- sig1 ---");

        let (sk1, pk1) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk1, sk1);

        // e=hash(R.x, m)    s=k1+e*p1    sig1=(s,r1)
        let sig1 = sign_single(&secp, &msg, &sk1, Some(&secnonce_1), None, None).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig1:\t\t{:?}", sig1);

        // sig1.s*G-e*P1 = k1*G+e*p1*G-e*P1 = R1,   check R1.x == sig1.r ?
        let result = verify_single(&secp, &sig1, &msg, None, &pk1, false);
        if true == result {
            println!("sig1 signature check:\tOK");
        }else{
            println!("sig1 signature check:\tNOK");
        }

        //--- sig2

        println!("\n--- sig2 ---");

        let (sk2, pk2) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk2, sk2);

        // e=hash(R.x, m)    s=k2+e*p2    sig2=(s,r2)
        let sig2 = sign_single(&secp, &msg, &sk2, Some(&secnonce_2), None, None).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig2:\t\t{:?}", sig2);

        // sig2.s*G-e*P2 = k2*G+e*p2*G-e*P2 = R2,   check R2.x == sig2.r ?
        let result = verify_single(&secp, &sig2, &msg, None, &pk2, false);
        if true == result {
            println!("sig2 signature check:\tOK");
        }else{
            println!("sig2 signature check:\tNOK");
        }

        //--- sig3

        println!("\n--- sig3 ---");

        let (sk3, pk3) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("public key (P):\t\t{:?}\nprivate key (p):\t{:?}", pk3, sk3);

        // e=hash(R.x, m)    s=k3+e*p3    sig3=(s,r3)
        let sig3 = sign_single(&secp, &msg, &sk3, Some(&secnonce_3), None, None).unwrap();
        println!("msg:\t\t\t{:?}", msg);
        println!("\nschnorr sig3:\t\t{:?}", sig3);

        // sig3.s*G-e*P3 = k3*G+e*p3*G-e*P3 = R3,   check R3.x == sig3.r ?
        let result = verify_single(&secp, &sig3, &msg, None, &pk3, false);
        if true == result {
            println!("sig3 signature check:\tOK");
        }else{
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

        println!("\nCombined sig:\t{:?}\n\tmsg:\t{:?}\n\tpk_sum:\t{:?}", combined_sig, msg, pk_sum);
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
        let result = verify_single(&secp, &combined_sig, &msg, Some(&nonce_sum), &pk_sum, false);
        if true==result {
            println!("\nSignature Batch Verification:\tOK");
        }else{
            println!("\nSignature Batch Verification:\tNOK");
        }
    }

}