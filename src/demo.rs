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
    use ::{Message, Secp256k1};
    use ContextFlag;
    use constants;
    use key::{ZERO_KEY, SecretKey};

    use rand::{Rng, thread_rng};

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

        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()
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
        let output2 = commit(<u64>::max_value()-100+1, r3);
        let tmp = commit(103, secp.blind_sum(vec![r2, k1], vec![]).unwrap());

        // publish k1*G as excess and k2, instead of (k1+k2)*G
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
    }
}
