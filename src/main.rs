// this crate will be used for alpenglow
use solana_bls_signatures::{
    PubkeyProjective,
    error::BlsError::VerificationFailed,
    keypair::Keypair,
    pubkey::VerifySignature,
    signature::{
        Signature, SignatureAffine, SignatureCompressed, SignatureProjective, VerifiableSignature,
    },
};

// qkniep/alpenglow
use alpenglow::ValidatorIndex;
use alpenglow::crypto::aggsig::{AggregateSignature, SecretKey};

fn main() {
    let keypair = Keypair::new();
    let keypair2 = Keypair::new();

    let message = b"solana is a server";

    let sig_projective: SignatureProjective = keypair.sign(message);

    let sig_affine: SignatureAffine = sig_projective.into();
    let sig_compressed: SignatureCompressed = sig_projective.into();
    let sig_uncompressed: Signature = sig_projective.into();

    keypair
        .public
        .verify_signature(&sig_projective, message)
        .unwrap();
    keypair
        .public
        .verify_signature(&sig_affine, message)
        .unwrap();
    keypair
        .public
        .verify_signature(&sig_compressed, message)
        .unwrap();
    keypair
        .public
        .verify_signature(&sig_uncompressed, message)
        .unwrap();

    assert_eq!(
        sig_projective.verify(&keypair2.public, message),
        Err(VerificationFailed),
    );

    sig_affine.verify(&keypair.public, message).unwrap();
    sig_compressed.verify(&keypair.public, message).unwrap();
    sig_uncompressed.verify(&keypair.public, message).unwrap();

    // aggregate signatures
    let message_for_all = b"better sign me";
    let kp1 = Keypair::new();
    let kp2 = Keypair::new();
    let kp3 = Keypair::new();

    let sig1 = kp1.sign(message_for_all);
    let sig2 = kp2.sign(message_for_all);
    let sig3 = kp3.sign(message_for_all);

    let app_sig = SignatureProjective::aggregate([&sig1, &sig2, &sig3].into_iter()).unwrap();
    let app_kp =
        PubkeyProjective::aggregate([&kp1.public, &kp2.public, &kp3.public].into_iter()).unwrap();

    app_kp
        .verify_signature(&app_sig, message_for_all)
        .expect("Aggregated Sigs are valid");

    // qkniep/alpenglow
    let msg = b"solana is not a chain";

    let sk1 = SecretKey::new(&mut rand::rng());
    let pk1 = sk1.to_pk();
    let sig1 = sk1.sign_bytes(msg);

    let sk2 = SecretKey::new(&mut rand::rng());
    let pk2 = sk2.to_pk();
    let sig2 = sk2.sign_bytes(msg);

    let sk3 = SecretKey::new(&mut rand::rng());
    let pk3 = sk3.to_pk();
    let sig3 = sk3.sign_bytes(msg);

    let aggsig = AggregateSignature::new(
        &[sig1, sig2, sig3],
        [
            ValidatorIndex::new(0),
            ValidatorIndex::new(1),
            ValidatorIndex::new(2),
        ],
        3,
    );
    assert!(aggsig.verify_bytes(msg, &[pk1, pk2, pk3]));
}
