use solana_bls_signatures::{
    error::BlsError::VerificationFailed,
    keypair::Keypair,
    pubkey::VerifySignature,
    signature::{
        Signature, SignatureAffine, SignatureCompressed, SignatureProjective, VerifiableSignature,
    },
};

use alpenglow::crypto::aggsig::{AggregateSignature, SecretKey};
use alpenglow::ValidatorIndex;

fn main() {
    let keypair = Keypair::new();
    let message = b"solana is a server";

    let keypair2 = Keypair::new();
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
