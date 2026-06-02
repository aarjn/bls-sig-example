use solana_bls_signatures::{
    keypair::Keypair,
    pubkey::VerifySignature,
    signature::{
        Signature, SignatureAffine, SignatureCompressed, SignatureProjective, VerifiableSignature,
    },
};

use alpenglow::ValidatorIndex;
use alpenglow::crypto::aggsig::{AggregateSignature, SecretKey};

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

    sig_projective.verify(&keypair2.public, message).unwrap();
    sig_affine.verify(&keypair.public, message).unwrap();
    sig_compressed.verify(&keypair.public, message).unwrap();
    sig_uncompressed.verify(&keypair.public, message).unwrap();

    // Alpenglow
    let msg = b"solana is not a chain";

    let sk1 = SecretKey::new(&mut rand::rng());
    let pk1 = sk1.to_pk();
    let sig1 = sk1.sign_bytes(msg);

    let sk2 = SecretKey::new(&mut rand::rng());
    let pk2 = sk2.to_pk();
    let sig2 = sk2.sign_bytes(msg);

    let mut aggsig = AggregateSignature::new(
        &[sig1, sig2],
        [ValidatorIndex::new(0), ValidatorIndex::new(1)],
        2,
    );
    assert!(aggsig.verify_bytes(msg, &[pk1, pk2]));
}
