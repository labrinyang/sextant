use alloy::signers::{SignerSync, local::PrivateKeySigner};
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::SolValue;
use anyhow::Context;
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;

const SIGNING_KEY_ENV: &str = "SOLVER_NATIVE_BENEFICIARY_SIGNING_KEY";

/// Compact EIP-2098 signature consumed by a Settler build's
/// `executeWithNativeAuthorization`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAuthorization {
    pub r: B256,
    pub vs: B256,
}

/// Process-local signer that binds Native's off-chain beneficiary to one
/// canonical Settler execution. Cloning this type clones only the `Arc`, never
/// the parsed private-key material.
#[derive(Clone)]
pub struct NativeBeneficiaryAuthorizer {
    signer: Arc<PrivateKeySigner>,
}

impl fmt::Debug for NativeBeneficiaryAuthorizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeBeneficiaryAuthorizer")
            .field("address", &self.address())
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl NativeBeneficiaryAuthorizer {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_env_value(std::env::var(SIGNING_KEY_ENV))
    }

    fn from_env_value(value: Result<String, std::env::VarError>) -> anyhow::Result<Self> {
        let secret = match value {
            Ok(secret) => Zeroizing::new(secret),
            Err(std::env::VarError::NotPresent) => {
                anyhow::bail!("{SIGNING_KEY_ENV} is required when Native RFQ is enabled")
            }
            Err(error) => anyhow::bail!("reading {SIGNING_KEY_ENV}: {error}"),
        };
        Self::from_secret(secret.trim())
            .with_context(|| format!("{SIGNING_KEY_ENV} is not a valid secp256k1 private key"))
    }

    pub fn from_secret(secret: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !secret.trim().is_empty(),
            "beneficiary signing key is empty"
        );
        let signer = secret
            .trim()
            .parse::<PrivateKeySigner>()
            .context("invalid beneficiary signing key")?;
        Ok(Self {
            signer: Arc::new(signer),
        })
    }

    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// `typehash` names the authorization type the chain's Settler build
    /// recovers (`SettlerProfile::native_authorization_typehash`).
    #[allow(clippy::too_many_arguments)]
    pub fn struct_hash(
        typehash: B256,
        chain_id: u64,
        settler: Address,
        taker: Address,
        beneficiary: Address,
        execution_calldata: &[u8],
        deadline: u64,
    ) -> B256 {
        keccak256(
            (
                typehash,
                U256::from(chain_id),
                settler,
                taker,
                beneficiary,
                keccak256(execution_calldata),
                U256::from(deadline),
            )
                .abi_encode(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        typehash: B256,
        chain_id: u64,
        settler: Address,
        taker: Address,
        beneficiary: Address,
        execution_calldata: &[u8],
        deadline: u64,
    ) -> anyhow::Result<NativeAuthorization> {
        let struct_hash = Self::struct_hash(
            typehash,
            chain_id,
            settler,
            taker,
            beneficiary,
            execution_calldata,
            deadline,
        );
        self.sign_struct_hash(struct_hash)
    }

    fn sign_struct_hash(&self, struct_hash: B256) -> anyhow::Result<NativeAuthorization> {
        // sign_message_sync applies the EIP-191 "Ethereum Signed Message"
        // prefix. The contract recovers the same personal-sign digest.
        let signature = self
            .signer
            .sign_message_sync(struct_hash.as_slice())
            .context("signing Native beneficiary authorization")?;
        let compact = signature.as_erc2098();
        Ok(NativeAuthorization {
            r: B256::from_slice(&compact[..32]),
            vs: B256::from_slice(&compact[32..]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TYPEHASH: B256 = crate::chain::FIXTURE_NATIVE_AUTHORIZATION_TYPEHASH;
    use alloy_primitives::Signature;

    const TEST_KEY: &str = "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d";

    fn fields() -> (u64, Address, Address, Address, Vec<u8>, u64) {
        (
            2_818,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x33),
            vec![0x01, 0x02, 0x03, 0x04, 0x05],
            1_800_000_060,
        )
    }

    #[test]
    fn compact_signature_recovers_the_configured_signer() {
        let authorizer = NativeBeneficiaryAuthorizer::from_secret(TEST_KEY).unwrap();
        let (chain_id, settler, taker, beneficiary, calldata, deadline) = fields();
        let struct_hash = NativeBeneficiaryAuthorizer::struct_hash(
            TYPEHASH,
            chain_id,
            settler,
            taker,
            beneficiary,
            &calldata,
            deadline,
        );
        let authorization = authorizer
            .authorize(
                TYPEHASH,
                chain_id,
                settler,
                taker,
                beneficiary,
                &calldata,
                deadline,
            )
            .unwrap();
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(authorization.r.as_slice());
        compact[32..].copy_from_slice(authorization.vs.as_slice());
        let recovered = Signature::from_erc2098(&compact)
            .recover_address_from_msg(struct_hash.as_slice())
            .unwrap();

        assert_eq!(recovered, authorizer.address());
        assert_eq!(
            authorizer.address(),
            "0x1f56e73362f9ceda7a6c190e374361b9b0edc2ec"
                .parse::<Address>()
                .unwrap()
        );
    }

    /// Vectors a Native-capable Settler build's own tests check, generated
    /// with cast alone.
    #[test]
    fn signatures_match_the_settler_test_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures/native_authorization.json")).unwrap();
        assert_eq!(
            vectors["typehash"]
                .as_str()
                .unwrap()
                .parse::<B256>()
                .unwrap(),
            TYPEHASH
        );
        assert_eq!(TYPEHASH, keccak256(vectors["type"].as_str().unwrap()));
        // The public test key the vectors were generated with.
        let signer = NativeBeneficiaryAuthorizer::from_secret(
            "0x00000000000000000000000000000000000000000000000000000000000a11ce",
        )
        .unwrap();
        assert_eq!(
            signer.address(),
            vectors["signer"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap()
        );
        let cases = vectors["cases"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let field = |name: &str| case[name].as_str().unwrap();
            let chain_id: u64 = field("chainId").parse().unwrap();
            let settler: Address = field("settler").parse().unwrap();
            let taker: Address = field("taker").parse().unwrap();
            let recipient: Address = field("recipient").parse().unwrap();
            let deadline: u64 = field("deadline").parse().unwrap();
            let execute = crate::abi::hexbytes(field("executeCalldata")).unwrap();
            assert_eq!(
                keccak256(&execute),
                field("executionHash").parse::<B256>().unwrap()
            );
            assert_eq!(
                NativeBeneficiaryAuthorizer::struct_hash(
                    TYPEHASH, chain_id, settler, taker, recipient, &execute, deadline
                ),
                field("structHash").parse::<B256>().unwrap(),
                "{}",
                field("name")
            );
            let authorization = signer
                .authorize(
                    TYPEHASH, chain_id, settler, taker, recipient, &execute, deadline,
                )
                .unwrap();
            assert_eq!(authorization.r, field("r").parse::<B256>().unwrap());
            assert_eq!(authorization.vs, field("vs").parse::<B256>().unwrap());
        }
    }

    #[test]
    fn debug_output_never_contains_private_key_material() {
        let authorizer = NativeBeneficiaryAuthorizer::from_secret(TEST_KEY).unwrap();
        let rendered = format!("{authorizer:?}");
        assert!(!rendered.contains(TEST_KEY));
        assert!(!rendered.contains(TEST_KEY.trim_start_matches("0x")));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn enabled_native_requires_a_valid_independent_signing_key() {
        let missing =
            NativeBeneficiaryAuthorizer::from_env_value(Err(std::env::VarError::NotPresent))
                .unwrap_err();
        assert!(missing.to_string().contains("is required"));

        let invalid = NativeBeneficiaryAuthorizer::from_env_value(Ok(
            "not-the-native-http-api-key".to_string(),
        ))
        .unwrap_err();
        assert!(invalid.to_string().contains("not a valid secp256k1"));
    }

    #[test]
    fn every_authorized_field_changes_the_struct_hash() {
        let (chain_id, settler, taker, beneficiary, calldata, deadline) = fields();
        let baseline = NativeBeneficiaryAuthorizer::struct_hash(
            TYPEHASH,
            chain_id,
            settler,
            taker,
            beneficiary,
            &calldata,
            deadline,
        );
        let variants = [
            NativeBeneficiaryAuthorizer::struct_hash(
                TYPEHASH,
                chain_id + 1,
                settler,
                taker,
                beneficiary,
                &calldata,
                deadline,
            ),
            NativeBeneficiaryAuthorizer::struct_hash(
                TYPEHASH,
                chain_id,
                Address::repeat_byte(0x12),
                taker,
                beneficiary,
                &calldata,
                deadline,
            ),
            NativeBeneficiaryAuthorizer::struct_hash(
                TYPEHASH,
                chain_id,
                settler,
                Address::repeat_byte(0x23),
                beneficiary,
                &calldata,
                deadline,
            ),
            NativeBeneficiaryAuthorizer::struct_hash(
                TYPEHASH,
                chain_id,
                settler,
                taker,
                Address::repeat_byte(0x34),
                &calldata,
                deadline,
            ),
            NativeBeneficiaryAuthorizer::struct_hash(
                TYPEHASH,
                chain_id,
                settler,
                taker,
                beneficiary,
                &[0x01, 0x02, 0x03, 0x04, 0x06],
                deadline,
            ),
            NativeBeneficiaryAuthorizer::struct_hash(
                TYPEHASH,
                chain_id,
                settler,
                taker,
                beneficiary,
                &calldata,
                deadline + 1,
            ),
        ];

        assert!(variants.into_iter().all(|variant| variant != baseline));
    }
}
