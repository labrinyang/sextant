use super::types::{
    FirmQuoteRequest, FirmQuoteWire, NativeRfqError, NumberOrString, ValidatedFirmQuote,
};
use crate::chain::NativeRfqProfile;
use alloy_primitives::{Address, B256, Bytes, FixedBytes, Signature, U256, b256, keccak256, uint};
use alloy_sol_types::SolValue;

const V6_AMOUNT_IN_OFFSET: usize = 36;
const V6_AMOUNT_OUT_MINIMUM_OFFSET: usize = 68;
const V6_QUOTE_OFFSET: usize = 96;
const V6_QUOTE_HEAD_WORDS: usize = 27;
const ABI_WORD_BYTES: usize = 32;
const ECDSA_SIGNATURE_BYTES: usize = 65;
const MAX_CALLDATA_BYTES: usize = 128 * 1024;
const SECP256K1_ORDER: U256 =
    uint!(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_U256);
const SECP256K1_HALF_ORDER: U256 =
    uint!(0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0_U256);
const INVALID_QUOTE_SIGNATURE: &str = "quote signature is not a canonical 65-byte secp256k1 value";
const INVALID_WIDGET_SIGNATURE: &str =
    "quote widget fee signature is not a canonical 65-byte secp256k1 value";
const INVALID_RECOVERED_QUOTE_SIGNER: &str = "quote signature does not recover the declared signer";

/// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
const EIP712_DOMAIN_TYPEHASH: B256 =
    b256!("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");
/// keccak256("Order(uint256 nonce,address signer,address buyerToken,address sellerToken,uint256 buyerTokenAmount,uint256 sellerTokenAmount,uint256 deadlineTimestamp,uint256 confidenceExtractedValueT,uint256 confidenceExtractedValueN,uint256 confidenceExtractedValueE,uint256 confidenceExtractedValueM,bytes16 quoteId)")
const NATIVE_ORDER_TYPEHASH: B256 =
    b256!("24db30db0c6378384fabc7896423fdb0caf09704c05de8b8fc17a4cb85171fe5");

#[derive(Debug)]
struct DecodedV6Quote {
    actual_seller_amount: U256,
    actual_min_output_amount: U256,
    pool: Address,
    signer: Address,
    recipient: Address,
    seller_token: Address,
    buyer_token: Address,
    seller_token_amount: U256,
    buyer_token_amount: U256,
    amount_out_minimum: U256,
    deadline_timestamp: U256,
    nonce: U256,
    confidence_t: U256,
    confidence_n: U256,
    confidence_e: U256,
    confidence_m: U256,
    expected_payer: Address,
    expected_origin: Address,
    quote_id: FixedBytes<16>,
    multi_hop: bool,
    signature: [u8; ECDSA_SIGNATURE_BYTES],
    widget_fee_rate: U256,
}

pub fn validate_firm_quote(
    request: &FirmQuoteRequest,
    wire: FirmQuoteWire,
    now: u64,
    min_ttl_seconds: u64,
) -> Result<ValidatedFirmQuote, NativeRfqError> {
    let tx = wire
        .tx_request
        .ok_or(NativeRfqError::InvalidResponse("missing txRequest"))?;
    let target = parse_address(&tx.target, "invalid txRequest target")?;
    if target != request.identity.router {
        return Err(NativeRfqError::InvalidResponse(
            "txRequest target is not the reviewed Native Router",
        ));
    }
    if tx
        .function
        .as_deref()
        .is_some_and(|function| function != "tradeRFQT")
    {
        return Err(NativeRfqError::InvalidResponse(
            "txRequest function is not tradeRFQT",
        ));
    }
    if parse_u256(&tx.value, "invalid txRequest value")? != U256::ZERO {
        return Err(NativeRfqError::InvalidResponse(
            "ERC20 Native RFQ returned nonzero transaction value",
        ));
    }

    let calldata = parse_bytes(&tx.calldata)?;
    if calldata.len() > MAX_CALLDATA_BYTES {
        return Err(NativeRfqError::InvalidResponse("calldata is too large"));
    }
    if calldata.get(..4) != Some(request.identity.trade_selector.as_slice()) {
        return Err(NativeRfqError::InvalidResponse(
            "calldata selector is not reviewed",
        ));
    }

    let amount_in_offset = wire
        .amount_in_offset
        .ok_or(NativeRfqError::InvalidResponse("missing amountInOffset"))?;
    let amount_out_minimum_offset =
        wire.amount_out_minimum_offset
            .ok_or(NativeRfqError::InvalidResponse(
                "missing amountOutMinimumOffset",
            ))?;
    validate_word_offset(&calldata, amount_in_offset)?;
    validate_word_offset(&calldata, amount_out_minimum_offset)?;
    if amount_in_offset != V6_AMOUNT_IN_OFFSET
        || amount_out_minimum_offset != V6_AMOUNT_OUT_MINIMUM_OFFSET
    {
        return Err(NativeRfqError::InvalidResponse(
            "calldata offsets do not match Native Router v6",
        ));
    }

    let quote = decode_v6_trade(&calldata)?;
    // Native returns both dynamic execution overrides as zero. Settler BASIC
    // fills only actualSellerAmount at offset 36. Leaving
    // actualMinOutputAmount at offset 68 as zero is Native's documented
    // sentinel: Router v6 scales tuple word 7 amountOutMinimum by the effective
    // input ratio instead of disabling the minimum-output check. Word 7 is not
    // in the Pool EIP-712 signer hash, but the Native authorization commits
    // the complete canonical execution calldata.
    if quote.actual_seller_amount != U256::ZERO || quote.actual_min_output_amount != U256::ZERO {
        return Err(NativeRfqError::InvalidResponse(
            "firm calldata already overrides dynamic amounts",
        ));
    }
    if quote.pool != request.identity.pool {
        return Err(NativeRfqError::InvalidResponse(
            "quote pool is not the reviewed Native RFQ pool",
        ));
    }
    if quote.signer == Address::ZERO {
        return Err(NativeRfqError::InvalidResponse("quote has no signer"));
    }
    if quote.recipient != request.settler {
        return Err(NativeRfqError::InvalidResponse(
            "quote recipient is not the Settler",
        ));
    }
    if quote.expected_payer != request.settler {
        return Err(NativeRfqError::InvalidResponse(
            "quote execution payer is not the Settler",
        ));
    }
    if quote.expected_origin != request.tx_origin.unwrap_or(Address::ZERO) {
        return Err(NativeRfqError::InvalidResponse(
            "quote transaction origin does not match the request",
        ));
    }
    if quote.seller_token != request.token_in || quote.buyer_token != request.token_out {
        return Err(NativeRfqError::InvalidResponse(
            "quote token pair does not match the request",
        ));
    }
    if quote.seller_token_amount != request.amount_in {
        return Err(NativeRfqError::InvalidResponse(
            "quote input amount does not match the request",
        ));
    }
    if quote.buyer_token_amount == U256::ZERO || quote.amount_out_minimum == U256::ZERO {
        return Err(NativeRfqError::InvalidResponse(
            "quote output or minimum output is zero",
        ));
    }
    if quote.amount_out_minimum > quote.buyer_token_amount {
        return Err(NativeRfqError::InvalidResponse(
            "quote minimum output exceeds quoted output",
        ));
    }
    if quote.multi_hop {
        return Err(NativeRfqError::InvalidResponse(
            "multihop Native quotes are disabled",
        ));
    }
    if quote.widget_fee_rate != U256::ZERO {
        return Err(NativeRfqError::InvalidResponse(
            "Native widget fee must be disabled; solver fees settle separately",
        ));
    }

    let deadline = u64::try_from(quote.deadline_timestamp)
        .map_err(|_| NativeRfqError::InvalidResponse("quote deadline is out of range"))?;
    if deadline < now.saturating_add(min_ttl_seconds) {
        return Err(NativeRfqError::InvalidResponse(
            "quote does not have enough remaining TTL",
        ));
    }
    if deadline
        > now
            .saturating_add(request.expiry_seconds)
            .saturating_add(30)
    {
        return Err(NativeRfqError::InvalidResponse(
            "quote deadline exceeds the requested expiry window",
        ));
    }

    let response_recipient = parse_address(&wire.recipient, "invalid response recipient")?;
    if response_recipient != request.settler {
        return Err(NativeRfqError::InvalidResponse(
            "response recipient is not the Settler",
        ));
    }
    let response_amount_in = parse_u256(&wire.amount_in, "invalid response amountIn")?;
    let response_amount_out = parse_u256(&wire.amount_out, "invalid response amountOut")?;
    if response_amount_in != request.amount_in {
        return Err(NativeRfqError::InvalidResponse(
            "response amountIn does not match the request",
        ));
    }
    if response_amount_out != quote.buyer_token_amount {
        return Err(NativeRfqError::InvalidResponse(
            "response amountOut does not match signed calldata",
        ));
    }
    let router_version = parse_router_version(wire.router_version)?;
    if router_version != request.identity.router_version {
        return Err(NativeRfqError::InvalidResponse(
            "response router version is not reviewed",
        ));
    }
    verify_quote_signature(request.identity, &quote)?;

    Ok(ValidatedFirmQuote {
        target,
        pool: quote.pool,
        calldata,
        token_in: request.token_in,
        token_out: request.token_out,
        settler: request.settler,
        expected_origin: request.tx_origin.unwrap_or(Address::ZERO),
        amount_in: response_amount_in,
        amount_out: response_amount_out,
        signer: quote.signer,
        nonce: quote.nonce,
        beneficiary: request.beneficiary,
        deadline,
        min_ttl_seconds,
        amount_in_offset,
        amount_out_minimum_offset,
        router_version,
        observation: None,
    })
}

/// Decode only the reviewed Native Router v6 words that the adapter must
/// authenticate. The v6 RFQT tuple has 26 fields (27 ABI head words because
/// WidgetFee is a two-word static tuple), which exceeds alloy-sol-types' typed
/// tuple limit. The target runtime and selector are pinned before this parser
/// runs, and the original bytes are always forwarded unchanged.
fn decode_v6_trade(calldata: &[u8]) -> Result<DecodedV6Quote, NativeRfqError> {
    let quote_offset = read_u256(calldata, 4)?;
    if quote_offset != U256::from(V6_QUOTE_OFFSET) {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT quote offset is not canonical",
        ));
    }
    let quote_start =
        4usize
            .checked_add(V6_QUOTE_OFFSET)
            .ok_or(NativeRfqError::InvalidResponse(
                "tradeRFQT calldata offset overflow",
            ))?;
    let quote_head_bytes = V6_QUOTE_HEAD_WORDS * ABI_WORD_BYTES;
    let quote_head_end =
        quote_start
            .checked_add(quote_head_bytes)
            .ok_or(NativeRfqError::InvalidResponse(
                "tradeRFQT calldata offset overflow",
            ))?;
    if quote_head_end > calldata.len() {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata is truncated",
        ));
    }

    // Solidity's external ABI decoder rejects dirty padding on fixed-width
    // values even when application logic does not inspect the field. Mirror
    // those checks so a `ValidatedFirmQuote` cannot still fail at dispatch.
    validate_fixed_bytes_padding(calldata, quote_word_offset(quote_start, 20)?, 16)?;
    quote_address(calldata, quote_start, 24)?;

    let signature_offset = quote_u256(calldata, quote_start, 23)?;
    if signature_offset != U256::from(quote_head_bytes) {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT dynamic bytes offset is not canonical",
        ));
    }
    let signature =
        dynamic_bytes_region(calldata, quote_start, quote_head_bytes, signature_offset)?;
    let expected_widget_signature_offset =
        signature
            .end
            .checked_sub(quote_start)
            .ok_or(NativeRfqError::InvalidResponse(
                "tradeRFQT calldata offset overflow",
            ))?;
    let widget_signature_offset = quote_u256(calldata, quote_start, 26)?;
    if widget_signature_offset != U256::from(expected_widget_signature_offset) {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT dynamic bytes offset is not canonical",
        ));
    }
    let widget_signature = dynamic_bytes_region(
        calldata,
        quote_start,
        quote_head_bytes,
        widget_signature_offset,
    )?;
    if widget_signature.end != calldata.len() {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata has non-canonical trailing bytes",
        ));
    }

    let signature_bytes = signature.bytes(calldata);
    validate_canonical_ecdsa_signature(signature_bytes, INVALID_QUOTE_SIGNATURE)?;
    let signature: [u8; ECDSA_SIGNATURE_BYTES] = signature_bytes
        .try_into()
        .map_err(|_| NativeRfqError::InvalidResponse(INVALID_QUOTE_SIGNATURE))?;
    // Native's V6 responses sign WidgetFee with a 65-byte ECDSA value even
    // when feeRate is zero. Reject an absent signature here rather than
    // forwarding calldata that the fixed Router identity cannot authenticate.
    validate_canonical_ecdsa_signature(widget_signature.bytes(calldata), INVALID_WIDGET_SIGNATURE)?;

    // Validate both ABI booleans even though skipPAMM is selected and signed
    // by Native rather than by this solver.
    let multi_hop = quote_bool(calldata, quote_start, 21)?;
    let _skip_pamm = quote_bool(calldata, quote_start, 22)?;

    Ok(DecodedV6Quote {
        actual_seller_amount: read_u256(calldata, V6_AMOUNT_IN_OFFSET)?,
        actual_min_output_amount: read_u256(calldata, V6_AMOUNT_OUT_MINIMUM_OFFSET)?,
        pool: quote_address(calldata, quote_start, 0)?,
        signer: quote_address(calldata, quote_start, 1)?,
        recipient: quote_address(calldata, quote_start, 2)?,
        seller_token: quote_address(calldata, quote_start, 3)?,
        buyer_token: quote_address(calldata, quote_start, 4)?,
        seller_token_amount: quote_u256(calldata, quote_start, 5)?,
        buyer_token_amount: quote_u256(calldata, quote_start, 6)?,
        amount_out_minimum: quote_u256(calldata, quote_start, 7)?,
        deadline_timestamp: quote_u256(calldata, quote_start, 8)?,
        nonce: quote_u256(calldata, quote_start, 9)?,
        confidence_t: quote_u256(calldata, quote_start, 10)?,
        confidence_n: quote_u256(calldata, quote_start, 11)?,
        confidence_e: quote_u256(calldata, quote_start, 12)?,
        confidence_m: quote_u256(calldata, quote_start, 13)?,
        expected_payer: quote_address(calldata, quote_start, 14)?,
        expected_origin: quote_address(calldata, quote_start, 15)?,
        quote_id: FixedBytes::from_slice(
            calldata
                .get(quote_word_offset(quote_start, 20)?..quote_word_offset(quote_start, 20)? + 16)
                .ok_or(NativeRfqError::InvalidResponse(
                    "tradeRFQT calldata is truncated",
                ))?,
        ),
        multi_hop,
        signature,
        // WidgetFee expands in-place to feeRecipient at word 24 and feeRate
        // at word 25 because the nested tuple itself is static.
        widget_fee_rate: quote_u256(calldata, quote_start, 25)?,
    })
}

fn native_order_struct_hash(quote: &DecodedV6Quote) -> B256 {
    keccak256(
        (
            NATIVE_ORDER_TYPEHASH,
            quote.nonce,
            quote.signer,
            quote.buyer_token,
            quote.seller_token,
            quote.buyer_token_amount,
            quote.seller_token_amount,
            quote.deadline_timestamp,
            quote.confidence_t,
            quote.confidence_n,
            quote.confidence_e,
            quote.confidence_m,
            quote.quote_id,
        )
            .abi_encode(),
    )
}

fn native_pool_domain_separator(identity: NativeRfqProfile) -> B256 {
    keccak256(
        (
            EIP712_DOMAIN_TYPEHASH,
            keccak256(identity.domain_name.as_bytes()),
            keccak256(identity.domain_version.as_bytes()),
            U256::from(identity.domain_chain_id),
            identity.pool,
        )
            .abi_encode(),
    )
}

fn native_order_digest(identity: NativeRfqProfile, quote: &DecodedV6Quote) -> B256 {
    let mut encoded = [0u8; 66];
    encoded[..2].copy_from_slice(&[0x19, 0x01]);
    encoded[2..34].copy_from_slice(native_pool_domain_separator(identity).as_slice());
    encoded[34..].copy_from_slice(native_order_struct_hash(quote).as_slice());
    keccak256(encoded)
}

fn verify_quote_signature(
    identity: NativeRfqProfile,
    quote: &DecodedV6Quote,
) -> Result<(), NativeRfqError> {
    let signature = Signature::try_from(quote.signature.as_slice())
        .map_err(|_| NativeRfqError::InvalidResponse(INVALID_QUOTE_SIGNATURE))?;
    let recovered = signature
        .recover_address_from_prehash(&native_order_digest(identity, quote))
        .map_err(|_| NativeRfqError::InvalidResponse(INVALID_RECOVERED_QUOTE_SIGNER))?;
    if recovered != quote.signer {
        return Err(NativeRfqError::InvalidResponse(
            INVALID_RECOVERED_QUOTE_SIGNER,
        ));
    }
    Ok(())
}

fn quote_word_offset(quote_start: usize, index: usize) -> Result<usize, NativeRfqError> {
    quote_start
        .checked_add(
            index
                .checked_mul(ABI_WORD_BYTES)
                .ok_or(NativeRfqError::InvalidResponse(
                    "tradeRFQT calldata offset overflow",
                ))?,
        )
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata offset overflow",
        ))
}

fn quote_u256(calldata: &[u8], quote_start: usize, index: usize) -> Result<U256, NativeRfqError> {
    read_u256(calldata, quote_word_offset(quote_start, index)?)
}

fn quote_address(
    calldata: &[u8],
    quote_start: usize,
    index: usize,
) -> Result<Address, NativeRfqError> {
    read_address(calldata, quote_word_offset(quote_start, index)?)
}

fn quote_bool(calldata: &[u8], quote_start: usize, index: usize) -> Result<bool, NativeRfqError> {
    match quote_u256(calldata, quote_start, index)? {
        U256::ZERO => Ok(false),
        U256::ONE => Ok(true),
        _ => Err(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata has a non-canonical boolean",
        )),
    }
}

fn read_u256(calldata: &[u8], offset: usize) -> Result<U256, NativeRfqError> {
    let end = offset
        .checked_add(ABI_WORD_BYTES)
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata offset overflow",
        ))?;
    let word = calldata
        .get(offset..end)
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata is truncated",
        ))?;
    Ok(U256::from_be_slice(word))
}

fn read_address(calldata: &[u8], offset: usize) -> Result<Address, NativeRfqError> {
    let end = offset
        .checked_add(ABI_WORD_BYTES)
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata offset overflow",
        ))?;
    let word = calldata
        .get(offset..end)
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata is truncated",
        ))?;
    if word[..12].iter().any(|byte| *byte != 0) {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata has a non-canonical address",
        ));
    }
    Ok(Address::from_slice(&word[12..]))
}

fn validate_fixed_bytes_padding(
    calldata: &[u8],
    offset: usize,
    value_bytes: usize,
) -> Result<(), NativeRfqError> {
    let end = offset
        .checked_add(ABI_WORD_BYTES)
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata offset overflow",
        ))?;
    let word = calldata
        .get(offset..end)
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata is truncated",
        ))?;
    if value_bytes > ABI_WORD_BYTES || word[value_bytes..].iter().any(|byte| *byte != 0) {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT calldata has non-canonical fixed-bytes padding",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DynamicBytesRegion {
    /// Absolute start of the unpadded byte value.
    data_start: usize,
    /// Absolute end of the unpadded byte value.
    value_end: usize,
    /// Absolute end of the padded ABI tail.
    end: usize,
}

impl DynamicBytesRegion {
    fn bytes<'a>(&self, calldata: &'a [u8]) -> &'a [u8] {
        &calldata[self.data_start..self.value_end]
    }
}

fn dynamic_bytes_region(
    calldata: &[u8],
    tuple_start: usize,
    head_bytes: usize,
    relative_offset: U256,
) -> Result<DynamicBytesRegion, NativeRfqError> {
    let relative_offset = usize::try_from(relative_offset).map_err(|_| {
        NativeRfqError::InvalidResponse("tradeRFQT dynamic bytes offset is out of range")
    })?;
    if relative_offset < head_bytes || !relative_offset.is_multiple_of(ABI_WORD_BYTES) {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT dynamic bytes offset is not canonical",
        ));
    }
    let length_offset =
        tuple_start
            .checked_add(relative_offset)
            .ok_or(NativeRfqError::InvalidResponse(
                "tradeRFQT calldata offset overflow",
            ))?;
    let length = usize::try_from(read_u256(calldata, length_offset)?).map_err(|_| {
        NativeRfqError::InvalidResponse("tradeRFQT dynamic bytes length is out of range")
    })?;
    let padded_length = length
        .checked_add(ABI_WORD_BYTES - 1)
        .map(|value| value / ABI_WORD_BYTES * ABI_WORD_BYTES)
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT dynamic bytes length overflow",
        ))?;
    let data_start =
        length_offset
            .checked_add(ABI_WORD_BYTES)
            .ok_or(NativeRfqError::InvalidResponse(
                "tradeRFQT dynamic bytes length overflow",
            ))?;
    let value_end = data_start
        .checked_add(length)
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT dynamic bytes length overflow",
        ))?;
    let data_end = data_start
        .checked_add(padded_length)
        .ok_or(NativeRfqError::InvalidResponse(
            "tradeRFQT dynamic bytes length overflow",
        ))?;
    if data_end > calldata.len() {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT dynamic bytes are truncated",
        ));
    }
    if calldata[value_end..data_end].iter().any(|byte| *byte != 0) {
        return Err(NativeRfqError::InvalidResponse(
            "tradeRFQT dynamic bytes padding is nonzero",
        ));
    }
    Ok(DynamicBytesRegion {
        data_start,
        value_end,
        end: data_end,
    })
}

fn validate_canonical_ecdsa_signature(
    signature: &[u8],
    reason: &'static str,
) -> Result<(), NativeRfqError> {
    if signature.len() != ECDSA_SIGNATURE_BYTES {
        return Err(NativeRfqError::InvalidResponse(reason));
    }

    let r = U256::from_be_slice(&signature[..32]);
    let s = U256::from_be_slice(&signature[32..64]);
    let v = signature[64];
    if r == U256::ZERO
        || r >= SECP256K1_ORDER
        || s == U256::ZERO
        || s > SECP256K1_HALF_ORDER
        || !matches!(v, 27 | 28)
    {
        return Err(NativeRfqError::InvalidResponse(reason));
    }
    Ok(())
}

fn validate_word_offset(calldata: &[u8], offset: usize) -> Result<(), NativeRfqError> {
    if offset < 4 || !(offset - 4).is_multiple_of(32) || offset.saturating_add(32) > calldata.len()
    {
        return Err(NativeRfqError::InvalidResponse(
            "calldata word offset is out of bounds or unaligned",
        ));
    }
    Ok(())
}

fn parse_address(value: &str, reason: &'static str) -> Result<Address, NativeRfqError> {
    value
        .parse()
        .map_err(|_| NativeRfqError::InvalidResponse(reason))
}

fn parse_u256(value: &str, reason: &'static str) -> Result<U256, NativeRfqError> {
    let parsed = match value.strip_prefix("0x") {
        Some(hex) => U256::from_str_radix(hex, 16),
        None => U256::from_str_radix(value, 10),
    };
    parsed.map_err(|_| NativeRfqError::InvalidResponse(reason))
}

fn parse_bytes(value: &str) -> Result<Bytes, NativeRfqError> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    alloy_primitives::hex::decode(hex)
        .map(Bytes::from)
        .map_err(|_| NativeRfqError::InvalidResponse("invalid txRequest calldata"))
}

fn parse_router_version(value: Option<NumberOrString>) -> Result<u8, NativeRfqError> {
    let value = value.ok_or(NativeRfqError::InvalidResponse("missing router_version"))?;
    let version = match value {
        NumberOrString::Number(value) => value,
        NumberOrString::String(value) => {
            let value = value
                .strip_prefix('v')
                .or_else(|| value.strip_prefix('V'))
                .unwrap_or(&value);
            let mut components = value.split('.');
            let major = components
                .next()
                .filter(|component| !component.is_empty())
                .ok_or(NativeRfqError::InvalidResponse("invalid router_version"))?
                .parse()
                .map_err(|_| NativeRfqError::InvalidResponse("invalid router_version"))?;
            if components.any(|component| {
                component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                return Err(NativeRfqError::InvalidResponse("invalid router_version"));
            }
            major
        }
    };
    u8::try_from(version)
        .map_err(|_| NativeRfqError::InvalidResponse("router_version is out of range"))
}

#[cfg(any(test, feature = "testing"))]
pub mod test_support {
    use super::*;

    use super::super::types::TxRequestWire;
    use crate::chain::FIXTURE_NATIVE_RFQ;
    use alloy::signers::{SignerSync, local::PrivateKeySigner};

    pub const NOW: u64 = 1_800_000_000;

    pub const TEST_NATIVE_SIGNING_KEY: &str =
        "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d";

    pub fn token_in() -> Address {
        Address::repeat_byte(0x11)
    }

    pub fn token_out() -> Address {
        Address::repeat_byte(0x22)
    }

    pub fn settler() -> Address {
        Address::repeat_byte(0x33)
    }

    pub fn request() -> FirmQuoteRequest {
        FirmQuoteRequest {
            identity: FIXTURE_NATIVE_RFQ,
            token_in: token_in(),
            token_out: token_out(),
            amount_in: U256::from(1_000u64),
            settler: settler(),
            beneficiary: Address::repeat_byte(0x45),
            tx_origin: Some(Address::repeat_byte(0x44)),
            slippage_bps: 50,
            expiry_seconds: 60,
            chain_timestamp: NOW,
        }
    }

    pub fn canonical_signature(v: u8) -> Vec<u8> {
        let mut signature = vec![0u8; ECDSA_SIGNATURE_BYTES];
        signature[31] = 1;
        signature[63] = 1;
        signature[64] = v;
        signature
    }

    pub fn invalid_signature_shapes() -> Vec<Vec<u8>> {
        let mut zero_r = canonical_signature(27);
        zero_r[..32].fill(0);

        let mut zero_s = canonical_signature(27);
        zero_s[32..64].fill(0);

        let mut r_at_order = canonical_signature(27);
        r_at_order[..32].copy_from_slice(&SECP256K1_ORDER.to_be_bytes::<32>());

        let mut high_s = canonical_signature(27);
        high_s[32..64].copy_from_slice(&(SECP256K1_HALF_ORDER + U256::ONE).to_be_bytes::<32>());

        let mut invalid_v = canonical_signature(27);
        invalid_v[64] = 1;

        vec![zero_r, zero_s, r_at_order, high_s, invalid_v]
    }

    #[derive(Clone)]
    pub struct TestQuote {
        pub pool: Address,
        pub signer: Address,
        pub recipient: Address,
        pub seller_token: Address,
        pub buyer_token: Address,
        pub seller_token_amount: U256,
        pub buyer_token_amount: U256,
        pub amount_out_minimum: U256,
        pub deadline: U256,
        pub nonce: U256,
        pub confidence_t: U256,
        pub confidence_n: U256,
        pub confidence_e: U256,
        pub confidence_m: U256,
        pub expected_payer: Address,
        pub expected_origin: Address,
        pub quote_id: [u8; 16],
        pub multi_hop: bool,
        pub skip_pamm: bool,
        pub signature: Vec<u8>,
        pub widget_fee_recipient: Address,
        pub widget_fee_rate: U256,
        pub widget_fee_signature: Vec<u8>,
    }

    pub fn quote() -> TestQuote {
        let signer = TEST_NATIVE_SIGNING_KEY.parse::<PrivateKeySigner>().unwrap();
        let mut quote = TestQuote {
            pool: FIXTURE_NATIVE_RFQ.pool,
            signer: signer.address(),
            recipient: settler(),
            seller_token: token_in(),
            buyer_token: token_out(),
            seller_token_amount: U256::from(1_000u64),
            buyer_token_amount: U256::from(2_000u64),
            amount_out_minimum: U256::from(1_900u64),
            deadline: U256::from(NOW + 60),
            nonce: U256::from(7u64),
            confidence_t: U256::ZERO,
            confidence_n: U256::ZERO,
            confidence_e: U256::ZERO,
            confidence_m: U256::ZERO,
            expected_payer: settler(),
            expected_origin: Address::repeat_byte(0x44),
            quote_id: [0x66; 16],
            multi_hop: false,
            skip_pamm: false,
            // Replaced below after all EIP-712 fields have been assembled.
            signature: canonical_signature(27),
            // V6 responses may use a nonzero fee recipient even when the
            // widget fee rate itself is disabled.
            widget_fee_recipient: Address::repeat_byte(0x60),
            widget_fee_rate: U256::ZERO,
            widget_fee_signature: canonical_signature(28),
        };
        quote.signature = signer
            .sign_hash_sync(&native_order_digest(
                FIXTURE_NATIVE_RFQ,
                &decoded_test_quote(&quote),
            ))
            .unwrap()
            .as_bytes()
            .to_vec();
        quote
    }

    pub(super) fn decoded_test_quote(quote: &TestQuote) -> DecodedV6Quote {
        DecodedV6Quote {
            actual_seller_amount: U256::ZERO,
            actual_min_output_amount: U256::ZERO,
            pool: quote.pool,
            signer: quote.signer,
            recipient: quote.recipient,
            seller_token: quote.seller_token,
            buyer_token: quote.buyer_token,
            seller_token_amount: quote.seller_token_amount,
            buyer_token_amount: quote.buyer_token_amount,
            amount_out_minimum: quote.amount_out_minimum,
            deadline_timestamp: quote.deadline,
            nonce: quote.nonce,
            confidence_t: quote.confidence_t,
            confidence_n: quote.confidence_n,
            confidence_e: quote.confidence_e,
            confidence_m: quote.confidence_m,
            expected_payer: quote.expected_payer,
            expected_origin: quote.expected_origin,
            quote_id: FixedBytes::from(quote.quote_id),
            multi_hop: quote.multi_hop,
            signature: quote.signature.as_slice().try_into().unwrap(),
            widget_fee_rate: quote.widget_fee_rate,
        }
    }

    pub fn push_u256(out: &mut Vec<u8>, value: U256) {
        out.extend_from_slice(&value.to_be_bytes::<32>());
    }

    pub fn push_address(out: &mut Vec<u8>, value: Address) {
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(value.as_slice());
    }

    pub fn push_dynamic_bytes(out: &mut Vec<u8>, value: &[u8]) {
        push_u256(out, U256::from(value.len()));
        out.extend_from_slice(value);
        let padding = (32 - value.len() % 32) % 32;
        out.resize(out.len() + padding, 0);
    }

    pub fn overwrite_u256(calldata: &mut [u8], offset: usize, value: U256) {
        calldata[offset..offset + 32].copy_from_slice(&value.to_be_bytes::<32>());
    }

    pub fn calldata(quote: TestQuote, actual_in: U256, actual_min: U256) -> Vec<u8> {
        const QUOTE_HEAD_WORDS: usize = 27;

        let signature_tail_bytes = 32 + quote.signature.len().div_ceil(32) * 32;
        let mut out = FIXTURE_NATIVE_RFQ.trade_selector.to_vec();

        // Function head: the dynamic quote tuple, followed by the two words
        // that Settler BASIC is permitted to overwrite.
        push_u256(&mut out, U256::from(3 * 32));
        push_u256(&mut out, actual_in);
        push_u256(&mut out, actual_min);

        push_address(&mut out, quote.pool); // 0
        push_address(&mut out, quote.signer); // 1
        push_address(&mut out, quote.recipient); // 2
        push_address(&mut out, quote.seller_token); // 3
        push_address(&mut out, quote.buyer_token); // 4
        push_u256(&mut out, quote.seller_token_amount); // 5
        push_u256(&mut out, quote.buyer_token_amount); // 6
        push_u256(&mut out, quote.amount_out_minimum); // 7
        push_u256(&mut out, quote.deadline); // 8
        push_u256(&mut out, quote.nonce); // nonce, 9
        push_u256(&mut out, quote.confidence_t); // confidence T, 10
        push_u256(&mut out, quote.confidence_n); // confidence N, 11
        push_u256(&mut out, quote.confidence_e); // confidence E, 12
        push_u256(&mut out, quote.confidence_m); // confidence M, 13
        push_address(&mut out, quote.expected_payer); // 14
        push_address(&mut out, quote.expected_origin); // 15
        for _ in 16..=19 {
            push_u256(&mut out, U256::ZERO); // confidence P/O/R/D
        }
        let mut quote_id_word = [0u8; 32];
        quote_id_word[..16].copy_from_slice(&quote.quote_id);
        out.extend_from_slice(&quote_id_word); // bytes16 quoteId, 20
        push_u256(&mut out, U256::from(quote.multi_hop as u8)); // 21
        push_u256(&mut out, U256::from(quote.skip_pamm as u8)); // 22
        push_u256(&mut out, U256::from(QUOTE_HEAD_WORDS * 32)); // signature, 23
        push_address(&mut out, quote.widget_fee_recipient); // widgetFee recipient, 24
        push_u256(&mut out, quote.widget_fee_rate); // widgetFee rate, 25
        push_u256(
            &mut out,
            U256::from(QUOTE_HEAD_WORDS * 32 + signature_tail_bytes),
        ); // widgetFeeSignature, 26

        push_dynamic_bytes(&mut out, &quote.signature);
        push_dynamic_bytes(&mut out, &quote.widget_fee_signature);
        out
    }

    pub fn wire_with_call(call: Vec<u8>) -> FirmQuoteWire {
        FirmQuoteWire {
            success: true,
            code: None,
            recipient: format!("{:#x}", settler()),
            amount_in: "1000".to_string(),
            amount_out: "2000".to_string(),
            tx_request: Some(TxRequestWire {
                target: format!("{:#x}", FIXTURE_NATIVE_RFQ.router),
                calldata: format!("0x{}", alloy_primitives::hex::encode(call)),
                value: "0".to_string(),
                function: Some("tradeRFQT".to_string()),
            }),
            router_version: Some(NumberOrString::Number(6)),
            amount_in_offset: Some(V6_AMOUNT_IN_OFFSET),
            amount_out_minimum_offset: Some(V6_AMOUNT_OUT_MINIMUM_OFFSET),
            is_black_address: false,
        }
    }

    pub fn wire() -> FirmQuoteWire {
        wire_with_call(calldata(quote(), U256::ZERO, U256::ZERO))
    }

    pub fn assert_rejected(wire: FirmQuoteWire, reason: &'static str) {
        assert_eq!(
            validate_firm_quote(&request(), wire, NOW, 10).unwrap_err(),
            NativeRfqError::InvalidResponse(reason)
        );
    }

    /// The fixture quote, validated at `NOW`.
    pub fn validated() -> ValidatedFirmQuote {
        validate_firm_quote(&request(), wire(), NOW, 10).unwrap()
    }

    pub const AMOUNT_IN_OFFSET: usize = V6_AMOUNT_IN_OFFSET;
    pub const AMOUNT_OUT_MINIMUM_OFFSET: usize = V6_AMOUNT_OUT_MINIMUM_OFFSET;
    pub const WORD_BYTES: usize = ABI_WORD_BYTES;
}

#[cfg(test)]
mod tests {

    use super::test_support::*;
    use super::*;
    use crate::chain::FIXTURE_NATIVE_RFQ;

    #[test]
    fn accepts_reviewed_router_v6_quote_and_preserves_original_calldata() {
        let wire_fixture = wire();
        let expected_calldata = wire_fixture
            .tx_request
            .as_ref()
            .expect("fixture has txRequest")
            .calldata
            .clone();

        let validated = validate_firm_quote(&request(), wire_fixture, NOW, 10).unwrap();

        assert_eq!(validated.target(), FIXTURE_NATIVE_RFQ.router);
        assert_eq!(validated.pool(), FIXTURE_NATIVE_RFQ.pool);
        assert_eq!(validated.amount_in(), U256::from(1_000u64));
        assert_eq!(validated.amount_out(), U256::from(2_000u64));
        assert_eq!(validated.signer, quote().signer);
        assert_eq!(validated.nonce, U256::from(7u64));
        assert_eq!(validated.beneficiary(), request().beneficiary);
        assert_eq!(validated.deadline(), NOW + 60);
        assert_eq!(validated.amount_in_offset(), V6_AMOUNT_IN_OFFSET);
        assert_eq!(
            validated.amount_out_minimum_offset(),
            V6_AMOUNT_OUT_MINIMUM_OFFSET
        );
        assert_eq!(FIXTURE_NATIVE_RFQ.trade_selector, [0x70, 0x83, 0x52, 0x7c]);
        assert_eq!(
            FIXTURE_NATIVE_RFQ.router,
            alloy_primitives::address!("dbb3f5f906fda25784a8ed1dd208cf3772efe6cb")
        );
        assert_eq!(
            FIXTURE_NATIVE_RFQ.pool,
            alloy_primitives::address!("80096680894326faba21e298806a84826dca3a83")
        );
        assert_eq!(&validated.calldata()[..4], &[0x70, 0x83, 0x52, 0x7c]);
        assert_eq!(validated.router_version(), 6);
        assert_eq!(
            format!("0x{}", alloy_primitives::hex::encode(validated.calldata())),
            expected_calldata
        );

        let mut without_swagger_hint = wire();
        without_swagger_hint.tx_request.as_mut().unwrap().function = None;
        validate_firm_quote(&request(), without_swagger_hint, NOW, 10).unwrap();

        let mut pamm_skipped = quote();
        pamm_skipped.skip_pamm = true;
        validate_firm_quote(
            &request(),
            wire_with_call(calldata(pamm_skipped, U256::ZERO, U256::ZERO)),
            NOW,
            10,
        )
        .unwrap();

        for version in ["6", "v6", "v6.0.0", "V6.0"] {
            let mut semantic_version = wire();
            semantic_version.router_version = Some(NumberOrString::String(version.to_string()));
            validate_firm_quote(&request(), semantic_version, NOW, 10).unwrap();
        }
    }

    #[test]
    fn recovers_the_signer_from_a_real_successful_native_v6_trade() {
        // Ethereum transaction
        // 0x4d872921a29da4985775eab3247438d574a22b6a41af605799d6b9357633e993.
        // This public fixture independently pins the Order typehash, field
        // order, bytes16 encoding, EIP-712 domain and v=28 recovery semantics.
        let signature: [u8; ECDSA_SIGNATURE_BYTES] = alloy_primitives::hex::decode(
            "84e40d088280094ada92f3b73a7d6c8674646e0f7ffffa9ee1e6f9f8cb5fd96113f0a160065dbdfe845b767eab2ad0db9411fb03188e557eeb6d70e69ade4a371c",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let quote = DecodedV6Quote {
            actual_seller_amount: U256::ZERO,
            actual_min_output_amount: U256::ZERO,
            pool: alloy_primitives::address!("ef435b99c2108d0309211d0cc05b70d202c0b5df"),
            signer: alloy_primitives::address!("129b3d9a0a6e4beab88f5cb1e57995d72a6e24f1"),
            recipient: alloy_primitives::address!("5f81ad6fa8d9a3dfb0e63890a5eebe645e1a74bc"),
            seller_token: alloy_primitives::address!("dac17f958d2ee523a2206206994597c13d831ec7"),
            buyer_token: alloy_primitives::address!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            seller_token_amount: U256::from(1_000_000u64),
            buyer_token_amount: U256::from(405_813_944_199_229u64),
            amount_out_minimum: U256::from(401_755_804_757_236u64),
            deadline_timestamp: U256::from(1_787_714_022u64),
            nonce: U256::from(6_125_472_088_152_409_473u64),
            confidence_t: U256::from(1_787_713_936u64),
            confidence_n: U256::from(1_787_713_986u64),
            confidence_e: U256::ONE,
            confidence_m: U256::ZERO,
            expected_payer: Address::ZERO,
            expected_origin: Address::ZERO,
            quote_id: FixedBytes::from_slice(
                &alloy_primitives::hex::decode("e189f60fed4c48149628b4b564249dc4").unwrap(),
            ),
            multi_hop: false,
            signature,
            widget_fee_rate: U256::ZERO,
        };
        let ethereum_identity = NativeRfqProfile {
            pool: quote.pool,
            domain_chain_id: 1,
            ..FIXTURE_NATIVE_RFQ
        };

        assert_eq!(
            native_pool_domain_separator(ethereum_identity),
            b256!("75e55faf0869a6966065b19e3bad8a4c67a72966b33ff26e68ffae407d28a378")
        );
        assert_eq!(
            native_order_struct_hash(&quote),
            b256!("43b5b07d38588effba2124228f3571099681dd050c3d1cb1edffc439f035fbec")
        );
        assert_eq!(
            native_order_digest(ethereum_identity, &quote),
            b256!("0e43df8d6b8328de9feb75f6055edb1cde95a681f0b7acfa17488edff3b36a69")
        );
        verify_quote_signature(ethereum_identity, &quote).unwrap();
    }

    #[test]
    fn rejects_wrong_domain_wrong_signer_and_tampered_signed_fields() {
        let mut wrong_domain_request = request();
        wrong_domain_request.identity.domain_chain_id = 1;
        assert_eq!(
            validate_firm_quote(&wrong_domain_request, wire(), NOW, 10).unwrap_err(),
            NativeRfqError::InvalidResponse(INVALID_RECOVERED_QUOTE_SIGNER)
        );

        let mut wrong_signature = quote();
        wrong_signature.signature = canonical_signature(27);
        assert_rejected(
            wire_with_call(calldata(wrong_signature, U256::ZERO, U256::ZERO)),
            INVALID_RECOVERED_QUOTE_SIGNER,
        );

        let mut tampered_nonce = calldata(quote(), U256::ZERO, U256::ZERO);
        overwrite_u256(
            &mut tampered_nonce,
            4 + V6_QUOTE_OFFSET + 9 * ABI_WORD_BYTES,
            U256::from(8u64),
        );
        assert_rejected(
            wire_with_call(tampered_nonce),
            INVALID_RECOVERED_QUOTE_SIGNER,
        );

        let signed_quote = decode_v6_trade(&calldata(quote(), U256::ZERO, U256::ZERO)).unwrap();
        let mut wrong_pool = FIXTURE_NATIVE_RFQ;
        wrong_pool.pool = Address::repeat_byte(0xa1);
        let mut wrong_name = FIXTURE_NATIVE_RFQ;
        wrong_name.domain_name = "Wrong RFQ Pool";
        let mut wrong_version = FIXTURE_NATIVE_RFQ;
        wrong_version.domain_version = "2";
        for (label, identity) in [
            ("verifying pool", wrong_pool),
            ("domain name", wrong_name),
            ("domain version", wrong_version),
        ] {
            assert_eq!(
                verify_quote_signature(identity, &signed_quote),
                Err(NativeRfqError::InvalidResponse(
                    INVALID_RECOVERED_QUOTE_SIGNER
                )),
                "{label}"
            );
        }
    }

    #[test]
    fn every_signed_order_field_changes_the_recovered_signer() {
        let quote_start = 4 + V6_QUOTE_OFFSET;
        for (label, word) in [
            ("signer", 1usize),
            ("sellerToken", 3),
            ("buyerToken", 4),
            ("sellerTokenAmount", 5),
            ("buyerTokenAmount", 6),
            ("deadlineTimestamp", 8),
            ("nonce", 9),
            ("confidenceExtractedValueT", 10),
            ("confidenceExtractedValueN", 11),
            ("confidenceExtractedValueE", 12),
            ("confidenceExtractedValueM", 13),
        ] {
            let mut tampered = calldata(quote(), U256::ZERO, U256::ZERO);
            let offset = quote_start + word * ABI_WORD_BYTES;
            let original = read_u256(&tampered, offset).unwrap();
            overwrite_u256(&mut tampered, offset, original + U256::ONE);
            let decoded = decode_v6_trade(&tampered).unwrap();
            assert_eq!(
                verify_quote_signature(FIXTURE_NATIVE_RFQ, &decoded),
                Err(NativeRfqError::InvalidResponse(
                    INVALID_RECOVERED_QUOTE_SIGNER
                )),
                "{label}"
            );
        }

        let mut tampered_quote_id = calldata(quote(), U256::ZERO, U256::ZERO);
        tampered_quote_id[quote_start + 20 * ABI_WORD_BYTES] ^= 1;
        let decoded = decode_v6_trade(&tampered_quote_id).unwrap();
        assert_eq!(
            verify_quote_signature(FIXTURE_NATIVE_RFQ, &decoded),
            Err(NativeRfqError::InvalidResponse(
                INVALID_RECOVERED_QUOTE_SIGNER
            )),
            "quoteId"
        );
    }

    #[test]
    fn rejects_unreviewed_target_function_value_and_selector() {
        let mut wrong_target = wire();
        wrong_target.tx_request.as_mut().unwrap().target =
            format!("{:#x}", Address::repeat_byte(9));
        assert_rejected(
            wrong_target,
            "txRequest target is not the reviewed Native Router",
        );

        let mut wrong_function = wire();
        wrong_function.tx_request.as_mut().unwrap().function = Some("swap".to_string());
        assert_rejected(wrong_function, "txRequest function is not tradeRFQT");

        let mut nonzero_value = wire();
        nonzero_value.tx_request.as_mut().unwrap().value = "0x1".to_string();
        assert_rejected(
            nonzero_value,
            "ERC20 Native RFQ returned nonzero transaction value",
        );

        let mut wrong_selector = wire();
        let tx = wrong_selector.tx_request.as_mut().unwrap();
        tx.calldata.replace_range(2..10, "deadbeef");
        assert_rejected(wrong_selector, "calldata selector is not reviewed");
    }

    #[test]
    fn rejects_unsafe_dynamic_amount_offsets_and_prepopulated_overrides() {
        let mut unaligned = wire();
        unaligned.amount_in_offset = Some(V6_AMOUNT_IN_OFFSET + 1);
        assert_rejected(
            unaligned,
            "calldata word offset is out of bounds or unaligned",
        );

        let mut wrong_word = wire();
        wrong_word.amount_in_offset = Some(V6_AMOUNT_IN_OFFSET + 64);
        assert_rejected(wrong_word, "calldata offsets do not match Native Router v6");

        let prepopulated = wire_with_call(calldata(quote(), U256::ONE, U256::ZERO));
        assert_rejected(
            prepopulated,
            "firm calldata already overrides dynamic amounts",
        );

        let prepopulated_minimum = wire_with_call(calldata(quote(), U256::ZERO, U256::ONE));
        assert_rejected(
            prepopulated_minimum,
            "firm calldata already overrides dynamic amounts",
        );
    }

    #[test]
    fn rejects_noncanonical_or_truncated_v6_tuple_encoding() {
        let quote_start = 4 + V6_QUOTE_OFFSET;
        let quote_head_bytes = V6_QUOTE_HEAD_WORDS * ABI_WORD_BYTES;

        let mut wrong_quote_offset = calldata(quote(), U256::ZERO, U256::ZERO);
        overwrite_u256(&mut wrong_quote_offset, 4, U256::from(64u64));
        assert_rejected(
            wire_with_call(wrong_quote_offset),
            "tradeRFQT quote offset is not canonical",
        );

        let mut bad_skip_pamm = calldata(quote(), U256::ZERO, U256::ZERO);
        overwrite_u256(
            &mut bad_skip_pamm,
            quote_start + 22 * ABI_WORD_BYTES,
            U256::from(2u64),
        );
        assert_rejected(
            wire_with_call(bad_skip_pamm),
            "tradeRFQT calldata has a non-canonical boolean",
        );

        let mut aliased_signature = calldata(quote(), U256::ZERO, U256::ZERO);
        overwrite_u256(
            &mut aliased_signature,
            quote_start + 23 * ABI_WORD_BYTES,
            U256::from((V6_QUOTE_HEAD_WORDS - 1) * ABI_WORD_BYTES),
        );
        assert_rejected(
            wire_with_call(aliased_signature),
            "tradeRFQT dynamic bytes offset is not canonical",
        );

        let mut dirty_quote_id = calldata(quote(), U256::ZERO, U256::ZERO);
        dirty_quote_id[quote_start + 20 * ABI_WORD_BYTES + 16] = 1;
        assert_rejected(
            wire_with_call(dirty_quote_id),
            "tradeRFQT calldata has non-canonical fixed-bytes padding",
        );

        let mut dirty_widget_recipient = calldata(quote(), U256::ZERO, U256::ZERO);
        dirty_widget_recipient[quote_start + 24 * ABI_WORD_BYTES] = 1;
        assert_rejected(
            wire_with_call(dirty_widget_recipient),
            "tradeRFQT calldata has a non-canonical address",
        );

        let mut aliased_widget_signature = calldata(quote(), U256::ZERO, U256::ZERO);
        overwrite_u256(
            &mut aliased_widget_signature,
            quote_start + 26 * ABI_WORD_BYTES,
            U256::from(quote_head_bytes),
        );
        assert_rejected(
            wire_with_call(aliased_widget_signature),
            "tradeRFQT dynamic bytes offset is not canonical",
        );

        let mut overlapping_widget_signature = calldata(quote(), U256::ZERO, U256::ZERO);
        overwrite_u256(
            &mut overlapping_widget_signature,
            quote_start + 26 * ABI_WORD_BYTES,
            U256::from(quote_head_bytes + ABI_WORD_BYTES),
        );
        assert_rejected(
            wire_with_call(overlapping_widget_signature),
            "tradeRFQT dynamic bytes offset is not canonical",
        );

        let mut gapped_widget_signature = calldata(quote(), U256::ZERO, U256::ZERO);
        let widget_offset_word = quote_start + 26 * ABI_WORD_BYTES;
        let widget_offset = read_u256(&gapped_widget_signature, widget_offset_word).unwrap();
        let widget_tail_start = quote_start + usize::try_from(widget_offset).unwrap();
        gapped_widget_signature.splice(widget_tail_start..widget_tail_start, [0u8; ABI_WORD_BYTES]);
        overwrite_u256(
            &mut gapped_widget_signature,
            widget_offset_word,
            widget_offset + U256::from(ABI_WORD_BYTES),
        );
        assert_rejected(
            wire_with_call(gapped_widget_signature),
            "tradeRFQT dynamic bytes offset is not canonical",
        );

        let mut dirty_signature_padding = calldata(quote(), U256::ZERO, U256::ZERO);
        let signature_data_start = quote_start + quote_head_bytes + ABI_WORD_BYTES;
        dirty_signature_padding[signature_data_start + ECDSA_SIGNATURE_BYTES] = 1;
        assert_rejected(
            wire_with_call(dirty_signature_padding),
            "tradeRFQT dynamic bytes padding is nonzero",
        );

        let mut dirty_widget_signature_padding = calldata(quote(), U256::ZERO, U256::ZERO);
        let widget_relative_offset = usize::try_from(
            read_u256(&dirty_widget_signature_padding, widget_offset_word).unwrap(),
        )
        .unwrap();
        let widget_data_start = quote_start + widget_relative_offset + ABI_WORD_BYTES;
        dirty_widget_signature_padding[widget_data_start + ECDSA_SIGNATURE_BYTES] = 1;
        assert_rejected(
            wire_with_call(dirty_widget_signature_padding),
            "tradeRFQT dynamic bytes padding is nonzero",
        );

        for trailing_len in [1, ABI_WORD_BYTES] {
            let mut trailing_bytes = calldata(quote(), U256::ZERO, U256::ZERO);
            trailing_bytes.resize(trailing_bytes.len() + trailing_len, 0);
            assert_rejected(
                wire_with_call(trailing_bytes),
                "tradeRFQT calldata has non-canonical trailing bytes",
            );
        }

        let mut truncated_tail = calldata(quote(), U256::ZERO, U256::ZERO);
        truncated_tail.pop();
        assert_rejected(
            wire_with_call(truncated_tail),
            "tradeRFQT dynamic bytes are truncated",
        );

        let mut truncated = calldata(quote(), U256::ZERO, U256::ZERO);
        truncated.truncate(quote_start + quote_head_bytes - 1);
        assert_rejected(wire_with_call(truncated), "tradeRFQT calldata is truncated");
    }

    #[test]
    fn rejects_quote_identity_or_order_mismatch() {
        let mut wrong_pool = quote();
        wrong_pool.pool = Address::repeat_byte(0x88);
        assert_rejected(
            wire_with_call(calldata(wrong_pool, U256::ZERO, U256::ZERO)),
            "quote pool is not the reviewed Native RFQ pool",
        );

        let mut wrong_recipient = quote();
        wrong_recipient.recipient = Address::repeat_byte(0x88);
        assert_rejected(
            wire_with_call(calldata(wrong_recipient, U256::ZERO, U256::ZERO)),
            "quote recipient is not the Settler",
        );

        let mut wrong_payer = quote();
        wrong_payer.expected_payer = Address::repeat_byte(0x88);
        assert_rejected(
            wire_with_call(calldata(wrong_payer, U256::ZERO, U256::ZERO)),
            "quote execution payer is not the Settler",
        );

        let mut wrong_origin = quote();
        wrong_origin.expected_origin = Address::repeat_byte(0x88);
        assert_rejected(
            wire_with_call(calldata(wrong_origin, U256::ZERO, U256::ZERO)),
            "quote transaction origin does not match the request",
        );

        let mut wrong_tokens = quote();
        wrong_tokens.buyer_token = Address::repeat_byte(0x88);
        assert_rejected(
            wire_with_call(calldata(wrong_tokens, U256::ZERO, U256::ZERO)),
            "quote token pair does not match the request",
        );

        let mut wrong_amount = quote();
        wrong_amount.seller_token_amount = U256::from(999u64);
        assert_rejected(
            wire_with_call(calldata(wrong_amount, U256::ZERO, U256::ZERO)),
            "quote input amount does not match the request",
        );
    }

    #[test]
    fn absent_tx_origin_requires_the_router_zero_origin_sentinel() {
        let mut request_without_origin = request();
        request_without_origin.tx_origin = None;
        let mut zero_origin_quote = quote();
        zero_origin_quote.expected_origin = Address::ZERO;
        validate_firm_quote(
            &request_without_origin,
            wire_with_call(calldata(zero_origin_quote, U256::ZERO, U256::ZERO)),
            NOW,
            10,
        )
        .unwrap();

        assert_eq!(
            validate_firm_quote(&request_without_origin, wire(), NOW, 10).unwrap_err(),
            NativeRfqError::InvalidResponse("quote transaction origin does not match the request")
        );
    }

    #[test]
    fn rejects_invalid_signatures_multihop_or_fee_bearing_quote() {
        for invalid_len in [0, ECDSA_SIGNATURE_BYTES - 1, ECDSA_SIGNATURE_BYTES + 1] {
            let mut invalid_signature = quote();
            invalid_signature.signature = vec![0x77; invalid_len];
            assert_rejected(
                wire_with_call(calldata(invalid_signature, U256::ZERO, U256::ZERO)),
                INVALID_QUOTE_SIGNATURE,
            );
        }

        for signature in invalid_signature_shapes() {
            let mut invalid_signature = quote();
            invalid_signature.signature = signature;
            assert_rejected(
                wire_with_call(calldata(invalid_signature, U256::ZERO, U256::ZERO)),
                INVALID_QUOTE_SIGNATURE,
            );
        }

        for invalid_len in [0, ECDSA_SIGNATURE_BYTES - 1, ECDSA_SIGNATURE_BYTES + 1] {
            let mut invalid_widget_signature = quote();
            invalid_widget_signature.widget_fee_signature = vec![0x88; invalid_len];
            assert_rejected(
                wire_with_call(calldata(invalid_widget_signature, U256::ZERO, U256::ZERO)),
                INVALID_WIDGET_SIGNATURE,
            );
        }

        for signature in invalid_signature_shapes() {
            let mut invalid_widget_signature = quote();
            invalid_widget_signature.widget_fee_signature = signature;
            assert_rejected(
                wire_with_call(calldata(invalid_widget_signature, U256::ZERO, U256::ZERO)),
                INVALID_WIDGET_SIGNATURE,
            );
        }

        let mut missing_signer = quote();
        missing_signer.signer = Address::ZERO;
        assert_rejected(
            wire_with_call(calldata(missing_signer, U256::ZERO, U256::ZERO)),
            "quote has no signer",
        );

        let mut multihop = quote();
        multihop.multi_hop = true;
        assert_rejected(
            wire_with_call(calldata(multihop, U256::ZERO, U256::ZERO)),
            "multihop Native quotes are disabled",
        );

        let mut fee_bearing = quote();
        fee_bearing.widget_fee_rate = U256::ONE;
        assert_rejected(
            wire_with_call(calldata(fee_bearing, U256::ZERO, U256::ZERO)),
            "Native widget fee must be disabled; solver fees settle separately",
        );
    }

    #[test]
    fn rejects_invalid_output_and_deadline_bounds() {
        let mut zero_output = quote();
        zero_output.buyer_token_amount = U256::ZERO;
        assert_rejected(
            wire_with_call(calldata(zero_output, U256::ZERO, U256::ZERO)),
            "quote output or minimum output is zero",
        );

        let mut impossible_minimum = quote();
        impossible_minimum.amount_out_minimum = impossible_minimum.buyer_token_amount + U256::ONE;
        assert_rejected(
            wire_with_call(calldata(impossible_minimum, U256::ZERO, U256::ZERO)),
            "quote minimum output exceeds quoted output",
        );

        let mut expiring = quote();
        expiring.deadline = U256::from(NOW + 9);
        assert_rejected(
            wire_with_call(calldata(expiring, U256::ZERO, U256::ZERO)),
            "quote does not have enough remaining TTL",
        );

        let mut too_long = quote();
        too_long.deadline = U256::from(NOW + 91);
        assert_rejected(
            wire_with_call(calldata(too_long, U256::ZERO, U256::ZERO)),
            "quote deadline exceeds the requested expiry window",
        );
    }

    #[test]
    fn rejects_wire_metadata_that_disagrees_with_signed_calldata() {
        let mut wrong_recipient = wire();
        wrong_recipient.recipient = format!("{:#x}", Address::repeat_byte(0x99));
        assert_rejected(wrong_recipient, "response recipient is not the Settler");

        let mut wrong_input = wire();
        wrong_input.amount_in = "999".to_string();
        assert_rejected(wrong_input, "response amountIn does not match the request");

        let mut wrong_output = wire();
        wrong_output.amount_out = "1999".to_string();
        assert_rejected(
            wrong_output,
            "response amountOut does not match signed calldata",
        );

        let mut wrong_version = wire();
        wrong_version.router_version = Some(NumberOrString::String("4".to_string()));
        assert_rejected(wrong_version, "response router version is not reviewed");
    }
}
