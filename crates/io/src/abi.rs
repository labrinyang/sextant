// ABI surface. Replaces the Julia keccak.jl + abi.jl pair:
//   - calldata ENCODING is typed via sol! (selectors computed at compile time,
//     pinned byte-for-byte against `cast` vectors in tests/port.rs),
//   - return-data DECODING stays raw word reads, exactly like the Julia
//     solver: slot0()/ticks() layouts differ between univ3 and Slipstream
//     variants, and offset-addressed words are the chain-validated approach.

use alloy_primitives::{Address, B256, I256, U256};
use alloy_sol_types::sol;
use anyhow::Context;

sol! {
    // ---- 0x Settler actions (ISettlerActions surface we emit) ----

    struct TokenPermissions { address token; uint256 amount; }
    struct PermitTransferFrom { TokenPermissions permitted; uint256 nonce; uint256 deadline; }
    struct AllowedSlippage { address recipient; address buyToken; uint256 minAmountOut; }

    function TRANSFER_FROM(address recipient, PermitTransferFrom permit, bytes sig) external;
    function UNISWAPV3(address recipient, uint256 ppm, bytes path, uint256 amountOutMin) external;
    function UNISWAPV3_VIP(address recipient, PermitTransferFrom permit, bytes path, bytes sig, uint256 amountOutMin) external;
    function UNISWAPV2(address recipient, address sellToken, uint256 ppm, address pool, uint24 swapInfo, uint256 amountOutMin) external;
    function VELODROME(address recipient, uint256 ppm, address pool, uint24 swapInfo, uint256 minAmountOut) external;
    function UNISWAPV4(address recipient, address sellToken, uint256 ppm, bool feeOnTransfer, uint256 hashMul, uint256 hashMod, bytes fills, uint256 amountOutMin) external;
    function EKUBOV3(address recipient, address sellToken, uint256 ppm, bool feeOnTransfer, uint256 hashMul, uint256 hashMod, bytes fills, uint256 amountOutMin) external;
    function BASIC(address sellToken, uint256 ppm, address pool, uint256 offset, bytes data) external;
    // 2026-09-25 release: pays `(balance - expectedAmount) * surplusPpm / 1e6`,
    // capped at `balance * maxPpm / 1e6`, and does nothing at or below
    // `expectedAmount`. With (0, 1e6, 1e6) it returns the whole balance.
    function POSITIVE_SLIPPAGE(address recipient, address token, uint256 expectedAmount, uint256 surplusPpm, uint256 maxPpm) external;
    function NATIVE_CHECK(uint256 deadline, uint256 amount) external;
    function execute(AllowedSlippage slippage, bytes[] actions, bytes32 zid) external;
    function executeWithNativeAuthorization(
        AllowedSlippage slippage,
        bytes[] actions,
        bytes32 zid,
        uint256 authorizationDeadline,
        bytes32 r,
        bytes32 vs
    ) external;

    // A Native-capable Settler build's beneficiary-authorizer identity,
    // verified at startup.
    function nativeAuthorizationSigner() external view returns (address);

    // AllowanceHolder entrypoint.
    function exec(address operator, address token, uint256 amount, address target, bytes data) external;

    // ---- BASIC inner calldata ----
    function withdraw(uint256 amount) external;
    function transfer(address to, uint256 amount) external;

    // ---- execution prerequisites ----
    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

sol! {
    // The v6 tradeRFQT quote has 26 tuple fields, beyond alloy-sol-types'
    // static tuple implementation limit. rfq::validation therefore parses
    // the reviewed ABI words directly and forwards the original calldata.
    function contractRevision() external view returns (uint256);

    // Minimal Native Router/Pool identity surface used only by the startup
    // verifier. Keeping these getters typed avoids treating a matching code
    // hash as sufficient when constructor immutables or live wiring differ.
    function isNativePools(address pool) external view returns (bool);
    function router() external view returns (address);
    function vault() external view returns (address);
    function treasury() external view returns (address);
    function WETH9() external view returns (address);
    function eip712Domain() external view returns (
        bytes1 fields,
        string name,
        string version,
        uint256 chainId,
        address verifyingContract,
        bytes32 salt,
        uint256[] extensions
    );
    function rfqSigners(address signer) external view returns (bool);
    function nonces(uint256 nonce) external view returns (bool);
}

sol! {
    interface IMulticall3 {
        struct Call3 { address target; bool allowFailure; bytes callData; }
        struct Result { bool success; bytes returnData; }
        function aggregate3(Call3[] calldata calls) external payable returns (Result[] memory returnData);
    }

    // Arbitrum-lineage precompile. On this chain `block.number` inside a
    // contract (so Multicall3.getBlockNumber too) is the PARENT chain's
    // number; arbBlockNumber() is the L2 block eth_blockNumber talks about.
    interface IArbSys {
        function arbBlockNumber() external view returns (uint256);
    }

    interface ISettlerRegistry {
        function ownerOf(uint256 id) external view returns (address);
    }

    // Uniswap V4 PoolManager raw storage reads (StateLibrary layout).
    interface IExtsload {
        function extsload(bytes32 slot) external view returns (bytes32);
    }

    interface IUniV2Factory {
        function getPair(address a, address b) external view returns (address);
    }

    interface IUp33V2Factory {
        function getPool(address a, address b, bool stable) external view returns (address);
        function getFee(address pool, bool stable) external view returns (uint256);
    }

    interface IUniV3Factory {
        function getPool(address a, address b, uint24 fee) external view returns (address);
        function feeAmountTickSpacing(uint24 fee) external view returns (int24);
    }

    interface IUp33ClFactory {
        function getPool(address a, address b, int24 tickSpacing) external view returns (address);
        function tickSpacings() external view returns (int24[] memory);
    }

    // Pool state getters. Return layouts differ between the univ3 and
    // Slipstream variants — returns are decoded raw (read_word), so only the
    // selectors matter here.
    interface IPoolState {
        function slot0() external view;
        function liquidity() external view;
        function fee() external view;
        function tickSpacing() external view;
        function getReserves() external view;
        function tickBitmap(int16 word) external view;
        function ticks(int24 tick) external view;
    }
}

// ---- hex ----

pub fn hexbytes(s: &str) -> anyhow::Result<Vec<u8>> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    alloy_primitives::hex::decode(h).with_context(|| format!("bad hex string {s}"))
}

pub fn tohex(b: &[u8]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(b))
}

/// Lowercase 0x-hex of an address — the wire format everywhere (the Julia
/// solver never checksums; Display on Address would).
pub fn addrhex(a: Address) -> String {
    format!("{a:#x}")
}

// ---- raw 32-byte words (return-data reads) ----

pub fn read_word(data: &[u8], off: usize) -> anyhow::Result<U256> {
    let w = data
        .get(off..off + 32)
        .context("return data shorter than expected")?;
    Ok(U256::from_be_slice(w))
}

/// Signed value of a 256-bit word (full sign extension assumed, per ABI).
pub fn untwos(w: U256) -> I256 {
    I256::from_raw(w)
}

/// Sign-extended word as i64 (ticks are int24) — errors on garbage widths.
pub fn word_i64(w: U256) -> anyhow::Result<i64> {
    i64::try_from(untwos(w)).map_err(|_| anyhow::anyhow!("signed word out of i64 range"))
}

pub fn word_address(data: &[u8], off: usize) -> anyhow::Result<Address> {
    let w = data
        .get(off..off + 32)
        .context("return data shorter than expected")?;
    Ok(Address::from_word(B256::from_slice(w)))
}

// ---- packed (big-endian, exact width) ----

pub fn be_bytes(x: U256, n: usize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        n <= 32 && (n == 32 || x >> (8 * n) == U256::ZERO),
        "value does not fit in {n} bytes"
    );
    Ok(x.to_be_bytes::<32>()[32 - n..].to_vec())
}

/// `UNISWAPV4` as builds released since November 2026 take it: the V4 fork
/// is named in the action, so its selector differs from `UNISWAPV4Call`'s.
pub mod forked_v4 {
    alloy_sol_types::sol! {
        function UNISWAPV4(address recipient, address sellToken, uint256 ppm, uint8 forkId, bool feeOnTransfer, uint256 hashMul, uint256 hashMod, bytes fills, uint256 amountOutMin) external;
    }
}
