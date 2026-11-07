// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// The solver's bulk state lens. Injected at a pseudo-address via eth_call's
// state-override param (never deployed), each invocation fetches every
// directly-readable storage word the quote pipeline needs — pool scalars, the
// ±W tickBitmap window around the current tick, and liquidityNet for every
// initialized tick inside it — for one bounded query chunk, atomic in one
// block. Large universes use concurrent chunks pinned to one canonical block
// hash. The old multicall path needed three dependent rounds (core state →
// bitmaps → ticks); here that dependency chain runs in-EVM. Sheriff's
// state-changing beforeSwap fee reads run separately, pinned to the same block.
//
// Everything returns as raw uint256 words (layout documented in
// solver-rs/src/lens.rs, the only consumer): forwarding words instead of
// decoded tuples keeps every fork's ABI quirks (extra slot0 fields, packed
// v4 storage) out of the lens, and lets the solver keep the exact word
// decoders it validated against the multicall rounds.
//
// Regenerate QuoteLens.bin with lens/build.sh after editing.

interface IV3Pool {
    // declared with only the leading fields every routed fork shares; call2
    // reads raw return words, so longer tuples (univ3's 7-field slot0, …)
    // decode nowhere and can't revert the lens
    function slot0() external view returns (uint160 sqrtPriceX96, int24 tick);
    function liquidity() external view returns (uint128);
    function fee() external view returns (uint24);
    function tickSpacing() external view returns (int24);
    function getReserves() external view returns (uint256 reserve0, uint256 reserve1);
    function tickBitmap(int16 word) external view returns (uint256);
    function ticks(int24 tick) external view returns (uint128 liquidityGross, int128 liquidityNet);
}

interface IAlgebraPool {
    function globalState()
        external
        view
        returns (uint160 price, int24 tick, uint16 lastFee, uint8 pluginConfig, uint16 communityFee, bool unlocked);
    function liquidity() external view returns (uint128);
    function fee() external view returns (uint16);
    function tickSpacing() external view returns (int24);
    function plugin() external view returns (address);
    function prevTickGlobal() external view returns (int24);
    function nextTickGlobal() external view returns (int24);
    function ticks(int24 tick)
        external
        view
        returns (
            uint256 liquidityTotal,
            int128 liquidityDelta,
            int24 prevTick,
            int24 nextTick,
            uint256 outerFeeGrowth0Token,
            uint256 outerFeeGrowth1Token
        );
}

interface IUp33V2Factory {
    function getFee(address pool, bool stable) external view returns (uint256);
}

interface IPoolManager {
    function extsload(bytes32[] calldata slots) external view returns (bytes32[] memory);
}

contract QuoteLens {
    uint8 internal constant KIND_V3 = 0;
    uint8 internal constant KIND_V4 = 1;
    uint8 internal constant KIND_V2 = 2;
    uint8 internal constant KIND_ALGEBRA = 3;
    uint8 internal constant READ_FEE = 1; // v3: fee() (UP33 CL) · v2: factory getFee (UP33 v2)
    uint8 internal constant READ_SPACING = 2; // v3: tickSpacing() (Pancake-lineage clones)
    uint256 internal constant MAX_OUTPUT_WORDS = 32_783;

    address internal constant UP33_V2_FACTORY = 0xFA5429AEBa338BEa2BFcc1b9a889862Ee395bc28;

    error InvalidQuery(uint8 kind, uint8 flags);
    error ResponseBudgetExceeded(uint256 requested, uint256 limit);
    error TickBudgetExceeded(address pool, uint256 initialized, uint256 limit);

    struct Query {
        uint8 kind;
        uint8 flags;
        address target; // pool (v3/v2) · PoolManager (v4)
        bytes32 slot; // v4: the pool's state slot in PoolManager storage
        int24 spacing; // v3 static / v4 key tickSpacing (clones read their own)
        uint24 fee; // v4: key fee (carried for the solver; not judged here)
    }

    function peek(
        uint16 words,
        uint16 maxTicksPerPool,
        Query[] calldata qs
    )
        external
        view
        returns (uint256[] memory out)
    {
        out = new uint256[](worstCaseQueryResponseWords(words, maxTicksPerPool, qs));
        // Rust resolves one canonical (number, hash) first and pins every Lens
        // chunk to that EIP-1898 hash. Keeping chain identity and Settler
        // discovery outside this injected bytecode makes the state reader
        // portable across chains instead of depending on Robinhood contracts.
        uint256 n = readQueries(qs, words, maxTicksPerPool, out, 0);
        assembly ("memory-safe") {
            mstore(out, n) // truncate to what was written
        }
    }

    function worstCaseQueryResponseWords(
        uint16 words,
        uint16 maxTicksPerPool,
        Query[] calldata qs
    ) internal pure returns (uint256 reserved) {
        uint256 bitmapWords = uint256(words) * 2 + 1;
        for (uint256 i = 0; i < qs.length; i++) {
            Query calldata q = qs[i];
            uint256 frame;
            if (q.kind == KIND_V2) {
                if (q.flags > READ_FEE) revert InvalidQuery(q.kind, q.flags);
                frame = 3 + (q.flags & READ_FEE == 0 ? 0 : 1);
            } else if (q.kind == KIND_ALGEBRA) {
                if (q.flags != 0) revert InvalidQuery(q.kind, q.flags);
                frame = 13 + uint256(words) * 4;
            } else if (q.kind == KIND_V4) {
                if (q.flags != 0) revert InvalidQuery(q.kind, q.flags);
                frame = 3 + bitmapWords + uint256(maxTicksPerPool);
            } else if (q.kind == KIND_V3) {
                if (q.flags > (READ_FEE | READ_SPACING)) {
                    revert InvalidQuery(q.kind, q.flags);
                }
                frame = 5 + bitmapWords + uint256(maxTicksPerPool);
                if (q.flags & READ_FEE != 0) frame++;
                if (q.flags & READ_SPACING != 0) frame++;
            } else {
                revert InvalidQuery(q.kind, q.flags);
            }
            reserved = reserveResponseWords(reserved, frame);
        }
    }

    function reserveResponseWords(uint256 reserved, uint256 frame)
        internal
        pure
        returns (uint256)
    {
        if (frame > MAX_OUTPUT_WORDS - reserved) {
            revert ResponseBudgetExceeded(reserved + frame, MAX_OUTPUT_WORDS);
        }
        return reserved + frame;
    }

    /// Every v4 pool's slot0 and liquidity words, in query order. All current
    /// v4 queries share one PoolManager, so the scalar set takes one call.
    function readV4Scalars(Query[] calldata qs) internal view returns (bytes32[] memory values) {
        uint256 count;
        address manager;
        for (uint256 i = 0; i < qs.length; i++) {
            if (qs[i].kind == KIND_V4) {
                if (count == 0) manager = qs[i].target;
                count++;
            }
        }
        bytes32[] memory slots = new bytes32[](count * 2);
        uint256 at;
        for (uint256 i = 0; i < qs.length; i++) {
            if (qs[i].kind == KIND_V4) {
                slots[at++] = qs[i].slot;
                slots[at++] = bytes32(uint256(qs[i].slot) + 3);
            }
        }
        if (count == 0) return slots;
        return IPoolManager(manager).extsload(slots);
    }

    function readQueries(
        Query[] calldata qs,
        uint16 words,
        uint16 maxTicksPerPool,
        uint256[] memory out,
        uint256 n
    ) internal view returns (uint256) {
        bytes32[] memory v4Scalars = readV4Scalars(qs);
        uint256 v4At;
        for (uint256 i = 0; i < qs.length; i++) {
            if (qs[i].kind == KIND_V4) {
                bytes32 slot0 = v4Scalars[v4At++];
                bytes32 liquidity = v4Scalars[v4At++];
                n = readV4(qs[i], words, maxTicksPerPool, out, n, slot0, liquidity);
            } else {
                n = read(qs[i], words, maxTicksPerPool, out, n);
            }
        }
        return n;
    }

    function read(
        Query calldata q,
        uint16 words,
        uint16 maxTicksPerPool,
        uint256[] memory out,
        uint256 n
    ) internal view returns (uint256) {
        if (q.kind == KIND_V2) {
            return readV2(q, out, n);
        }
        if (q.kind == KIND_ALGEBRA) {
            return readAlgebra(q, words, out, n);
        }
        int256 spacing = q.spacing;
        (bool ok, uint256 sqrtW, uint256 tickW) = call2(q.target, abi.encodeCall(IV3Pool.slot0, ()), 64);
        (bool okL, uint256 liqW,) = call2(q.target, abi.encodeCall(IV3Pool.liquidity, ()), 32);
        ok = ok && okL;
        uint256 feeW;
        uint256 spacingW;
        if (q.flags & READ_FEE != 0) {
            bool okF;
            (okF, feeW,) = call2(q.target, abi.encodeCall(IV3Pool.fee, ()), 32);
            ok = ok && okF;
        }
        if (q.flags & READ_SPACING != 0) {
            bool okS;
            (okS, spacingW,) = call2(q.target, abi.encodeCall(IV3Pool.tickSpacing, ()), 32);
            ok = ok && okS;
            spacing = int256(spacingW); // ABI already sign-extended the int24
        }
        out[n++] = ok ? 1 : 0;
        if (!ok) {
            return n;
        }
        out[n++] = sqrtW;
        out[n++] = tickW;
        out[n++] = liqW;
        if (q.flags & READ_FEE != 0) out[n++] = feeW;
        if (q.flags & READ_SPACING != 0) out[n++] = spacingW;
        bool live = sqrtW != 0;
        out[n++] = live ? 1 : 0;
        if (!live) {
            return n;
        }
        require(spacing > 0, "spacing");
        return window(q, words, maxTicksPerPool, spacing, int256(tickW), out, n);
    }

    function readV4(
        Query calldata q,
        uint16 words,
        uint16 maxTicksPerPool,
        uint256[] memory out,
        uint256 n,
        bytes32 slot0,
        bytes32 liquidity
    ) internal view returns (uint256) {
        out[n++] = uint256(slot0);
        out[n++] = uint256(liquidity);
        bool live = v4Live(q, slot0, liquidity);
        out[n++] = live ? 1 : 0;
        if (!live) return n;

        require(q.spacing > 0, "spacing");
        int256 tick = int24(uint24(uint256(slot0) >> 160));
        return windowV4(q, words, maxTicksPerPool, q.spacing, tick, out, n);
    }

    /// One live v4 pool takes two bounded PoolManager calls: its complete
    /// bitmap window, then exactly the initialized ticks revealed by it.
    function windowV4(
        Query calldata q,
        uint16 words,
        uint16 maxTicksPerPool,
        int256 spacing,
        int256 tick,
        uint256[] memory out,
        uint256 n
    ) internal view returns (uint256) {
        int256 wc = floorDiv(floorDiv(tick, spacing), 256);
        int256 lo = wc - int256(uint256(words));
        uint256 count = uint256(words) * 2 + 1;
        bytes32[] memory slots = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            slots[i] = mapSlot(lo + int256(i), q.slot, 5);
        }
        bytes32[] memory bitmaps = IPoolManager(q.target).extsload(slots);
        uint256 tickCount;
        for (uint256 i = 0; i < count; i++) {
            uint256 bitmap = uint256(bitmaps[i]);
            out[n++] = bitmap;
            tickCount += popcount(bitmap);
        }
        if (tickCount > maxTicksPerPool) {
            revert TickBudgetExceeded(q.target, tickCount, maxTicksPerPool);
        }
        if (tickCount == 0) return n;

        slots = new bytes32[](tickCount);
        uint256 at;
        for (uint256 i = 0; i < count; i++) {
            int256 w = lo + int256(i);
            uint256 bitmap = uint256(bitmaps[i]);
            uint256 bit;
            while (bitmap != 0) {
                if (bitmap & 1 != 0) {
                    int256 t = (w * 256 + int256(bit)) * spacing;
                    slots[at++] = mapSlot(t, q.slot, 4);
                }
                bitmap >>= 1;
                bit++;
            }
        }
        bytes32[] memory ticks = IPoolManager(q.target).extsload(slots);
        for (uint256 i = 0; i < ticks.length; i++) {
            out[n++] = uint256(ticks[i]);
        }
        return n;
    }

    // Live = initialized with in-range liquidity, nothing more: fee facts
    // (protocol fee, static/dynamic lpFee) are judged by the solver from the
    // slot0 word already in the stream — the lens carries state, not policy.
    function v4Live(Query calldata, bytes32 slot0, bytes32 liquidity)
        internal
        pure
        returns (bool)
    {
        return uint160(uint256(slot0)) != 0 && uint128(uint256(liquidity)) != 0;
    }

    function popcount(uint256 word) internal pure returns (uint256 count) {
        while (word != 0) {
            word &= word - 1;
            count++;
        }
    }

    /// Algebra has no bitmap: initialized ticks form a doubly-linked list.
    /// Stream: [ok, sqrt, tick, liquidity, baseFee, lastFee, pluginConfig,
    /// spacing, plugin, pluginCodehash, live],
    /// then [downCount, (tick, liquidityNet)*, upCount, (tick, liquidityNet)*].
    /// Both runs are ascending; each contains at most `words` ticks.
    function readAlgebra(Query calldata q, uint16 words, uint256[] memory out, uint256 n)
        internal
        view
        returns (uint256)
    {
        (bool ok, uint256 sqrtW, uint256 tickW, uint256 lastFeeW, uint256 configW) =
            call4(q.target, abi.encodeCall(IAlgebraPool.globalState, ()), 128);
        (bool okL, uint256 liqW,) = call2(q.target, abi.encodeCall(IAlgebraPool.liquidity, ()), 32);
        (bool okF, uint256 feeW,) = call2(q.target, abi.encodeCall(IAlgebraPool.fee, ()), 32);
        (bool okS, uint256 spacingW,) = call2(q.target, abi.encodeCall(IAlgebraPool.tickSpacing, ()), 32);
        (bool okP, uint256 pluginW,) = call2(q.target, abi.encodeCall(IAlgebraPool.plugin, ()), 32);
        ok = ok && okL && okF && okS && okP;
        out[n++] = ok ? 1 : 0;
        if (!ok) return n;

        out[n++] = sqrtW;
        out[n++] = tickW;
        out[n++] = liqW;
        out[n++] = feeW;
        out[n++] = lastFeeW;
        out[n++] = configW;
        out[n++] = spacingW;
        out[n++] = pluginW;
        out[n++] = uint256(address(uint160(pluginW)).codehash);
        out[n++] = sqrtW == 0 ? 0 : 1;
        if (sqrtW == 0) return n;

        IAlgebraPool pool = IAlgebraPool(q.target);
        uint256 countAt = n++;
        uint256 first = n;
        int24 cur = pool.prevTickGlobal();
        for (uint256 i = 0; i < words; i++) {
            (, int128 net, int24 prev,,,) = pool.ticks(cur);
            out[n++] = uint256(int256(cur));
            out[n++] = uint256(int256(net));
            if (prev == cur) break; // MIN_TICK sentinel
            cur = prev;
        }
        uint256 count = (n - first) / 2;
        out[countAt] = count;
        for (uint256 i = 0; i < count / 2; i++) {
            uint256 j = count - 1 - i;
            (out[first + 2 * i], out[first + 2 * j]) = (out[first + 2 * j], out[first + 2 * i]);
            (out[first + 2 * i + 1], out[first + 2 * j + 1]) =
                (out[first + 2 * j + 1], out[first + 2 * i + 1]);
        }

        countAt = n++;
        first = n;
        cur = pool.nextTickGlobal();
        for (uint256 i = 0; i < words; i++) {
            (, int128 net,, int24 next,,) = pool.ticks(cur);
            out[n++] = uint256(int256(cur));
            out[n++] = uint256(int256(net));
            if (next == cur) break; // MAX_TICK sentinel
            cur = next;
        }
        out[countAt] = (n - first) / 2;
        return n;
    }

    /// The v3 R4+R5 fetch for one live pool: ±words bitmap words around the
    /// current tick, then the tick word for every set bit, in (word asc,
    /// bit asc) order — the solver reconstructs tick positions from the
    /// bitmap words it just received, so no framing is needed. V4 windows
    /// take the per-live-pool batched path above.
    function window(
        Query calldata q,
        uint16 words,
        uint16 maxTicksPerPool,
        int256 spacing,
        int256 tick,
        uint256[] memory out,
        uint256 n
    ) internal view returns (uint256) {
        int256 wc = floorDiv(floorDiv(tick, spacing), 256);
        int256 lo = wc - int256(uint256(words));
        int256 hi = wc + int256(uint256(words));
        uint256 first = n;
        uint256 tickCount;
        for (int256 w = lo; w <= hi; w++) {
            uint256 bitmap = IV3Pool(q.target).tickBitmap(int16(w));
            out[n++] = bitmap;
            tickCount += popcount(bitmap);
        }
        if (tickCount > maxTicksPerPool) {
            revert TickBudgetExceeded(q.target, tickCount, maxTicksPerPool);
        }
        for (int256 w = lo; w <= hi; w++) {
            uint256 bm = out[first++];
            uint256 bit = 0;
            while (bm != 0) {
                if (bm & 1 != 0) {
                    int256 t = (w * 256 + int256(bit)) * spacing;
                    out[n++] = netWord(q.target, t);
                }
                bm >>= 1;
                bit++;
            }
        }
        return n;
    }

    function readV2(Query calldata q, uint256[] memory out, uint256 n) internal view returns (uint256) {
        (bool ok, uint256 r0, uint256 r1) = call2(q.target, abi.encodeCall(IV3Pool.getReserves, ()), 64);
        uint256 feeW;
        if (ok && q.flags & READ_FEE != 0) {
            (ok, feeW,) = call2(UP33_V2_FACTORY, abi.encodeCall(IUp33V2Factory.getFee, (q.target, false)), 32);
        }
        out[n++] = ok ? 1 : 0;
        if (!ok) {
            return n;
        }
        out[n++] = r0;
        out[n++] = r1;
        if (q.flags & READ_FEE != 0) out[n++] = feeW;
        return n;
    }

    /// ticks(t) with only liquidityNet kept, re-encoded as the sign-extended
    /// ABI word the solver's untwos() decoder expects.
    function netWord(address pool, int256 t) internal view returns (uint256) {
        (, int128 net) = IV3Pool(pool).ticks(int24(t));
        return uint256(int256(net));
    }

    /// Storage slot of mapping entry `key` under `base + offset` — v4
    /// Pool.State: offset 4 = ticks, offset 5 = tickBitmap.
    function mapSlot(int256 key, bytes32 base, uint256 offset) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, uint256(base) + offset));
    }

    /// Floor division for positive divisors — matches Rust's div_euclid, and
    /// Uniswap's own compressed-tick rounding.
    function floorDiv(int256 a, int256 b) internal pure returns (int256) {
        int256 q = a / b;
        return (a % b != 0 && a < 0) ? q - 1 : q;
    }

    /// staticcall reporting the first two raw return words; ok requires
    /// success and at least `min` bytes of return data. Used for the per-pool
    /// core reads, where a revert means "drop this pool", never "fail the
    /// snapshot" — bitmap/tick reads on a live pool use checked calls instead
    /// (a revert there is a broken invariant and should fail loudly).
    function call2(address target, bytes memory data, uint256 min)
        internal
        view
        returns (bool ok, uint256 w0, uint256 w1)
    {
        (bool s, bytes memory r) = target.staticcall(data);
        ok = s && r.length >= min;
        if (ok) {
            assembly ("memory-safe") {
                w0 := mload(add(r, 0x20))
                w1 := mload(add(r, 0x40))
            }
        }
    }

    /// Four-word sibling used for Algebra's globalState tuple.
    function call4(address target, bytes memory data, uint256 min)
        internal
        view
        returns (bool ok, uint256 w0, uint256 w1, uint256 w2, uint256 w3)
    {
        (bool s, bytes memory r) = target.staticcall(data);
        ok = s && r.length >= min;
        if (ok) {
            assembly ("memory-safe") {
                w0 := mload(add(r, 0x20))
                w1 := mload(add(r, 0x40))
                w2 := mload(add(r, 0x60))
                w3 := mload(add(r, 0x80))
            }
        }
    }
}
