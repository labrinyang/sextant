// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Ground truth for the Sheriff (Algebra Integral) simulator.
//
// The standard quoter trick: drive the pool's real swap() and revert inside the
// pay-in callback, so the pool's own math (including the plugin's beforeSwap
// dynamic fee) produces the deltas without anyone holding tokens. Whatever this
// returns IS what the pool would do at this block — the number sim_v3 must match
// to the wei.
//
// Algebra's swap has the same selector/shape as UniswapV3's; only the callback
// name differs (algebraSwapCallback). That is exactly why 0x-settler routes
// Sheriff through its univ3-fork path with just a different callback selector.

interface IAlgebraPool {
    function swap(
        address recipient,
        bool zeroToOne,
        int256 amountRequired,
        uint160 limitSqrtPrice,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1);

    function globalState()
        external
        view
        returns (uint160 price, int24 tick, uint16 lastFee, uint8 pluginConfig, uint16 communityFee, bool unlocked);

    function liquidity() external view returns (uint128);

    function fee() external view returns (uint16);

    function tickSpacing() external view returns (int24);

    function nextTickGlobal() external view returns (int24);

    function prevTickGlobal() external view returns (int24);

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

contract AlgebraQuoter {
    uint160 internal constant MIN_SQRT = 4295128739;
    uint160 internal constant MAX_SQRT = 1461446703485210103287273052203988822378723970342;

    /// Exact-input quote. Returns the signed deltas the pool computed
    /// (positive = owed to the pool, negative = paid out) PLUS the pool's own
    /// price before the call and the price it had reached by callback time.
    /// priceBefore vs globalState() answers "did the swap start where I read?";
    /// priceAfter pins which price curve the pool actually walked.
    function quoteExactIn(address pool, bool zeroToOne, int256 amountIn)
        external
        returns (int256 amount0, int256 amount1, uint256 priceBefore, uint256 priceAfter, uint256 baseFeeBefore)
    {
        (priceBefore,,,,,) = IAlgebraPool(pool).globalState();
        baseFeeBefore = IAlgebraPool(pool).fee();
        uint160 limit = zeroToOne ? MIN_SQRT + 1 : MAX_SQRT - 1;
        _probe = pool;
        try IAlgebraPool(pool).swap(address(this), zeroToOne, amountIn, limit, "") {
            revert("swap did not call back");
        } catch (bytes memory reason) {
            (amount0, amount1, priceAfter) = decodeDeltas(reason);
        }
        _probe = address(0);
    }

    address private transient _probe;

    function algebraSwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata) external view {
        (uint160 priceNow,,,,,) = IAlgebraPool(_probe).globalState();
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, amount0Delta)
            mstore(add(p, 0x20), amount1Delta)
            mstore(add(p, 0x40), priceNow)
            revert(p, 0x60)
        }
    }

    function decodeDeltas(bytes memory reason) private pure returns (int256 a0, int256 a1, uint256 pAfter) {
        require(reason.length == 0x60, "unexpected revert payload");
        assembly ("memory-safe") {
            a0 := mload(add(reason, 0x20))
            a1 := mload(add(reason, 0x40))
            pAfter := mload(add(reason, 0x60))
        }
    }

    /// Everything the Rust simulator needs to reproduce a swap, read atomically
    /// in one call so the state can never straddle two blocks.
    /// Returns the pool scalars plus `steps` initialized ticks in EACH direction
    /// walked through the prev/next linked list, ascending.
    function snapshot(address pool, uint256 steps)
        external
        view
        returns (
            uint160 price,
            int24 tick,
            uint16 currentFee,
            uint16 lastFee,
            uint16 communityFee,
            uint128 liq,
            int24 spacing,
            int24[] memory ticksOut,
            int128[] memory netOut
        )
    {
        IAlgebraPool p = IAlgebraPool(pool);
        (price, tick,, , communityFee,) = p.globalState();
        (, , lastFee, , ,) = p.globalState();
        currentFee = p.fee();
        liq = p.liquidity();
        spacing = p.tickSpacing();

        int24[] memory down = new int24[](steps);
        int128[] memory downNet = new int128[](steps);
        uint256 nd;
        int24 cur = p.prevTickGlobal();
        for (uint256 i = 0; i < steps; i++) {
            (, int128 net, int24 prev,,,) = p.ticks(cur);
            down[nd] = cur;
            downNet[nd] = net;
            nd++;
            if (prev == cur) break; // MIN_TICK sentinel points at itself
            cur = prev;
        }

        int24[] memory up = new int24[](steps);
        int128[] memory upNet = new int128[](steps);
        uint256 nu;
        cur = p.nextTickGlobal();
        for (uint256 i = 0; i < steps; i++) {
            (, int128 net,, int24 next,,) = p.ticks(cur);
            up[nu] = cur;
            upNet[nu] = net;
            nu++;
            if (next == cur) break; // MAX_TICK sentinel
            cur = next;
        }

        ticksOut = new int24[](nd + nu);
        netOut = new int128[](nd + nu);
        for (uint256 i = 0; i < nd; i++) {
            ticksOut[i] = down[nd - 1 - i]; // reverse: ascending
            netOut[i] = downNet[nd - 1 - i];
        }
        for (uint256 i = 0; i < nu; i++) {
            ticksOut[nd + i] = up[i];
            netOut[nd + i] = upNet[i];
        }
    }
}
