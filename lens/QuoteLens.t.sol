// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {QuoteLens} from "./QuoteLens.sol";

contract MockPoolManager {
    mapping(bytes32 => bytes32) internal values;

    function set(bytes32 slot, bytes32 value) external {
        values[slot] = value;
    }

    function extsload(bytes32) external pure returns (bytes32) {
        revert("single-slot read");
    }

    function extsload(bytes32[] calldata slots) external view returns (bytes32[] memory out) {
        out = new bytes32[](slots.length);
        for (uint256 i = 0; i < slots.length; i++) {
            out[i] = values[slots[i]];
        }
    }
}

contract MockV2Pool {
    uint256 internal immutable RESERVE0;
    uint256 internal immutable RESERVE1;

    constructor(uint256 r0, uint256 r1) {
        RESERVE0 = r0;
        RESERVE1 = r1;
    }

    function getReserves() external view returns (uint256, uint256) {
        return (RESERVE0, RESERVE1);
    }
}

contract QuoteLensHarness is QuoteLens {
    function queryOutput(uint16 words, uint16 maxTicksPerPool, Query[] calldata queries)
        external
        view
        returns (uint256[] memory out)
    {
        out = new uint256[](worstCaseQueryResponseWords(words, maxTicksPerPool, queries));
        uint256 n = readQueries(queries, words, maxTicksPerPool, out, 0);
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    function responseWords(uint16 words, uint16 maxTicksPerPool, Query[] calldata queries)
        external
        pure
        returns (uint256)
    {
        return worstCaseQueryResponseWords(words, maxTicksPerPool, queries);
    }

    function scalarCount(Query[] calldata queries) external view returns (uint256) {
        return readV4Scalars(queries).length;
    }

    function storageSlot(int256 key, bytes32 base, uint256 offset)
        external
        pure
        returns (bytes32)
    {
        return mapSlot(key, base, offset);
    }
}

contract QuoteLensTest {
    function testV4BatchesPreserveExactMixedQueryLayout() external {
        MockPoolManager manager = new MockPoolManager();
        MockV2Pool v2 = new MockV2Pool(7001, 7002);
        QuoteLensHarness lens = new QuoteLensHarness();

        bytes32 first = bytes32(uint256(0x100));
        bytes32 dead = bytes32(uint256(0x200));
        bytes32 second = bytes32(uint256(0x300));
        bytes32 firstState = slot0(2570, 3000);
        bytes32 secondState = slot0(-1, 500);
        manager.set(first, firstState);
        manager.set(bytes32(uint256(first) + 3), bytes32(uint256(11)));
        manager.set(dead, bytes32(0));
        manager.set(bytes32(uint256(dead) + 3), bytes32(uint256(12)));
        manager.set(second, secondState);
        manager.set(bytes32(uint256(second) + 3), bytes32(uint256(13)));

        uint256 firstBitmap0 = (1 << 0) | (1 << 2);
        uint256 firstBitmap1 = 1 << 1;
        manager.set(lens.storageSlot(0, first, 5), bytes32(firstBitmap0));
        manager.set(lens.storageSlot(1, first, 5), bytes32(firstBitmap1));
        manager.set(lens.storageSlot(2, first, 5), bytes32(0));
        manager.set(lens.storageSlot(0, first, 4), bytes32(uint256(101)));
        manager.set(lens.storageSlot(20, first, 4), bytes32(uint256(102)));
        manager.set(lens.storageSlot(2570, first, 4), bytes32(uint256(103)));

        uint256 secondBitmap0 = 1 << 255;
        uint256 secondBitmap1 = (1 << 0) | (1 << 5);
        uint256 secondBitmap2 = 1;
        manager.set(lens.storageSlot(-2, second, 5), bytes32(secondBitmap0));
        manager.set(lens.storageSlot(-1, second, 5), bytes32(secondBitmap1));
        manager.set(lens.storageSlot(0, second, 5), bytes32(secondBitmap2));
        manager.set(lens.storageSlot(-2570, second, 4), bytes32(uint256(201)));
        manager.set(lens.storageSlot(-2560, second, 4), bytes32(uint256(202)));
        manager.set(lens.storageSlot(-2510, second, 4), bytes32(uint256(203)));
        manager.set(lens.storageSlot(0, second, 4), bytes32(uint256(204)));

        QuoteLens.Query[] memory queries = new QuoteLens.Query[](4);
        queries[0] = query(1, address(manager), first, 10, 3000);
        queries[1] = query(2, address(v2), bytes32(0), 0, 0);
        queries[2] = query(1, address(manager), dead, 10, 3000);
        queries[3] = query(1, address(manager), second, 10, 500);

        require(lens.scalarCount(queries) == 6, "scalar count");

        uint256[] memory actual = lens.queryOutput(1, 1024, queries);
        uint256[] memory expected = new uint256[](25);
        expected[0] = uint256(firstState);
        expected[1] = 11;
        expected[2] = 1;
        expected[3] = firstBitmap0;
        expected[4] = firstBitmap1;
        expected[5] = 0;
        expected[6] = 101;
        expected[7] = 102;
        expected[8] = 103;
        expected[9] = 1;
        expected[10] = 7001;
        expected[11] = 7002;
        expected[12] = 0;
        expected[13] = 12;
        expected[14] = 0;
        expected[15] = uint256(secondState);
        expected[16] = 13;
        expected[17] = 1;
        expected[18] = secondBitmap0;
        expected[19] = secondBitmap1;
        expected[20] = secondBitmap2;
        expected[21] = 201;
        expected[22] = 202;
        expected[23] = 203;
        expected[24] = 204;
        require(keccak256(abi.encode(actual)) == keccak256(abi.encode(expected)), "output words");
    }

    function testV4BatchSkipsDependentCallsWithoutLivePools() external {
        MockPoolManager manager = new MockPoolManager();
        QuoteLensHarness lens = new QuoteLensHarness();
        bytes32 dead = bytes32(uint256(0x400));
        manager.set(dead, bytes32(0));
        manager.set(bytes32(uint256(dead) + 3), bytes32(uint256(99)));

        QuoteLens.Query[] memory queries = new QuoteLens.Query[](1);
        queries[0] = query(1, address(manager), dead, 10, 3000);
        require(lens.scalarCount(queries) == 2, "scalar count");

        uint256[] memory actual = lens.queryOutput(16, 1024, queries);
        require(actual.length == 3, "output length");
        require(actual[0] == 0 && actual[1] == 99 && actual[2] == 0, "dead output");
    }

    function testV4BatchSkipsPoolManagerWithoutV4Queries() external {
        QuoteLensHarness lens = new QuoteLensHarness();
        MockV2Pool v2 = new MockV2Pool(41, 42);
        QuoteLens.Query[] memory queries = new QuoteLens.Query[](1);
        queries[0] = query(2, address(v2), bytes32(0), 0, 0);

        require(lens.scalarCount(queries) == 0, "scalar count");
        uint256[] memory actual = lens.queryOutput(16, 1024, queries);
        require(actual.length == 3, "output length");
        require(actual[0] == 1 && actual[1] == 41 && actual[2] == 42, "v2 output");
    }

    function testResponseBudgetAcceptsW8192AlgebraAtExactBoundary() external {
        QuoteLensHarness lens = new QuoteLensHarness();
        QuoteLens.Query[] memory queries = new QuoteLens.Query[](1);
        queries[0] = query(3, address(0), bytes32(0), 0, 0);

        require(lens.responseWords(8192, 1024, queries) == 32_781, "algebra boundary");
    }

    function testResponseBudgetCoversTwoDenseDefaultV3Queries() external {
        QuoteLensHarness lens = new QuoteLensHarness();
        QuoteLens.Query[] memory queries = new QuoteLens.Query[](2);
        queries[0] = query(0, address(1), bytes32(0), 10, 0);
        queries[1] = query(0, address(2), bytes32(0), 10, 0);

        require(lens.responseWords(16, 1024, queries) == 2124, "dense v3 budget");
    }

    function testV4TickBudgetFailureIsExplicit() external {
        MockPoolManager manager = new MockPoolManager();
        QuoteLensHarness lens = new QuoteLensHarness();
        bytes32 stateSlot = bytes32(uint256(0x500));
        manager.set(stateSlot, slot0(0, 3000));
        manager.set(bytes32(uint256(stateSlot) + 3), bytes32(uint256(1)));
        manager.set(lens.storageSlot(-1, stateSlot, 5), bytes32(0));
        manager.set(lens.storageSlot(0, stateSlot, 5), bytes32(uint256(7)));
        manager.set(lens.storageSlot(1, stateSlot, 5), bytes32(0));

        QuoteLens.Query[] memory queries = new QuoteLens.Query[](1);
        queries[0] = query(1, address(manager), stateSlot, 10, 3000);
        try lens.queryOutput(1, 2, queries) returns (uint256[] memory) {
            revert("tick budget accepted");
        } catch (bytes memory reason) {
            require(selector(reason) == QuoteLens.TickBudgetExceeded.selector, "tick error");
        }
    }

    function slot0(int24 tick, uint24 fee) internal pure returns (bytes32) {
        return bytes32(uint256(1) | (uint256(uint24(tick)) << 160) | (uint256(fee) << 208));
    }

    function query(
        uint8 kind,
        address target,
        bytes32 slot,
        int24 spacing,
        uint24 fee
    ) internal pure returns (QuoteLens.Query memory) {
        return QuoteLens.Query({
            kind: kind,
            flags: 0,
            target: target,
            slot: slot,
            spacing: spacing,
            fee: fee
        });
    }

    function selector(bytes memory reason) internal pure returns (bytes4 value) {
        require(reason.length >= 4, "missing selector");
        assembly ("memory-safe") {
            value := mload(add(reason, 0x20))
        }
    }
}
