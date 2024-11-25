import { coreHash, hashH, prf } from './hash.js';
import {
  addrToByte,
  setChainAddr,
  setHashAddr,
  setKeyAndMask,
  setLTreeAddr,
  setOTSAddr,
  setTreeHeight,
  setTreeIndex,
  setType,
  toByteLittleEndian,
} from './helper.js';

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} seed
 * @param {Uint8Array} skSeed
 * @param {Uint32Array[number]} n
 * @param {Uint32Array} addr
 */
export function getSeed(hashFunction, seed, skSeed, n, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const bytes = new Uint8Array(32);

  setChainAddr(addr, 0);
  setHashAddr(addr, 0);
  setKeyAndMask(addr, 0);

  addrToByte(bytes, addr);
  prf(hashFunction, seed, bytes, skSeed, n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} outSeeds
 * @param {Uint8Array} inSeeds
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} len
 */
export function expandSeed(hashFunction, outSeeds, inSeeds, n, len) {
  const ctr = new Uint8Array(32);
  for (let i = 0; i < len; i++) {
    toByteLittleEndian(ctr, i, 32);
    prf(hashFunction, outSeeds.subarray(i * n, i * n + n), ctr, inSeeds, n);
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 */
export function hashF(hashFunction, out, input, pubSeed, addr, n) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const buf = new Uint8Array(n);
  const key = new Uint8Array(n);
  const bitMask = new Uint8Array(n);
  const byteAddr = new Uint8Array(32);

  setKeyAndMask(addr, 0);
  addrToByte(byteAddr, addr);
  prf(hashFunction, key, byteAddr, pubSeed, n);

  setKeyAndMask(addr, 1);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask, byteAddr, pubSeed, n);

  for (let i = 0; i < n; i++) {
    buf.set([input[i] ^ bitMask[i]], i);
  }
  coreHash(hashFunction, out, 0, key, n, buf, n, n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint32Array[number]} start
 * @param {Uint32Array[number]} steps
 * @param {WOTSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function genChain(hashFunction, out, input, start, steps, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  for (let i = 0; i < params.n; i++) {
    out.set([input[i]], i);
  }

  for (let i = start; i < start + steps && i < params.w; i++) {
    setHashAddr(addr, i);
    hashF(hashFunction, out, out, pubSeed, addr, params.n);
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} pk
 * @param {Uint8Array} sk
 * @param {WOTSParams} wOTSParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function wOTSPKGen(hashFunction, pk, sk, wOTSParams, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  expandSeed(hashFunction, pk, sk, wOTSParams.n, wOTSParams.len);
  for (let i = 0; i < wOTSParams.len; i++) {
    setChainAddr(addr, i);
    const pkStartOffset = i * wOTSParams.n;
    genChain(
      hashFunction,
      pk.subarray(pkStartOffset, pkStartOffset + wOTSParams.n),
      pk.subarray(pkStartOffset, pkStartOffset + wOTSParams.n),
      0,
      wOTSParams.w - 1,
      wOTSParams,
      pubSeed,
      addr
    );
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {WOTSParams} params
 * @param {Uint8Array} leaf
 * @param {Uint8Array} wotsPK
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function lTree(hashFunction, params, leaf, wotsPK, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  let l = params.len;
  const { n } = params;

  let [height] = new Uint32Array([0]);
  let [bound] = new Uint32Array([0]);

  setTreeHeight(addr, height);
  while (l > 1) {
    bound = l >>> 1;
    for (let i = 0; i < bound; i++) {
      setTreeIndex(addr, i);
      const outStartOffset = i * n;
      const inStartOffset = i * 2 * n;
      hashH(
        hashFunction,
        wotsPK.subarray(outStartOffset, outStartOffset + n),
        wotsPK.subarray(inStartOffset, inStartOffset + 2 * n),
        pubSeed,
        addr,
        n
      );
    }
    if ((l & 1) === 1) {
      const destStartOffset = (l >>> 1) * n;
      const srcStartOffset = (l - 1) * n;
      wotsPK.set(wotsPK.subarray(srcStartOffset, srcStartOffset + n), destStartOffset);
      l = (l >>> 1) + 1;
    } else {
      l >>>= 1;
    }
    height++;
    setTreeHeight(addr, height);
  }
  leaf.set(wotsPK.subarray(0, n));
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} leaf
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} xmssParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} lTreeAddr
 * @param {Uint32Array} otsAddr
 */
export function genLeafWOTS(hashFunction, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr) {
  if (otsAddr.length !== 8) {
    throw new Error('otsAddr should be an array of size 8');
  }

  const seed = new Uint8Array(xmssParams.n);
  const pk = new Uint8Array(xmssParams.wotsParams.keySize);

  getSeed(hashFunction, seed, skSeed, xmssParams.n, otsAddr);
  wOTSPKGen(hashFunction, pk, seed, xmssParams.wotsParams, pubSeed, otsAddr);
  lTree(hashFunction, xmssParams.wotsParams, leaf, pk, pubSeed, lTreeAddr);
}

/**
 * @param {HashFunction} hashFunction
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} leafIdx
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function bdsRound(hashFunction, bdsState, leafIdx, skSeed, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const bdsState1 = bdsState;
  const { n, h, k } = params;

  let tau = h;
  const buf = new Uint8Array(2 * n);

  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  otsAddr.set(addr.subarray(0, 3));
  setType(otsAddr, 0);

  lTreeAddr.set(addr.subarray(0, 3));
  setType(lTreeAddr, 1);

  nodeAddr.set(addr.subarray(0, 3));
  setType(nodeAddr, 2);

  for (let i = 0; i < h; i++) {
    if (((leafIdx >>> i) & 1) === 0) {
      tau = i;
      break;
    }
  }

  if (tau > 0) {
    let srcOffset = (tau - 1) * n;
    buf.set(bdsState1.auth.subarray(srcOffset, srcOffset + n));

    srcOffset = ((tau - 1) >>> 1) * n;
    buf.set(bdsState1.keep.subarray(srcOffset, srcOffset + n), n);
  }

  if (((leafIdx >>> (tau + 1)) & 1) === 0 && tau < h - 1) {
    const destOffset = (tau >>> 1) * n;
    const srcOffset = tau * n;
    bdsState1.keep.set(bdsState1.auth.subarray(srcOffset, srcOffset + n), destOffset);
  }

  if (tau === 0) {
    setLTreeAddr(lTreeAddr, leafIdx);
    setOTSAddr(otsAddr, leafIdx);
    genLeafWOTS(hashFunction, bdsState1.auth.subarray(0, n), skSeed, params, pubSeed, lTreeAddr, otsAddr);
  } else {
    setTreeHeight(nodeAddr, tau - 1);
    setTreeIndex(nodeAddr, leafIdx >>> tau);
    hashH(hashFunction, bdsState1.auth.subarray(tau * n, tau * n + n), buf, pubSeed, nodeAddr, n);
    for (let i = 0; i < tau; i++) {
      if (i < h - k) {
        bdsState1.auth.set(bdsState1.treeHash[i].node.subarray(), i * n);
      } else {
        const offset = (1 << (h - 1 - i)) + i - h;
        const rowIdx = ((leafIdx >>> i) - 1) >>> 1;
        const srcOffset = (offset + rowIdx) * n;
        bdsState1.auth.set(bdsState1.retain.subarray(srcOffset, srcOffset + n), i * n);
      }
    }

    let compareValue = h - k;
    if (tau < h - k) {
      compareValue = tau;
    }
    for (let i = 0; i < compareValue; i++) {
      const startIdx = leafIdx + 1 + 3 * (1 << i);
      if (startIdx < 1 << h) {
        bdsState1.treeHash[i].h = i;
        bdsState1.treeHash[i].nextIdx = startIdx;
        bdsState1.treeHash[i].completed = 0;
        bdsState1.treeHash[i].stackUsage = 0;
      }
    }
  }
}

/**
 * @param {BDSState} state
 * @param {XMSSParams} params
 * @param {TreeHashInst} treeHash
 * @returns {Uint8Array[number]}
 */
export function treeHashMinHeightOnStack(state, params, treeHash) {
  let r = params.h;
  for (let i = 0; i < treeHash.stackUsage; i++) {
    const stackLevelOffset = state.stackLevels[state.stackOffset - i - 1];
    if (stackLevelOffset < r) {
      r = stackLevelOffset;
    }
  }
  return r;
}

/**
 * @param {HashFunction} hashFunction
 * @param {TreeHashInst} treeHash
 * @param {BDSState} bdsState
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
export function treeHashUpdate(hashFunction, treeHash, bdsState, skSeed, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const treeHash1 = treeHash;
  const bdsState1 = bdsState;

  const { n } = params;

  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  otsAddr.set(addr.subarray(0, 3));
  setType(otsAddr, 0);

  lTreeAddr.set(addr.subarray(0, 3));
  setType(lTreeAddr, 1);

  nodeAddr.set(addr.subarray(0, 3));
  setType(nodeAddr, 2);

  setLTreeAddr(lTreeAddr, treeHash1.nextIdx);
  setOTSAddr(otsAddr, treeHash1.nextIdx);

  const nodeBuffer = new Uint8Array(2 * n);
  let [nodeHeight] = new Uint32Array([0]);

  genLeafWOTS(hashFunction, nodeBuffer, skSeed, params, pubSeed, lTreeAddr, otsAddr);

  while (treeHash1.stackUsage > 0 && bdsState1.stackLevels[bdsState1.stackOffset - 1] === nodeHeight) {
    nodeBuffer.set(nodeBuffer.subarray(0, n), n);
    const srcOffset = (bdsState1.stackOffset - 1) * n;
    nodeBuffer.set(bdsState1.stack.subarray(srcOffset, srcOffset + n));
    setTreeHeight(nodeAddr, nodeHeight);
    setTreeIndex(nodeAddr, treeHash1.nextIdx >>> (nodeHeight + 1));
    hashH(hashFunction, nodeBuffer.subarray(0, n), nodeBuffer, pubSeed, nodeAddr, n);
    nodeHeight++;
    treeHash1.stackUsage--;
    bdsState1.stackOffset--;
  }

  if (nodeHeight === treeHash1.h) {
    treeHash1.node.set(nodeBuffer.subarray(0, n));
    treeHash1.completed = 1;
  } else {
    const destOffset = bdsState1.stackOffset * n;
    bdsState1.stack.set(nodeBuffer.subarray(0, n), destOffset);
    treeHash1.stackUsage++;
    bdsState1.stackLevels.set([nodeHeight], bdsState1.stackOffset);
    bdsState1.stackOffset++;
    treeHash1.nextIdx++;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {BDSState} bdsState
 * @param {Uint32Array[number]} updates
 * @param {Uint8Array} skSeed
 * @param {XMSSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @returns {Uint32Array[number]}
 */
export function bdsTreeHashUpdate(hashFunction, bdsState, updates, skSeed, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const { h, k } = params;
  let [used] = new Uint32Array([0]);
  let [lMin] = new Uint32Array([0]);
  let [level] = new Uint32Array([0]);
  let [low] = new Uint32Array([0]);

  for (let j = 0; j < updates; j++) {
    lMin = h;
    level = h - k;
    for (let i = 0; i < h - k; i++) {
      if (bdsState.treeHash[i].completed === 1) {
        low = h;
      } else if (bdsState.treeHash[i].stackUsage === 0) {
        low = i;
      } else {
        low = treeHashMinHeightOnStack(bdsState, params, bdsState.treeHash[i]);
      }
      if (low < lMin) {
        level = i;
        lMin = low;
      }
    }
    if (level === h - k) {
      break;
    }
    treeHashUpdate(hashFunction, bdsState.treeHash[level], bdsState, skSeed, params, pubSeed, addr);
    used++;
  }

  return updates - used;
}
