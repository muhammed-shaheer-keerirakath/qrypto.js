import { sha256 as sha256$1 } from '@noble/hashes/sha256';
import jsSha3CommonJsPackage from 'js-sha3';

/// <reference path="typedefs.js" />

class TreeHashInst {
  constructor(n = 0) {
    [this.h] = new Uint32Array([0]);
    [this.nextIdx] = new Uint32Array([0]);
    [this.stackUsage] = new Uint32Array([0]);
    [this.completed] = new Uint8Array([0]);
    this.node = new Uint8Array(n);
  }
}

/**
 * @param {Uint32Array[number]} n
 * @returns {TreeHashInst}
 */
function newTreeHashInst(n) {
  return new TreeHashInst(n);
}

class BDSState {
  constructor(height, n, k) {
    this.stackOffset = 0;
    this.stack = new Uint8Array((height + 1) * n);
    this.stackLevels = new Uint8Array(height + 1);
    this.auth = new Uint8Array(height * n);
    this.keep = new Uint8Array((height >>> 1) * n);
    this.treeHash = new Array(0);
    for (let i = 0; i < height - k; i++) {
      this.treeHash.push(newTreeHashInst(n));
    }
    this.retain = new Uint8Array(((1 << k) - k - 1) * n);
    this.nextLeaf = 0;
  }
}

/**
 * @param {Uint32Array[number]} height
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} k
 * @returns {BDSState}
 */
function newBDSState(height, n, k) {
  return new BDSState(height, n, k);
}

class WOTSParams {
  constructor(n, w) {
    this.n = n;
    this.w = w;
    [this.logW] = new Uint32Array([Math.log2(w)]);
    if (this.logW !== 2 && this.logW !== 4 && this.logW !== 8) {
      throw new Error('logW should be either 2, 4 or 8');
    }
    // an integer value is passed to the ceil function for now w.r.t. golang code. update this as and when required.
    [this.len1] = new Uint32Array([Math.ceil(parseInt(((8 * n) / this.logW).toString(), 10))]);
    [this.len2] = new Uint32Array([Math.floor(Math.log2(this.len1 * (w - 1)) / this.logW) + 1]);
    this.len = this.len1 + this.len2;
    this.keySize = this.len * n;
  }
}

/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} w
 * @returns {WOTSParams}
 */
function newWOTSParams(n, w) {
  return new WOTSParams(n, w);
}

class XMSSParams {
  constructor(n, h, w, k) {
    this.wotsParams = newWOTSParams(n, w);
    this.n = n;
    this.h = h;
    this.k = k;
  }
}

/**
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} h
 * @param {Uint32Array[number]} w
 * @param {Uint32Array[number]} k
 * @returns {XMSSParams}
 */
function newXMSSParams(n, h, w, k) {
  return new XMSSParams(n, h, w, k);
}

const ENDIAN = Object.freeze({
  LITTLE: 0,
  BIG: 1,
});

const HASH_FUNCTION = Object.freeze({
  SHA2_256: 0,
  SHAKE_128: 1,
  SHAKE_256: 2,
});

const WOTS_PARAM = Object.freeze({
  K: 2,
  W: 16,
  N: 32,
});

const { shake256: sha3Shake256, shake128: sha3Shake128 } = jsSha3CommonJsPackage;

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function shake128(out, msg) {
  const hash = sha3Shake128(msg, 8 * out.length);
  for (let i = 0, h = 0; i < out.length; i++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], i);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function shake256(out, msg) {
  const hash = sha3Shake256(msg, 8 * out.length);
  for (let i = 0, h = 0; i < out.length; i++, h++) {
    out.set([parseInt(hash.substring(h * 2, h * 2 + 2), 16)], i);
  }
  return out;
}

/**
 * @param {Uint8Array} out
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function sha256(out, msg) {
  const hashOut = sha256$1(msg);
  out.set(hashOut.subarray());
  return out;
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} typeValue
 */
function setType(addr, typeValue) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  addr.set([typeValue], 3);
  for (let i = 4; i < 8; i++) {
    addr.set([0], i);
  }
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} lTree
 */
function setLTreeAddr(addr, lTree) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  addr.set([lTree], 4);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} ots
 */
function setOTSAddr(addr, ots) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  addr.set([ots], 4);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} chain
 */
function setChainAddr(addr, chain) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  addr.set([chain], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} hash
 */
function setHashAddr(addr, hash) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  addr.set([hash], 6);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} keyAndMask
 */
function setKeyAndMask(addr, keyAndMask) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  addr.set([keyAndMask], 7);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeHeight
 */
function setTreeHeight(addr, treeHeight) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  addr.set([treeHeight], 5);
}

/**
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} treeIndex
 */
function setTreeIndex(addr, treeIndex) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  addr.set([treeIndex], 6);
}

/** @returns Number */
function getEndian() {
  const buffer = new ArrayBuffer(2);
  const uint16View = new Uint16Array(buffer);
  const uint8View = new Uint8Array(buffer);
  uint16View[0] = 0xabcd;
  if (uint8View[0] === 0xcd && uint8View[1] === 0xab) {
    return ENDIAN.LITTLE;
  }
  if (uint8View[0] === 0xab && uint8View[1] === 0xcd) {
    return ENDIAN.BIG;
  }
  throw new Error('Could not determine native endian.');
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 */
function toByteLittleEndian(out, input, bytes) {
  let inValue = input;
  for (let i = bytes - 1; i >= 0; i--) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} input
 * @param {Uint32Array[number]} bytes
 */
function toByteBigEndian(out, input, bytes) {
  let inValue = input;
  for (let i = 0; i < bytes; i++) {
    out.set([new Uint8Array([inValue & 0xff])[0]], i);
    inValue >>>= 8;
  }
}

/**
 * @param {Uint8Array} out
 * @param {Uint32Array} addr
 * @param {function(): ENDIAN[keyof typeof ENDIAN]} getEndianFunc
 */
function addrToByte(out, addr, getEndianFunc = getEndian) {
  if (out.length !== 32) {
    throw new Error('out should be an array of size 32');
  }
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  switch (getEndianFunc()) {
    case ENDIAN.LITTLE:
      for (let i = 0; i < 8; i++) {
        toByteLittleEndian(out.subarray(i * 4, i * 4 + 4), addr[i], 4);
      }
      break;
    case ENDIAN.BIG:
      for (let i = 0; i < 8; i++) {
        toByteBigEndian(out.subarray(i * 4, i * 4 + 4), addr[i], 4);
      }
      break;
    default:
      throw new Error('Invalid Endian');
  }
}

/// <reference path="typedefs.js" />


/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint32Array[number]} typeValue
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 * @param {Uint8Array} input
 * @param {Uint32Array[number]} inLen
 * @param {Uint32Array[number]} n
 */
function coreHash(hashFunction, out, typeValue, key, keyLen, input, inLen, n) {
  const buf = new Uint8Array(inLen + n + keyLen);
  toByteLittleEndian(buf, typeValue, n);
  for (let i = 0; i < keyLen; i++) {
    buf.set([key[i]], i + n);
  }
  for (let i = 0; i < inLen; i++) {
    buf.set([input[i]], keyLen + n + i);
  }

  switch (hashFunction) {
    case HASH_FUNCTION.SHA2_256:
      sha256(out, buf);
      break;
    case HASH_FUNCTION.SHAKE_128:
      shake128(out, buf);
      break;
    case HASH_FUNCTION.SHAKE_256:
      shake256(out, buf);
      break;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} keyLen
 */
function prf(hashFunction, out, input, key, keyLen) {
  coreHash(hashFunction, out, 3, key, keyLen, input, 32, keyLen);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 * @param {Uint32Array[number]} n
 */
function hashH(hashFunction, out, input, pubSeed, addr, n) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const buf = new Uint8Array(2 * n);
  const key = new Uint8Array(n);
  const bitMask = new Uint8Array(2 * n);
  const byteAddr = new Uint8Array(32);

  setKeyAndMask(addr, 0);
  addrToByte(byteAddr, addr);
  prf(hashFunction, key, byteAddr, pubSeed, n);

  setKeyAndMask(addr, 1);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask.subarray(0, n), byteAddr, pubSeed, n);
  setKeyAndMask(addr, 2);
  addrToByte(byteAddr, addr);
  prf(hashFunction, bitMask.subarray(n, n + n), byteAddr, pubSeed, n);
  for (let i = 0; i < 2 * n; i++) {
    buf.set([input[i] ^ bitMask[i]], i);
  }
  coreHash(hashFunction, out, 1, key, n, buf, 2 * n, n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} seed
 * @param {Uint8Array} skSeed
 * @param {Uint32Array[number]} n
 * @param {Uint32Array} addr
 */
function getSeed(hashFunction, seed, skSeed, n, addr) {
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
function expandSeed(hashFunction, outSeeds, inSeeds, n, len) {
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
function hashF(hashFunction, out, input, pubSeed, addr, n) {
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
function genChain(hashFunction, out, input, start, steps, params, pubSeed, addr) {
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
function wOTSPKGen(hashFunction, pk, sk, wOTSParams, pubSeed, addr) {
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
function lTree(hashFunction, params, leaf, wotsPK, pubSeed, addr) {
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
function genLeafWOTS(hashFunction, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr) {
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
function bdsRound(hashFunction, bdsState, leafIdx, skSeed, params, pubSeed, addr) {
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
function treeHashMinHeightOnStack(state, params, treeHash) {
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
function treeHashUpdate(hashFunction, treeHash, bdsState, skSeed, params, pubSeed, addr) {
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
function bdsTreeHashUpdate(hashFunction, bdsState, updates, skSeed, params, pubSeed, addr) {
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

/**
 * @param {Uint8Array} output
 * @param {Uint32Array[number]} outputLen
 * @param {Uint8Array} input
 * @param {WOTSParams} params
 */
function calcBaseW(output, outputLen, input, params) {
  let inIndex = 0;
  let outIndex = 0;
  let [total] = new Uint32Array([0]);
  let [bits] = new Uint32Array([0]);

  for (let consumed = 0; consumed < outputLen; consumed++) {
    if (bits === 0) {
      [total] = new Uint32Array([input[inIndex]]);
      inIndex++;
      [bits] = new Uint32Array([bits + 8]);
    }
    [bits] = new Uint32Array([bits - params.logW]);
    output.set([new Uint8Array([(total >>> bits) & (params.w - 1)])[0]], outIndex);
    outIndex++;
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk
 * @param {WOTSParams} params
 * @param {Uint8Array} pubSeed
 * @param {Uint8Array} addr
 */
function wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const baseW = new Uint8Array(params.len);
  let [csum] = new Uint32Array([0]);

  calcBaseW(baseW, params.len1, msg, params);

  for (let i = 0; i < params.len1; i++) {
    csum += params.w - 1 - new Uint32Array([baseW[i]])[0];
  }

  csum <<= 8 - ((params.len2 * params.logW) % 8);

  const len2Bytes = (params.len2 * params.logW + 7) / 8;

  const cSumBytes = new Uint8Array(len2Bytes);
  toByteLittleEndian(cSumBytes, csum, len2Bytes);

  const cSumBaseW = new Uint8Array(params.len2);

  calcBaseW(cSumBaseW, params.len2, cSumBytes, params);

  for (let i = 0; i < params.len2; i++) {
    baseW.set([cSumBaseW[i]], params.len1 + i);
  }

  expandSeed(hashFunction, sig, sk, params.n, params.len);

  for (let i = 0; i < params.len; i++) {
    setChainAddr(addr, i);
    const offset = i * params.n;
    genChain(
      hashFunction,
      sig.subarray(offset, offset + params.n),
      sig.subarray(offset, offset + params.n),
      0,
      new Uint32Array([baseW[i]])[0],
      params,
      pubSeed,
      addr
    );
  }
}

/**
 * @param {Uint32Array[number]} keySize
 * @returns {Uint32Array[number]}
 */
function calculateSignatureBaseSize(keySize) {
  return 4 + 32 + keySize;
}

/**
 * @param {XMSSParams} params
 * @returns {Uint32Array[number]}
 */
function getSignatureSize(params) {
  const signatureBaseSize = calculateSignatureBaseSize(params.wotsParams.keySize);
  return signatureBaseSize + params.h * 32;
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} out
 * @param {Uint8Array} input
 * @param {Uint8Array} key
 * @param {Uint32Array[number]} n
 * @returns {{ error: string }}
 */
function hMsg(hashFunction, out, input, key, n) {
  if (key.length !== 3 * n) {
    return {
      error: `H_msg takes 3n-bit keys, we got n=${n} but a keylength of ${key.length}.`,
    };
  }
  coreHash(hashFunction, out, 2, key, key.length, input, input.length, n);
  return { error: null };
}

/**
 * @param {HashFunction} hashFunction
 * @param {XMSSParams} params
 * @param {Uint8Array} sk
 * @param {BDSState} bdsState
 * @param {Uint8Array} message
 * @returns {SignatureReturnType}
 */
function xmssFastSignMessage(hashFunction, params, sk, bdsState, message) {
  const { n } = params;

  const [idx] = new Uint32Array([
    (new Uint32Array([sk[0]])[0] << 24) |
      (new Uint32Array([sk[1]])[0] << 16) |
      (new Uint32Array([sk[2]])[0] << 8) |
      new Uint32Array([sk[3]])[0],
  ]);

  const skSeed = new Uint8Array(n);
  skSeed.set(sk.subarray(4, 4 + n));
  const skPRF = new Uint8Array(n);
  skPRF.set(sk.subarray(4 + n, 4 + n + n));
  const pubSeed = new Uint8Array(n);
  pubSeed.set(sk.subarray(4 + 2 * n, 4 + 2 * n + n));

  const idxBytes32 = new Uint8Array(32);
  toByteLittleEndian(idxBytes32, idx, 32);

  const hashKey = new Uint8Array(3 * n);

  sk.set([
    new Uint8Array([((idx + 1) >>> 24) & 0xff])[0],
    new Uint8Array([((idx + 1) >>> 16) & 0xff])[0],
    new Uint8Array([((idx + 1) >>> 8) & 0xff])[0],
    new Uint8Array([(idx + 1) & 0xff])[0],
  ]);

  const R = new Uint8Array(n);
  const otsAddr = new Uint32Array(8);

  prf(hashFunction, R, idxBytes32, skPRF, n);
  hashKey.set(R.subarray(0, R.length), 0);
  hashKey.set(sk.subarray(4 + 3 * n, 4 + 3 * n + n), n);
  toByteLittleEndian(hashKey.subarray(2 * n, 2 * n + n), idx, n);
  const msgHash = new Uint8Array(n);
  const { error } = hMsg(hashFunction, msgHash, message, hashKey, n);
  if (error !== null) {
    return { sigMsg: null, error };
  }
  let [sigMsgLen] = new Uint32Array([0]);
  const sigMsg = new Uint8Array(getSignatureSize(params));
  sigMsg.set([
    new Uint8Array([(idx >>> 24) & 0xff])[0],
    new Uint8Array([(idx >>> 16) & 0xff])[0],
    new Uint8Array([(idx >>> 8) & 0xff])[0],
    new Uint8Array([idx & 0xff])[0],
  ]);

  sigMsgLen += 4;
  for (let i = 0; i < n; i++) {
    sigMsg.set([R[i]], sigMsgLen + i);
  }

  sigMsgLen += n;

  setType(otsAddr, 0);
  setOTSAddr(otsAddr, idx);

  const otsSeed = new Uint8Array(n);
  getSeed(hashFunction, otsSeed, skSeed, n, otsAddr);

  wotsSign(hashFunction, sigMsg.subarray(sigMsgLen), msgHash, otsSeed, params.wotsParams, pubSeed, otsAddr);

  sigMsgLen += params.wotsParams.keySize;

  sigMsg.set(bdsState.auth.subarray(0, params.h * params.n), sigMsgLen);

  if (idx < (new Uint32Array([1])[0] << params.h) - 1) {
    bdsRound(hashFunction, bdsState, idx, skSeed, params, pubSeed, otsAddr);
    bdsTreeHashUpdate(hashFunction, bdsState, (params.h - params.k) >>> 1, skSeed, params, pubSeed, otsAddr);
  }

  return { sigMsg, error: null };
}

/**
 * @param {Uint32Array[number]} sigSize
 * @param {Uint32Array[number]} wotsParamW
 * @returns {Uint32Array[number]}
 */
function getHeightFromSigSize(sigSize, wotsParamW) {
  const wotsParam = newWOTSParams(WOTS_PARAM.N, wotsParamW);
  const signatureBaseSize = calculateSignatureBaseSize(wotsParam.keySize);
  if (sigSize < signatureBaseSize) {
    throw new Error('Invalid signature size');
  }

  if ((sigSize - 4) % 32 !== 0) {
    throw new Error('Invalid signature size');
  }

  return new Uint32Array([(sigSize - signatureBaseSize) / 32])[0];
}

/**
 * @param {HashFunction} hashfunction
 * @param {Uint8Array} pk
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @param {WOTSParams} wotsParams
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
function wotsPKFromSig(hashfunction, pk, sig, msg, wotsParams, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const {
    len: XMSSWOTSLEN,
    len1: XMSSWOTSLEN1,
    len2: XMSSWOTSLEN2,
    logW: XMSSWOTSLOGW,
    w: XMSSWOTSW,
    n: XMSSN,
  } = wotsParams;

  const baseW = new Uint8Array(XMSSWOTSLEN);
  let cSum = new Uint32Array([0])[0];
  const cSumBytes = new Uint8Array((XMSSWOTSLEN2 * XMSSWOTSLOGW + 7) / 8);
  const cSumBaseW = new Uint8Array(XMSSWOTSLEN2);

  calcBaseW(baseW, XMSSWOTSLEN1, msg, wotsParams);

  for (let i = 0; i < XMSSWOTSLEN1; i++) {
    cSum += XMSSWOTSW - 1 - new Uint32Array([baseW[i]])[0];
  }

  cSum <<= 8 - ((XMSSWOTSLEN2 * XMSSWOTSLOGW) % 8);

  toByteLittleEndian(cSumBytes, cSum, (XMSSWOTSLEN2 * XMSSWOTSLOGW + 7) / 8);
  calcBaseW(cSumBaseW, XMSSWOTSLEN2, cSumBytes, wotsParams);

  for (let i = 0; i < XMSSWOTSLEN2; i++) {
    baseW.set([cSumBaseW[i]], XMSSWOTSLEN1 + i);
  }
  for (let i = 0; i < XMSSWOTSLEN; i++) {
    setChainAddr(addr, i);
    const offset = i * XMSSN;
    genChain(
      hashfunction,
      pk.subarray(offset, offset + XMSSN),
      sig.subarray(offset, offset + XMSSN),
      new Uint32Array([baseW[i]])[0],
      XMSSWOTSW - 1 - new Uint32Array([baseW[i]])[0],
      wotsParams,
      pubSeed,
      addr
    );
  }
}

/**
 * @param {HashFunction} hashFunction
 * @param {Uint8Array} root
 * @param {Uint8Array} leaf
 * @param {Uint32Array[number]} leafIdx
 * @param {Uint8Array} authpath
 * @param {Uint32Array[number]} n
 * @param {Uint32Array[number]} h
 * @param {Uint8Array} pubSeed
 * @param {Uint32Array} addr
 */
function validateAuthPath(hashFunction, root, leaf, leafIdx, authpath, n, h, pubSeed, addr) {
  if (addr.length !== 8) {
    throw new Error('addr should be an array of size 8');
  }

  const buffer = new Uint8Array(2 * n);

  let leafIdx1 = leafIdx;
  if ((leafIdx1 & 1) === 1) {
    for (let j = 0; j < n; j++) {
      buffer.set([leaf[j]], n + j);
    }
    for (let j = 0; j < n; j++) {
      buffer.set([authpath[j]], j);
    }
  } else {
    for (let j = 0; j < n; j++) {
      buffer.set([leaf[j]], j);
    }
    for (let j = 0; j < n; j++) {
      buffer.set([authpath[j]], n + j);
    }
  }
  let authPathOffset = n;

  for (let i = 0; i < h - 1; i++) {
    setTreeHeight(addr, i);
    leafIdx1 >>>= 1;
    setTreeIndex(addr, leafIdx1);
    if ((leafIdx1 & 1) === 1) {
      hashH(hashFunction, buffer.subarray(n, n + n), buffer, pubSeed, addr, n);
      for (let j = 0; j < n; j++) {
        buffer.set([authpath[authPathOffset + j]], j);
      }
    } else {
      hashH(hashFunction, buffer.subarray(0, n), buffer, pubSeed, addr, n);
      for (let j = 0; j < n; j++) {
        buffer.set([authpath[authPathOffset + j]], j + n);
      }
    }
    authPathOffset += n;
  }
  setTreeHeight(addr, h - 1);
  leafIdx1 >>>= 1;
  setTreeIndex(addr, leafIdx1);
  hashH(hashFunction, root.subarray(0, n), buffer, pubSeed, addr, n);
}

/**
 * @param {HashFunction} hashFunction
 * @param {WOTSParams} wotsParams
 * @param {Uint8Array} msg
 * @param {Uint8Array} sigMsg
 * @param {Uint8Array} pk
 * @param {Uint32Array[number]} h
 * @returns {boolean}
 */
function xmssVerifySig(hashFunction, wotsParams, msg, sigMsg, pk, h) {
  let [sigMsgOffset] = new Uint32Array([0]);

  const { n } = wotsParams;

  const wotsPK = new Uint8Array(wotsParams.keySize);
  const pkHash = new Uint8Array(n);
  const root = new Uint8Array(n);
  const hashKey = new Uint8Array(3 * n);

  const pubSeed = new Uint8Array(n);
  pubSeed.set(pk.subarray(n, n + n));

  // Init addresses
  const otsAddr = new Uint32Array(8);
  const lTreeAddr = new Uint32Array(8);
  const nodeAddr = new Uint32Array(8);

  setType(otsAddr, 0);
  setType(lTreeAddr, 1);
  setType(nodeAddr, 2);

  // Extract index
  const idx =
    (new Uint32Array([sigMsg[0]])[0] << 24) |
    (new Uint32Array([sigMsg[1]])[0] << 16) |
    (new Uint32Array([sigMsg[2]])[0] << 8) |
    new Uint32Array([sigMsg[3]])[0];

  // Generate hash key (R || root || idx)
  hashKey.set(sigMsg.subarray(4, 4 + n));
  hashKey.set(pk.subarray(0, n), n);
  toByteLittleEndian(hashKey.subarray(2 * n, 2 * n + n), idx, n);

  sigMsgOffset += n + 4;

  // hash message
  const msgHash = new Uint8Array(n);
  const { error } = hMsg(hashFunction, msgHash, msg, hashKey, n);
  if (error !== null) {
    return false;
  }

  // Prepare Address
  setOTSAddr(otsAddr, idx);
  // Check WOTS signature
  wotsPKFromSig(hashFunction, wotsPK, sigMsg.subarray(sigMsgOffset), msgHash, wotsParams, pubSeed, otsAddr);

  sigMsgOffset += wotsParams.keySize;

  // Compute Ltree
  setLTreeAddr(lTreeAddr, idx);
  lTree(hashFunction, wotsParams, pkHash, wotsPK, pubSeed, lTreeAddr);

  // Compute root
  validateAuthPath(hashFunction, root, pkHash, idx, sigMsg.subarray(sigMsgOffset), n, h, pubSeed, nodeAddr);

  for (let i = 0; i < n; i++) {
    if (root[i] !== pk[i]) {
      return false;
    }
  }

  return true;
}

export { ENDIAN, HASH_FUNCTION, WOTS_PARAM, addrToByte, bdsRound, bdsTreeHashUpdate, calcBaseW, calculateSignatureBaseSize, coreHash, expandSeed, genChain, genLeafWOTS, getHeightFromSigSize, getSeed, getSignatureSize, hMsg, hashF, hashH, lTree, newBDSState, newTreeHashInst, newWOTSParams, newXMSSParams, prf, setChainAddr, setHashAddr, setKeyAndMask, setLTreeAddr, setOTSAddr, setTreeHeight, setTreeIndex, setType, sha256, shake128, shake256, toByteLittleEndian, treeHashMinHeightOnStack, treeHashUpdate, validateAuthPath, wOTSPKGen, wotsPKFromSig, wotsSign, xmssFastSignMessage, xmssVerifySig };
