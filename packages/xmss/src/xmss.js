import { newWOTSParams } from './classes.js';
import { WOTS_PARAM } from './constants.js';
import { coreHash, hashH, prf } from './hash.js';
import {
  setChainAddr,
  setLTreeAddr,
  setOTSAddr,
  setTreeHeight,
  setTreeIndex,
  setType,
  toByteLittleEndian,
} from './helper.js';
import { bdsRound, bdsTreeHashUpdate, expandSeed, genChain, getSeed, lTree } from './xmssFast.js';

/**
 * @param {Uint8Array} output
 * @param {Uint32Array[number]} outputLen
 * @param {Uint8Array} input
 * @param {WOTSParams} params
 */
export function calcBaseW(output, outputLen, input, params) {
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
export function wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr) {
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
export function calculateSignatureBaseSize(keySize) {
  return 4 + 32 + keySize;
}

/**
 * @param {XMSSParams} params
 * @returns {Uint32Array[number]}
 */
export function getSignatureSize(params) {
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
export function hMsg(hashFunction, out, input, key, n) {
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
export function xmssFastSignMessage(hashFunction, params, sk, bdsState, message) {
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
export function getHeightFromSigSize(sigSize, wotsParamW) {
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
export function wotsPKFromSig(hashfunction, pk, sig, msg, wotsParams, pubSeed, addr) {
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
export function validateAuthPath(hashFunction, root, leaf, leafIdx, authpath, n, h, pubSeed, addr) {
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
export function xmssVerifySig(hashFunction, wotsParams, msg, sigMsg, pk, h) {
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
