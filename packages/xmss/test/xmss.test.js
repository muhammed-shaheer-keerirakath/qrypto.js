import { expect } from 'chai';
import { describe } from 'mocha';
import { newQRLDescriptor, newQRLDescriptorFromExtendedSeed, newWOTSParams, newXMSSParams } from '../src/classes.js';
import { COMMON, HASH_FUNCTION } from '../src/constants.js';
import {
  calcBaseW,
  calculateSignatureBaseSize,
  getSignatureSize,
  getXMSSAddressFromPK,
  hMsg,
  initializeTree,
  newXMSSFromExtendedSeed,
  newXMSSFromHeight,
  newXMSSFromSeed,
  wotsSign,
} from '../src/xmss.js';

describe('xmss', function testFunction() {
  this.timeout(0);

  describe('calculateSignatureBaseSize', () => {
    it('should return the signature base size for the keysize 65', () => {
      const [keySize] = new Uint32Array([65]);
      const signautreBaseSize = calculateSignatureBaseSize(keySize);
      const expectedSignatureBaseSize = 101;

      expect(signautreBaseSize).to.equal(expectedSignatureBaseSize);
    });

    it('should return the signature base size for the keysize 399', () => {
      const [keySize] = new Uint32Array([399]);
      const signautreBaseSize = calculateSignatureBaseSize(keySize);
      const expectedSignatureBaseSize = 435;

      expect(signautreBaseSize).to.equal(expectedSignatureBaseSize);
    });

    it('should return the signature base size for the keysize 1064', () => {
      const [keySize] = new Uint32Array([1064]);
      const signautreBaseSize = calculateSignatureBaseSize(keySize);
      const expectedSignatureBaseSize = 1100;

      expect(signautreBaseSize).to.equal(expectedSignatureBaseSize);
    });
  });

  describe('getSignatureSize', () => {
    it('should return the signature size for the n[2] h[4] w[6] k[8]', () => {
      const n = 2;
      const h = 4;
      const w = 6;
      const k = 8;
      const params = newXMSSParams(n, h, w, k);
      const signatureSize = getSignatureSize(params);
      const expectedSignatureSize = 186;

      expect(signatureSize).to.equal(expectedSignatureSize);
    });

    it('should return the signature size for the n[13] h[7] w[9] k[3]', () => {
      const n = 13;
      const h = 7;
      const w = 9;
      const k = 3;
      const params = newXMSSParams(n, h, w, k);
      const signatureSize = getSignatureSize(params);
      const expectedSignatureSize = 741;

      expect(signatureSize).to.equal(expectedSignatureSize);
    });

    it('should return the signature size for the n[25] h[13] w[12] k[9]', () => {
      const n = 25;
      const h = 13;
      const w = 12;
      const k = 9;
      const params = newXMSSParams(n, h, w, k);
      const signatureSize = getSignatureSize(params);
      const expectedSignatureSize = 2202;

      expect(signatureSize).to.equal(expectedSignatureSize);
    });
  });

  describe('hMsg', () => {
    it('should return an error if key length is not equal to 3 times n', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const out = new Uint8Array([34, 56, 2, 7, 8, 45]);
      const input = new Uint8Array([32, 45, 7, 8, 23, 5, 7]);
      const key = new Uint8Array([34, 56, 2, 7, 8, 45, 34, 56, 2, 2]);
      const n = 3;
      const error = hMsg(hashFunction, out, input, key, n);

      expect(error).to.deep.equal({
        error: `H_msg takes 3n-bit keys, we got n=${n} but a keylength of ${key.length}.`,
      });
    });

    it('should return an null error if the function is executed correctly', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const out = new Uint8Array([34, 56, 2, 7, 8, 45]);
      const input = new Uint8Array([32, 45, 7, 8, 23, 5, 7]);
      const key = new Uint8Array([34, 56, 2, 7, 8, 45, 34, 56, 2]);
      const n = 3;
      const error = hMsg(hashFunction, out, input, key, n);

      expect(error).to.deep.equal({
        error: null,
      });
    });
  });

  describe('calcBaseW', () => {
    it('should calculate the base w, with w[6] input[74, 74, ...]', () => {
      const n = 13;
      const w = 6;
      const wotsParams = newWOTSParams(n, w);
      const outputLen = wotsParams.len1;
      const output = new Uint8Array(wotsParams.len);
      const input = new Uint8Array([
        74, 74, 32, 16, 12, 189, 110, 39, 169, 21, 184, 111, 59, 158, 132, 251, 205, 225, 89, 45, 117, 81, 92, 143, 82,
        170, 238, 156, 75,
      ]);
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedOutputLen = expectedWotsParams.len1;
      const expectedOutput = new Uint8Array([
        1, 4, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 1, 4, 0, 1, 5, 5, 1, 4, 1, 4, 0, 0, 1, 5, 0, 0, 0, 1, 0,
        1, 5, 5, 0, 1, 4, 0, 1, 4, 1, 5, 0, 1, 4, 1, 0, 0, 0, 0, 0,
      ]);
      const expectedInput = new Uint8Array([
        74, 74, 32, 16, 12, 189, 110, 39, 169, 21, 184, 111, 59, 158, 132, 251, 205, 225, 89, 45, 117, 81, 92, 143, 82,
        170, 238, 156, 75,
      ]);
      calcBaseW(output, outputLen, input, wotsParams);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(outputLen).to.deep.equal(expectedOutputLen);
      expect(output).to.deep.equal(expectedOutput);
      expect(input).to.deep.equal(expectedInput);
    });

    it('should calculate the base w, with w[16] input[34, 23, ...]', () => {
      const n = 25;
      const w = 16;
      const wotsParams = newWOTSParams(n, w);
      const outputLen = wotsParams.len1;
      const output = new Uint8Array(wotsParams.len);
      const input = new Uint8Array([
        34, 23, 66, 23, 4, 7, 8, 23, 34, 23, 66, 23, 4, 7, 8, 23, 34, 23, 66, 23, 4, 7, 8, 23, 34, 23, 66, 23, 4, 7, 8,
        23, 34,
      ]);
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedOutputLen = expectedWotsParams.len1;
      const expectedOutput = new Uint8Array([
        2, 2, 1, 7, 4, 2, 1, 7, 0, 4, 0, 7, 0, 8, 1, 7, 2, 2, 1, 7, 4, 2, 1, 7, 0, 4, 0, 7, 0, 8, 1, 7, 2, 2, 1, 7, 4,
        2, 1, 7, 0, 4, 0, 7, 0, 8, 1, 7, 2, 2, 0, 0, 0,
      ]);
      const expectedInput = new Uint8Array([
        34, 23, 66, 23, 4, 7, 8, 23, 34, 23, 66, 23, 4, 7, 8, 23, 34, 23, 66, 23, 4, 7, 8, 23, 34, 23, 66, 23, 4, 7, 8,
        23, 34,
      ]);
      calcBaseW(output, outputLen, input, wotsParams);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(outputLen).to.deep.equal(expectedOutputLen);
      expect(output).to.deep.equal(expectedOutput);
      expect(input).to.deep.equal(expectedInput);
    });

    it('should calculate the base w, with w[256] input[159, 202, ...]', () => {
      const n = 11;
      const w = 256;
      const wotsParams = newWOTSParams(n, w);
      const outputLen = wotsParams.len1;
      const output = new Uint8Array(wotsParams.len);
      const input = new Uint8Array([
        159, 202, 211, 84, 72, 119, 20, 240, 87, 221, 150, 241, 19, 50, 16, 16, 212, 61, 35, 204, 89, 163, 228, 212, 10,
        173, 44, 146, 41, 95, 131, 72,
      ]);
      const expectedWotsParams = newWOTSParams(n, w);
      const expectedOutputLen = expectedWotsParams.len1;
      const expectedOutput = new Uint8Array([159, 202, 211, 84, 72, 119, 20, 240, 87, 221, 150, 0, 0]);
      const expectedInput = new Uint8Array([
        159, 202, 211, 84, 72, 119, 20, 240, 87, 221, 150, 241, 19, 50, 16, 16, 212, 61, 35, 204, 89, 163, 228, 212, 10,
        173, 44, 146, 41, 95, 131, 72,
      ]);
      calcBaseW(output, outputLen, input, wotsParams);

      expect(wotsParams).to.deep.equal(expectedWotsParams);
      expect(outputLen).to.deep.equal(expectedOutputLen);
      expect(output).to.deep.equal(expectedOutput);
      expect(input).to.deep.equal(expectedInput);
    });
  });

  describe('wotsSign', () => {
    it('should throw an error if the size of addr is invalid', () => {
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const sig = new Uint8Array([
        224, 201, 246, 138, 163, 4, 236, 101, 149, 141, 198, 200, 52, 152, 221, 51, 7, 165, 205, 23, 66, 130, 153, 139,
        158, 164, 149, 241,
      ]);
      const msg = new Uint8Array([
        139, 172, 150, 45, 231, 244, 232, 178, 87, 66, 68, 153, 193, 43, 143, 159, 174, 252, 98, 12, 196, 221, 107, 122,
        97, 174,
      ]);
      const sk = new Uint8Array([
        68, 172, 140, 141, 41, 40, 252, 44, 118, 197, 181, 104, 53, 95, 217, 186, 119, 36, 131, 206, 57,
      ]);
      const n = 2;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([
        232, 10, 209, 120, 126, 242, 118, 253, 164, 208, 15, 70, 40, 111, 142, 239, 154, 123, 96, 189, 176, 202, 3, 213,
        148, 237, 38, 241, 149, 238, 21, 26, 10,
      ]);
      const addr = new Uint32Array([136, 63, 214, 113, 214, 45, 225]);

      expect(() => wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr)).to.throw(
        'addr should be an array of size 8'
      );
    });

    it('should sign wots, with SHA2_256 n[2] w[16]', () => {
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const sig = new Uint8Array([
        224, 201, 246, 138, 163, 4, 236, 101, 149, 141, 198, 200, 52, 152, 221, 51, 7, 165, 205, 23, 66, 130, 153, 139,
        158, 164, 149, 241,
      ]);
      const msg = new Uint8Array([
        139, 172, 150, 45, 231, 244, 232, 178, 87, 66, 68, 153, 193, 43, 143, 159, 174, 252, 98, 12, 196, 221, 107, 122,
        97, 174,
      ]);
      const sk = new Uint8Array([
        68, 172, 140, 141, 41, 40, 252, 44, 118, 197, 181, 104, 53, 95, 217, 186, 119, 36, 131, 206, 57,
      ]);
      const n = 2;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([
        232, 10, 209, 120, 126, 242, 118, 253, 164, 208, 15, 70, 40, 111, 142, 239, 154, 123, 96, 189, 176, 202, 3, 213,
        148, 237, 38, 241, 149, 238, 21, 26, 10,
      ]);
      const addr = new Uint32Array([136, 243, 63, 214, 113, 214, 45, 225]);
      const expectedSig = new Uint8Array([
        66, 143, 173, 51, 39, 251, 23, 249, 135, 223, 37, 136, 52, 152, 221, 51, 7, 165, 205, 23, 66, 130, 153, 139,
        158, 164, 149, 241,
      ]);
      const expectedMsg = new Uint8Array([
        139, 172, 150, 45, 231, 244, 232, 178, 87, 66, 68, 153, 193, 43, 143, 159, 174, 252, 98, 12, 196, 221, 107, 122,
        97, 174,
      ]);
      const expectedSk = new Uint8Array([
        68, 172, 140, 141, 41, 40, 252, 44, 118, 197, 181, 104, 53, 95, 217, 186, 119, 36, 131, 206, 57,
      ]);
      const expectedParams = newWOTSParams(n, w);
      const expectedPubSeed = new Uint8Array([
        232, 10, 209, 120, 126, 242, 118, 253, 164, 208, 15, 70, 40, 111, 142, 239, 154, 123, 96, 189, 176, 202, 3, 213,
        148, 237, 38, 241, 149, 238, 21, 26, 10,
      ]);
      const expectedAddr = new Uint32Array([136, 243, 63, 214, 113, 5, 11, 1]);
      wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr);

      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sk).to.deep.equal(expectedSk);
      expect(params).to.deep.equal(expectedParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should sign wots, with SHAKE_128 n[2] w[6]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const sig = new Uint8Array([
        8, 8, 2, 13, 4, 14, 0, 5, 5, 7, 11, 12, 2, 11, 10, 11, 14, 0, 4, 11, 13, 2, 8, 7, 12, 9, 122, 26, 49, 178, 15,
        72, 228,
      ]);
      const msg = new Uint8Array([
        178, 104, 176, 20, 253, 235, 214, 9, 122, 26, 49, 178, 15, 72, 228, 226, 9, 56, 105, 40, 93, 189, 155, 23, 2,
      ]);
      const sk = new Uint8Array([
        114, 54, 69, 150, 127, 24, 154, 74, 203, 198, 101, 138, 26, 233, 160, 137, 224, 2, 108, 75, 141, 166, 239, 172,
      ]);
      const n = 2;
      const w = 6;
      const params = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([
        217, 43, 195, 228, 235, 132, 239, 100, 186, 210, 252, 23, 0, 47, 179, 206, 150, 115, 99, 49, 26, 187, 128, 134,
        101, 110, 246, 77, 32, 69, 224, 166, 171, 130,
      ]);
      const addr = new Uint32Array([253, 215, 207, 144, 64, 155, 102, 31]);
      const expectedSig = new Uint8Array([
        230, 213, 215, 44, 58, 144, 232, 247, 57, 34, 134, 197, 101, 141, 171, 217, 43, 14, 100, 242, 118, 92, 8, 7, 12,
        9, 122, 26, 49, 178, 15, 72, 228,
      ]);
      const expectedMsg = new Uint8Array([
        178, 104, 176, 20, 253, 235, 214, 9, 122, 26, 49, 178, 15, 72, 228, 226, 9, 56, 105, 40, 93, 189, 155, 23, 2,
      ]);
      const expectedSk = new Uint8Array([
        114, 54, 69, 150, 127, 24, 154, 74, 203, 198, 101, 138, 26, 233, 160, 137, 224, 2, 108, 75, 141, 166, 239, 172,
      ]);
      const expectedParams = newWOTSParams(n, w);
      const expectedPubSeed = new Uint8Array([
        217, 43, 195, 228, 235, 132, 239, 100, 186, 210, 252, 23, 0, 47, 179, 206, 150, 115, 99, 49, 26, 187, 128, 134,
        101, 110, 246, 77, 32, 69, 224, 166, 171, 130,
      ]);
      const expectedAddr = new Uint32Array([253, 215, 207, 144, 64, 10, 3, 1]);
      wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr);

      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sk).to.deep.equal(expectedSk);
      expect(params).to.deep.equal(expectedParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should sign wots, with SHAKE_256 n[3] w[256]', () => {
      const hashFunction = HASH_FUNCTION.SHAKE_256;
      const sig = new Uint8Array([
        94, 41, 14, 122, 27, 26, 103, 13, 225, 153, 164, 236, 149, 75, 253, 59, 114, 172, 163, 230, 161, 149, 76, 9,
        231, 240, 141,
      ]);
      const msg = new Uint8Array([
        34, 122, 83, 18, 112, 92, 216, 101, 49, 184, 37, 119, 62, 113, 223, 50, 162, 74, 67, 23, 245, 103, 184, 130, 27,
        156, 153, 196, 32, 48, 65, 130, 207, 64, 226,
      ]);
      const sk = new Uint8Array([
        11, 198, 107, 59, 33, 178, 149, 21, 29, 158, 31, 154, 251, 220, 67, 213, 31, 29, 140, 184, 122, 89, 240, 132,
        129, 182, 118, 140, 155, 59,
      ]);
      const n = 3;
      const w = 256;
      const params = newWOTSParams(n, w);
      const pubSeed = new Uint8Array([
        240, 169, 165, 69, 9, 20, 6, 63, 132, 84, 168, 26, 76, 63, 61, 220, 204, 240, 41, 252, 197, 225, 7, 246, 185,
      ]);
      const addr = new Uint32Array([13, 215, 66, 106, 98, 55, 105, 183]);
      const expectedSig = new Uint8Array([
        163, 210, 143, 216, 97, 38, 11, 67, 245, 99, 82, 239, 15, 209, 230, 59, 114, 172, 163, 230, 161, 149, 76, 9,
        231, 240, 141,
      ]);
      const expectedMsg = new Uint8Array([
        34, 122, 83, 18, 112, 92, 216, 101, 49, 184, 37, 119, 62, 113, 223, 50, 162, 74, 67, 23, 245, 103, 184, 130, 27,
        156, 153, 196, 32, 48, 65, 130, 207, 64, 226,
      ]);
      const expectedSk = new Uint8Array([
        11, 198, 107, 59, 33, 178, 149, 21, 29, 158, 31, 154, 251, 220, 67, 213, 31, 29, 140, 184, 122, 89, 240, 132,
        129, 182, 118, 140, 155, 59,
      ]);
      const expectedParams = newWOTSParams(n, w);
      const expectedPubSeed = new Uint8Array([
        240, 169, 165, 69, 9, 20, 6, 63, 132, 84, 168, 26, 76, 63, 61, 220, 204, 240, 41, 252, 197, 225, 7, 246, 185,
      ]);
      const expectedAddr = new Uint32Array([13, 215, 66, 106, 98, 4, 13, 1]);
      wotsSign(hashFunction, sig, msg, sk, params, pubSeed, addr);

      expect(sig).to.deep.equal(expectedSig);
      expect(msg).to.deep.equal(expectedMsg);
      expect(sk).to.deep.equal(expectedSk);
      expect(params).to.deep.equal(expectedParams);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('initializeTree', () => {
    it('should generate xmss tree for extendedSeed[5, 146 ...] and seed[0, 0 ...]', () => {
      const extendedSeed = new Uint8Array([
        5, 146, 182, 224, 114, 250, 181, 221, 201, 138, 132, 84, 79, 78, 158, 191, 80, 177, 135, 151, 5, 221, 84, 237,
        94, 152, 84, 18, 184, 211, 20, 10, 9, 204, 252, 12, 222, 114, 131, 220, 167, 111, 147, 207, 143, 68, 70, 228,
        217, 106, 73,
      ]);
      const desc = newQRLDescriptorFromExtendedSeed(extendedSeed);
      const seed = new Uint8Array(COMMON.SEED_SIZE);
      const xmssTree = initializeTree(desc, seed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 4,
        k: 2,
      };
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 237, 163, 19, 201, 85, 145, 160, 35, 165, 179, 127, 54, 28, 7, 165, 117, 58, 146, 211, 208, 66, 116,
        89, 243, 76, 120, 149, 215, 39, 214, 40, 22, 179, 170, 34, 36, 235, 157, 130, 49, 39, 212, 249, 248, 163, 15,
        215, 161, 160, 44, 100, 131, 217, 192, 241, 253, 65, 149, 123, 154, 228, 223, 198, 58, 49, 145, 218, 52, 66,
        104, 98, 130, 179, 213, 22, 15, 37, 207, 22, 42, 81, 127, 210, 19, 31, 131, 251, 242, 105, 138, 88, 249, 196,
        106, 252, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      const expectedSeed = new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      const expectedBdsState = {
        stack: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        stackOffset: 0,
        stackLevels: new Uint8Array([0, 0, 0, 0, 0]),
        auth: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        keep: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
          },
        ],
        retain: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 5, signatureType: 0, height: 4, addrFormatType: 9 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 5,
        height: 4,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });

    it('should generate xmss tree for desc[6, 1 ...] and seed[68, 24 ...]', () => {
      const desc = newQRLDescriptor(6, HASH_FUNCTION.SHA2_256, 4, 44);
      const seed = new Uint8Array([
        68, 24, 114, 231, 214, 43, 119, 145, 112, 232, 156, 22, 88, 162, 41, 27, 245, 171, 90, 221, 2, 91, 82, 83, 10,
        140, 73, 25, 113, 67, 166, 224, 57, 194, 244, 60, 252, 197, 168, 250, 3, 128, 62, 174, 226, 90, 16, 101,
      ]);
      const xmssTree = initializeTree(desc, seed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 6,
        k: 2,
      };
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 154, 124, 42, 121, 37, 91, 246, 4, 244, 198, 21, 251, 28, 4, 35, 72, 186, 212, 16, 58, 65, 10, 71,
        199, 179, 243, 41, 255, 130, 228, 229, 218, 103, 150, 133, 159, 31, 169, 114, 23, 101, 118, 205, 2, 69, 93, 244,
        28, 30, 74, 202, 51, 1, 126, 221, 194, 173, 108, 116, 239, 216, 159, 196, 120, 106, 95, 23, 31, 137, 115, 198,
        67, 170, 158, 112, 141, 174, 87, 118, 59, 86, 3, 163, 2, 61, 136, 190, 250, 192, 228, 240, 46, 122, 190, 56,
        114, 241, 68, 91, 104, 2, 87, 5, 51, 74, 254, 235, 95, 98, 146, 115, 119, 21, 107, 20, 228, 162, 151, 209, 61,
        56, 147, 41, 26, 22, 99, 249, 86,
      ]);
      const expectedSeed = new Uint8Array([
        68, 24, 114, 231, 214, 43, 119, 145, 112, 232, 156, 22, 88, 162, 41, 27, 245, 171, 90, 221, 2, 91, 82, 83, 10,
        140, 73, 25, 113, 67, 166, 224, 57, 194, 244, 60, 252, 197, 168, 250, 3, 128, 62, 174, 226, 90, 16, 101,
      ]);
      const expectedBdsState = {
        stack: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0,
        ]),
        stackOffset: 0,
        stackLevels: new Uint8Array([0, 0, 0, 0, 0, 0, 0]),
        auth: new Uint8Array([
          239, 230, 210, 209, 42, 56, 30, 84, 20, 13, 235, 131, 43, 250, 72, 181, 51, 206, 243, 93, 123, 209, 25, 150,
          167, 6, 75, 142, 33, 38, 69, 194, 168, 194, 64, 40, 41, 216, 105, 51, 189, 5, 177, 90, 47, 46, 17, 168, 225,
          100, 222, 132, 0, 254, 23, 189, 32, 155, 99, 230, 40, 174, 161, 61, 189, 66, 37, 25, 168, 161, 24, 169, 120,
          232, 73, 118, 210, 119, 182, 255, 21, 61, 167, 132, 110, 187, 204, 128, 88, 0, 142, 109, 177, 41, 21, 22, 116,
          167, 87, 236, 3, 135, 23, 201, 192, 47, 182, 75, 216, 10, 165, 42, 44, 96, 199, 228, 40, 144, 7, 4, 224, 78,
          85, 41, 25, 213, 69, 203, 32, 67, 177, 179, 152, 233, 144, 81, 151, 158, 22, 14, 152, 69, 93, 46, 96, 32, 20,
          80, 4, 98, 52, 23, 248, 240, 39, 216, 237, 76, 155, 242, 217, 19, 226, 29, 84, 199, 189, 167, 119, 213, 26,
          119, 168, 146, 145, 136, 136, 115, 144, 15, 21, 161, 135, 214, 35, 91, 91, 64, 21, 14, 185, 124,
        ]),
        keep: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              212, 34, 252, 232, 11, 222, 231, 173, 225, 184, 171, 42, 182, 23, 71, 49, 140, 167, 65, 38, 202, 170, 88,
              205, 157, 237, 252, 218, 243, 92, 100, 244,
            ]),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              40, 173, 199, 139, 180, 235, 36, 89, 148, 254, 204, 128, 204, 42, 128, 68, 184, 191, 249, 71, 193, 228,
              96, 251, 96, 141, 46, 252, 208, 145, 20, 47,
            ]),
          },
          {
            h: 2,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              255, 187, 140, 215, 114, 144, 244, 141, 243, 154, 33, 43, 124, 6, 241, 31, 230, 139, 82, 85, 92, 170, 235,
              19, 68, 194, 205, 197, 158, 31, 199, 126,
            ]),
          },
          {
            h: 3,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              131, 172, 174, 116, 50, 39, 27, 197, 141, 247, 196, 1, 120, 143, 186, 98, 25, 15, 171, 69, 250, 107, 104,
              207, 103, 68, 250, 83, 241, 30, 194, 189,
            ]),
          },
        ],
        retain: new Uint8Array([
          255, 61, 112, 94, 197, 238, 148, 207, 238, 93, 203, 33, 33, 198, 132, 37, 9, 23, 44, 23, 183, 0, 51, 57, 196,
          172, 42, 240, 237, 183, 242, 131,
        ]),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 0, signatureType: 4, height: 6, addrFormatType: 44 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 0,
        height: 6,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });

    it('should generate xmss tree for desc[10, 2 ...] and seed[112, 104 ...]', () => {
      const desc = newQRLDescriptor(10, HASH_FUNCTION.SHAKE_256, 7, 13);
      const seed = new Uint8Array([
        112, 104, 137, 192, 105, 171, 35, 223, 91, 12, 173, 112, 183, 118, 223, 141, 63, 16, 125, 67, 71, 76, 28, 116,
        25, 53, 100, 29, 214, 232, 245, 214, 150, 86, 22, 197, 20, 54, 96, 252, 21, 40, 57, 42, 8, 71, 0, 35,
      ]);
      const xmssTree = initializeTree(desc, seed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 10,
        k: 2,
      };
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 39, 135, 83, 241, 136, 93, 226, 7, 200, 120, 210, 139, 188, 172, 34, 191, 3, 66, 54, 212, 158, 222,
        210, 47, 185, 192, 215, 33, 206, 194, 220, 133, 248, 236, 222, 241, 118, 149, 173, 127, 12, 70, 59, 162, 209,
        16, 67, 178, 44, 70, 42, 5, 32, 155, 87, 62, 229, 243, 29, 249, 194, 203, 149, 232, 119, 221, 48, 105, 254, 149,
        240, 2, 209, 189, 121, 124, 213, 82, 179, 75, 127, 116, 166, 212, 101, 174, 36, 158, 198, 146, 110, 121, 163,
        169, 89, 247, 62, 22, 224, 63, 54, 243, 198, 235, 221, 233, 135, 116, 129, 144, 250, 78, 51, 178, 143, 224, 227,
        45, 249, 97, 217, 13, 237, 89, 237, 215, 128, 127,
      ]);
      const expectedSeed = new Uint8Array([
        112, 104, 137, 192, 105, 171, 35, 223, 91, 12, 173, 112, 183, 118, 223, 141, 63, 16, 125, 67, 71, 76, 28, 116,
        25, 53, 100, 29, 214, 232, 245, 214, 150, 86, 22, 197, 20, 54, 96, 252, 21, 40, 57, 42, 8, 71, 0, 35,
      ]);
      const expectedBdsState = {
        stack: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        stackOffset: 0,
        stackLevels: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        auth: new Uint8Array([
          41, 80, 220, 130, 200, 3, 187, 20, 8, 211, 98, 221, 135, 61, 220, 224, 182, 184, 109, 57, 25, 80, 159, 215,
          173, 69, 209, 251, 115, 14, 23, 172, 223, 215, 81, 242, 128, 87, 6, 131, 248, 212, 200, 188, 195, 36, 6, 173,
          0, 53, 33, 114, 117, 198, 181, 160, 85, 67, 29, 152, 170, 0, 108, 167, 225, 147, 58, 161, 22, 11, 69, 141, 76,
          203, 142, 48, 176, 47, 130, 71, 95, 166, 94, 221, 68, 233, 60, 196, 109, 131, 3, 119, 39, 172, 147, 75, 194,
          238, 231, 11, 233, 63, 91, 156, 106, 72, 121, 206, 65, 204, 36, 37, 145, 255, 140, 164, 70, 65, 89, 119, 8,
          125, 99, 159, 51, 158, 228, 116, 153, 192, 6, 62, 243, 177, 92, 28, 59, 247, 191, 250, 221, 15, 29, 41, 49,
          167, 38, 85, 162, 31, 13, 207, 184, 190, 227, 221, 112, 181, 143, 161, 208, 246, 73, 205, 205, 185, 115, 209,
          138, 105, 56, 93, 68, 183, 23, 188, 50, 200, 78, 210, 73, 215, 60, 86, 120, 89, 13, 64, 52, 189, 35, 48, 193,
          216, 189, 177, 93, 49, 147, 179, 167, 11, 223, 40, 144, 48, 223, 74, 206, 61, 131, 68, 212, 68, 80, 69, 83,
          213, 67, 244, 159, 230, 226, 184, 101, 214, 75, 10, 96, 30, 179, 31, 50, 116, 163, 176, 58, 165, 73, 148, 207,
          73, 180, 115, 16, 234, 248, 172, 238, 113, 9, 202, 117, 96, 154, 13, 27, 241, 218, 194, 127, 243, 243, 171,
          109, 14, 225, 249, 46, 140, 77, 144, 183, 244, 132, 90, 119, 114, 2, 185, 32, 79, 240, 116, 1, 44, 170, 224,
          156, 150, 183, 190, 25, 132, 190, 66, 145, 125, 189, 211, 128, 120, 246, 220, 120, 51, 54, 23, 129, 78, 184,
          226, 112, 54, 187, 219, 218, 183, 228, 227,
        ]),
        keep: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              138, 180, 144, 111, 215, 200, 34, 101, 204, 252, 168, 93, 222, 173, 232, 122, 135, 132, 128, 191, 235, 42,
              65, 87, 69, 12, 141, 55, 15, 212, 127, 251,
            ]),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              54, 85, 11, 179, 236, 72, 88, 165, 85, 48, 194, 250, 167, 170, 174, 183, 245, 33, 121, 123, 76, 56, 76,
              66, 62, 197, 48, 7, 76, 182, 193, 45,
            ]),
          },
          {
            h: 2,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              79, 174, 147, 214, 121, 205, 179, 115, 130, 217, 52, 216, 106, 20, 252, 57, 104, 25, 38, 126, 109, 159,
              95, 110, 67, 144, 96, 241, 62, 72, 147, 99,
            ]),
          },
          {
            h: 3,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              125, 215, 182, 50, 200, 203, 235, 194, 80, 61, 248, 188, 184, 31, 242, 140, 54, 73, 123, 114, 19, 207, 44,
              58, 206, 203, 97, 66, 77, 233, 87, 153,
            ]),
          },
          {
            h: 4,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              188, 70, 56, 170, 197, 170, 100, 25, 198, 47, 138, 203, 88, 157, 227, 79, 58, 221, 252, 47, 116, 58, 186,
              63, 71, 168, 48, 158, 40, 74, 120, 246,
            ]),
          },
          {
            h: 5,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              29, 174, 213, 191, 76, 166, 189, 78, 124, 99, 175, 182, 2, 97, 180, 101, 251, 241, 121, 0, 91, 78, 128,
              205, 202, 97, 215, 19, 88, 29, 222, 241,
            ]),
          },
          {
            h: 6,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              106, 80, 57, 115, 62, 29, 22, 213, 167, 2, 196, 102, 97, 109, 138, 199, 11, 243, 125, 151, 201, 128, 38,
              55, 234, 130, 174, 207, 77, 35, 219, 93,
            ]),
          },
          {
            h: 7,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              202, 110, 220, 51, 199, 211, 17, 131, 65, 253, 180, 164, 243, 76, 197, 6, 46, 52, 178, 194, 160, 8, 98, 6,
              70, 131, 45, 153, 51, 106, 231, 118,
            ]),
          },
        ],
        retain: new Uint8Array([
          55, 56, 230, 69, 249, 176, 209, 23, 75, 94, 43, 16, 39, 89, 27, 230, 200, 47, 254, 239, 134, 142, 56, 232, 71,
          199, 70, 173, 246, 139, 44, 160,
        ]),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 2, signatureType: 7, height: 10, addrFormatType: 13 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 2,
        height: 10,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });
  });

  describe('newXMSSFromSeed', () => {
    it('should generate xmss tree for seed[122, 12 ...]', () => {
      const seed = new Uint8Array([
        122, 12, 172, 214, 239, 194, 16, 161, 113, 166, 97, 235, 207, 90, 230, 216, 61, 90, 44, 213, 226, 30, 131, 85,
        96, 36, 106, 37, 115, 169, 158, 236, 17, 171, 235, 77, 50, 235, 94, 42, 21, 222, 35, 87, 151, 221, 190, 37,
      ]);
      const height = 12;
      const hashFunction = HASH_FUNCTION.SHA2_256;
      const addrFormatType = 4;
      const xmssTree = newXMSSFromSeed(seed, height, hashFunction, addrFormatType);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 12,
        k: 2,
      };
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 163, 248, 93, 138, 186, 254, 253, 129, 159, 214, 128, 156, 118, 94, 22, 193, 59, 99, 241, 156, 26,
        25, 79, 55, 225, 55, 254, 9, 83, 190, 135, 69, 3, 80, 157, 48, 170, 62, 23, 53, 244, 72, 50, 104, 91, 40, 151,
        144, 204, 71, 17, 160, 106, 81, 145, 155, 150, 206, 164, 22, 58, 255, 230, 205, 197, 205, 229, 54, 73, 171, 13,
        188, 203, 69, 156, 93, 111, 156, 86, 59, 232, 75, 144, 153, 143, 241, 214, 110, 161, 155, 135, 55, 190, 10, 60,
        218, 121, 243, 50, 119, 230, 31, 156, 244, 201, 186, 201, 173, 206, 221, 33, 14, 239, 14, 120, 94, 203, 152,
        117, 27, 110, 111, 150, 182, 6, 132, 39, 79,
      ]);
      const expectedSeed = new Uint8Array([
        122, 12, 172, 214, 239, 194, 16, 161, 113, 166, 97, 235, 207, 90, 230, 216, 61, 90, 44, 213, 226, 30, 131, 85,
        96, 36, 106, 37, 115, 169, 158, 236, 17, 171, 235, 77, 50, 235, 94, 42, 21, 222, 35, 87, 151, 221, 190, 37,
      ]);
      const expectedBdsState = {
        stack: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        stackOffset: 0,
        stackLevels: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        auth: new Uint8Array([
          39, 23, 239, 134, 120, 149, 201, 21, 254, 171, 197, 51, 154, 98, 104, 138, 20, 155, 230, 180, 65, 57, 91, 18,
          48, 248, 15, 30, 126, 205, 124, 236, 224, 181, 74, 105, 162, 146, 113, 15, 138, 156, 43, 222, 199, 95, 71,
          227, 6, 22, 116, 29, 72, 83, 39, 51, 26, 207, 130, 43, 93, 102, 75, 22, 151, 130, 134, 129, 4, 135, 243, 105,
          177, 145, 149, 36, 198, 87, 218, 203, 6, 15, 244, 245, 212, 224, 46, 239, 161, 29, 206, 244, 32, 59, 58, 201,
          214, 30, 57, 161, 147, 153, 86, 6, 221, 238, 0, 255, 118, 212, 204, 17, 225, 173, 236, 95, 199, 170, 181, 110,
          61, 156, 122, 2, 19, 104, 176, 82, 197, 216, 86, 65, 189, 130, 106, 100, 75, 251, 222, 199, 227, 166, 99, 175,
          219, 8, 162, 197, 143, 64, 206, 38, 227, 96, 204, 99, 185, 49, 70, 78, 127, 211, 86, 219, 239, 205, 80, 77, 7,
          135, 177, 233, 177, 38, 210, 114, 149, 207, 26, 26, 59, 252, 97, 71, 127, 161, 241, 226, 236, 153, 22, 255,
          16, 15, 29, 242, 204, 255, 36, 45, 101, 129, 206, 188, 107, 28, 140, 99, 29, 146, 119, 16, 249, 209, 178, 156,
          28, 241, 184, 235, 97, 222, 244, 208, 109, 230, 161, 135, 82, 203, 14, 127, 105, 97, 140, 208, 170, 20, 19,
          37, 247, 42, 88, 203, 191, 163, 146, 93, 42, 56, 118, 101, 102, 140, 186, 224, 137, 32, 10, 184, 111, 87, 212,
          32, 183, 36, 133, 80, 205, 152, 48, 9, 192, 159, 171, 107, 115, 165, 1, 236, 196, 244, 84, 110, 215, 102, 115,
          186, 34, 182, 95, 156, 186, 13, 235, 204, 133, 89, 158, 227, 192, 166, 239, 148, 123, 153, 193, 86, 194, 199,
          235, 206, 201, 6, 96, 13, 119, 3, 223, 65, 87, 100, 51, 173, 76, 188, 83, 163, 167, 72, 125, 188, 121, 60,
          207, 125, 113, 7, 234, 86, 139, 91, 111, 98, 159, 244, 189, 49, 2, 1, 225, 47, 148, 56, 142, 232, 200, 247,
          106, 6, 104, 133, 164, 214, 214, 148, 126, 174, 82, 39, 228, 125, 69, 217, 189, 137, 7, 115, 170, 234, 162,
          116, 229, 218,
        ]),
        keep: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0,
        ]),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              14, 85, 127, 154, 236, 15, 202, 158, 112, 250, 205, 237, 36, 250, 202, 95, 150, 12, 55, 150, 36, 111, 34,
              158, 42, 244, 101, 254, 248, 84, 84, 130,
            ]),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              18, 186, 148, 141, 111, 16, 72, 251, 247, 190, 253, 213, 198, 229, 68, 185, 55, 167, 195, 74, 180, 153,
              170, 142, 131, 91, 120, 249, 150, 77, 2, 37,
            ]),
          },
          {
            h: 2,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              165, 165, 237, 99, 209, 17, 138, 148, 41, 180, 167, 179, 228, 250, 156, 76, 63, 19, 104, 4, 200, 101, 194,
              50, 87, 160, 90, 166, 19, 119, 202, 229,
            ]),
          },
          {
            h: 3,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              74, 219, 165, 221, 15, 177, 87, 233, 195, 61, 219, 112, 234, 180, 212, 28, 33, 204, 199, 11, 93, 117, 90,
              11, 20, 155, 148, 251, 37, 115, 170, 175,
            ]),
          },
          {
            h: 4,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              125, 102, 76, 156, 94, 248, 216, 48, 223, 107, 86, 146, 193, 45, 12, 217, 182, 189, 36, 97, 105, 198, 224,
              56, 190, 142, 31, 193, 191, 38, 6, 17,
            ]),
          },
          {
            h: 5,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              182, 47, 232, 123, 241, 23, 108, 174, 170, 229, 179, 7, 20, 136, 82, 19, 198, 20, 56, 10, 219, 212, 175,
              164, 37, 190, 138, 174, 48, 203, 29, 233,
            ]),
          },
          {
            h: 6,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              216, 3, 117, 250, 163, 244, 38, 233, 195, 137, 195, 79, 253, 216, 106, 241, 44, 68, 93, 33, 108, 157, 246,
              72, 194, 97, 3, 156, 111, 17, 199, 58,
            ]),
          },
          {
            h: 7,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              200, 224, 50, 136, 105, 30, 232, 36, 159, 224, 201, 216, 165, 113, 178, 83, 150, 81, 100, 93, 70, 164,
              226, 118, 41, 4, 90, 104, 229, 84, 235, 82,
            ]),
          },
          {
            h: 8,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              131, 29, 210, 52, 195, 101, 131, 19, 163, 217, 4, 7, 17, 160, 97, 17, 212, 205, 48, 209, 233, 120, 152,
              12, 116, 123, 115, 202, 51, 1, 100, 224,
            ]),
          },
          {
            h: 9,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              53, 73, 146, 210, 134, 46, 33, 117, 62, 202, 61, 136, 137, 110, 33, 192, 28, 1, 167, 250, 131, 37, 78, 89,
              153, 238, 212, 184, 172, 2, 153, 202,
            ]),
          },
        ],
        retain: new Uint8Array([
          251, 64, 34, 233, 66, 23, 138, 134, 102, 201, 225, 216, 251, 19, 167, 160, 171, 146, 178, 80, 174, 82, 119,
          201, 73, 202, 101, 168, 137, 21, 122, 4,
        ]),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 0, signatureType: 1, height: 12, addrFormatType: 4 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 0,
        height: 12,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });

    it('should generate xmss tree for seed[107, 11 ...]', () => {
      const seed = new Uint8Array([
        107, 11, 136, 223, 17, 9, 167, 8, 52, 13, 70, 183, 52, 6, 148, 158, 39, 230, 155, 20, 240, 188, 38, 162, 174,
        154, 34, 158, 83, 70, 225, 88, 132, 207, 21, 105, 155, 89, 7, 247, 172, 118, 81, 64, 19, 122, 221, 199,
      ]);
      const height = 6;
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const addrFormatType = 3;
      const xmssTree = newXMSSFromSeed(seed, height, hashFunction, addrFormatType);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 6,
        k: 2,
      };
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 150, 178, 143, 132, 233, 120, 243, 203, 98, 249, 23, 78, 218, 209, 24, 234, 53, 38, 3, 30, 27, 171,
        26, 134, 53, 200, 114, 88, 175, 231, 66, 100, 9, 96, 92, 40, 57, 84, 205, 78, 185, 43, 85, 253, 174, 137, 186,
        199, 217, 245, 98, 202, 182, 118, 180, 117, 131, 113, 79, 68, 105, 81, 247, 28, 220, 7, 173, 40, 156, 155, 94,
        175, 144, 142, 134, 8, 78, 240, 29, 190, 209, 36, 187, 230, 19, 184, 137, 138, 149, 48, 168, 247, 172, 158, 200,
        123, 193, 187, 46, 87, 205, 77, 72, 94, 135, 90, 82, 119, 177, 235, 231, 155, 220, 244, 26, 91, 148, 85, 29,
        152, 164, 247, 193, 251, 224, 250, 68, 19,
      ]);
      const expectedSeed = new Uint8Array([
        107, 11, 136, 223, 17, 9, 167, 8, 52, 13, 70, 183, 52, 6, 148, 158, 39, 230, 155, 20, 240, 188, 38, 162, 174,
        154, 34, 158, 83, 70, 225, 88, 132, 207, 21, 105, 155, 89, 7, 247, 172, 118, 81, 64, 19, 122, 221, 199,
      ]);
      const expectedBdsState = {
        stack: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0,
        ]),
        stackOffset: 0,
        stackLevels: new Uint8Array([0, 0, 0, 0, 0, 0, 0]),
        auth: new Uint8Array([
          3, 194, 192, 227, 227, 245, 117, 249, 144, 125, 94, 39, 122, 105, 55, 11, 73, 18, 203, 25, 19, 179, 106, 11,
          60, 157, 30, 149, 171, 143, 101, 114, 111, 59, 56, 182, 172, 65, 238, 199, 83, 197, 38, 104, 20, 80, 73, 44,
          25, 56, 171, 44, 198, 209, 12, 146, 232, 105, 94, 172, 11, 165, 148, 156, 106, 91, 48, 27, 208, 98, 139, 158,
          150, 40, 14, 3, 135, 46, 67, 25, 185, 86, 160, 109, 149, 71, 57, 155, 121, 81, 122, 55, 62, 214, 64, 225, 211,
          222, 171, 111, 139, 107, 117, 72, 115, 214, 138, 25, 97, 41, 105, 21, 184, 221, 91, 210, 184, 27, 158, 177,
          204, 188, 135, 168, 199, 41, 98, 53, 15, 178, 163, 27, 190, 151, 47, 112, 223, 99, 31, 138, 80, 168, 110, 118,
          173, 195, 50, 59, 44, 196, 4, 228, 58, 153, 197, 190, 166, 33, 70, 95, 153, 79, 13, 123, 72, 223, 2, 37, 118,
          179, 180, 115, 85, 210, 33, 80, 119, 11, 25, 250, 251, 5, 242, 116, 247, 84, 93, 236, 61, 250, 92, 192,
        ]),
        keep: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              244, 76, 32, 3, 174, 246, 165, 149, 85, 120, 5, 182, 134, 50, 42, 46, 55, 188, 119, 139, 32, 179, 185,
              240, 100, 33, 224, 38, 177, 118, 136, 62,
            ]),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              37, 203, 68, 106, 249, 9, 162, 244, 140, 119, 60, 6, 53, 121, 174, 225, 75, 209, 199, 176, 78, 140, 55,
              230, 53, 252, 154, 140, 243, 22, 11, 49,
            ]),
          },
          {
            h: 2,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              153, 165, 71, 53, 180, 219, 213, 197, 184, 209, 133, 151, 194, 10, 193, 177, 10, 234, 127, 109, 176, 164,
              71, 71, 129, 1, 81, 64, 48, 61, 60, 211,
            ]),
          },
          {
            h: 3,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              224, 71, 69, 133, 173, 204, 157, 26, 61, 233, 155, 196, 228, 54, 88, 45, 206, 165, 132, 247, 225, 121,
              112, 67, 153, 168, 115, 49, 200, 64, 4, 195,
            ]),
          },
        ],
        retain: new Uint8Array([
          35, 71, 147, 149, 151, 130, 143, 173, 221, 227, 108, 150, 16, 43, 222, 253, 172, 26, 189, 34, 196, 248, 81,
          52, 229, 254, 141, 175, 46, 199, 30, 8,
        ]),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 1, signatureType: 1, height: 6, addrFormatType: 3 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 1,
        height: 6,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });
  });

  describe('newXMSSFromExtendedSeed', () => {
    it('should generate xmss tree for extendedSeed[214, 194 ...]', () => {
      const extendedSeed = new Uint8Array([
        214, 194, 166, 208, 12, 19, 66, 136, 10, 70, 2, 11, 194, 117, 223, 80, 115, 176, 220, 223, 5, 105, 238, 186,
        102, 21, 34, 20, 242, 103, 8, 210, 212, 21, 85, 234, 167, 59, 19, 225, 9, 17, 49, 51, 0, 158, 70, 214, 108, 85,
        175,
      ]);
      const xmssTree = newXMSSFromExtendedSeed(extendedSeed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 4,
        k: 2,
      };
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 76, 200, 159, 241, 89, 59, 24, 197, 174, 65, 210, 144, 235, 195, 150, 124, 138, 113, 75, 34, 143,
        30, 141, 35, 142, 22, 247, 240, 38, 10, 111, 175, 75, 10, 150, 235, 154, 111, 135, 53, 166, 223, 200, 146, 170,
        63, 73, 200, 95, 145, 52, 87, 65, 118, 183, 231, 208, 118, 223, 174, 23, 214, 117, 125, 91, 29, 99, 142, 39,
        242, 26, 197, 139, 26, 234, 136, 11, 174, 61, 89, 230, 40, 210, 127, 38, 84, 171, 208, 182, 193, 182, 52, 74,
        225, 50, 195, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      const expectedSeed = new Uint8Array([
        208, 12, 19, 66, 136, 10, 70, 2, 11, 194, 117, 223, 80, 115, 176, 220, 223, 5, 105, 238, 186, 102, 21, 34, 20,
        242, 103, 8, 210, 212, 21, 85, 234, 167, 59, 19, 225, 9, 17, 49, 51, 0, 158, 70, 214, 108, 85, 175,
      ]);
      const expectedBdsState = {
        stack: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        stackOffset: 0,
        stackLevels: new Uint8Array([0, 0, 0, 0, 0]),
        auth: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        keep: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
          },
        ],
        retain: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 6, signatureType: 13, height: 4, addrFormatType: 12 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 6,
        height: 4,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });

    it('should generate xmss tree for extendedSeed[184, 179 ...]', () => {
      const extendedSeed = new Uint8Array([
        184, 179, 172, 206, 173, 95, 229, 42, 104, 198, 74, 183, 196, 51, 147, 126, 200, 172, 30, 224, 248, 240, 36,
        250, 252, 58, 45, 66, 252, 41, 126, 29, 58, 90, 176, 180, 147, 126, 198, 154, 6, 130, 232, 28, 62, 24, 43, 50,
        158, 217, 228,
      ]);
      const xmssTree = newXMSSFromExtendedSeed(extendedSeed);
      const expectedXmssParams = {
        wotsParams: {
          len1: 64,
          len2: 3,
          len: 67,
          n: 32,
          w: 16,
          logW: 4,
          keySize: 2144,
        },
        n: 32,
        h: 6,
        k: 2,
      };
      const expectedSk = new Uint8Array([
        0, 0, 0, 0, 171, 188, 99, 188, 157, 216, 137, 54, 83, 153, 230, 71, 16, 220, 222, 55, 49, 208, 81, 194, 210, 3,
        113, 98, 171, 116, 198, 153, 233, 129, 139, 200, 188, 96, 151, 144, 72, 209, 75, 167, 160, 255, 144, 234, 182,
        93, 110, 175, 29, 219, 31, 141, 248, 11, 185, 233, 156, 115, 198, 167, 250, 195, 39, 5, 124, 181, 255, 157, 62,
        40, 32, 194, 40, 252, 181, 40, 170, 152, 83, 106, 16, 192, 251, 238, 74, 211, 167, 179, 37, 196, 118, 9, 175,
        28, 66, 91, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      const expectedSeed = new Uint8Array([
        206, 173, 95, 229, 42, 104, 198, 74, 183, 196, 51, 147, 126, 200, 172, 30, 224, 248, 240, 36, 250, 252, 58, 45,
        66, 252, 41, 126, 29, 58, 90, 176, 180, 147, 126, 198, 154, 6, 130, 232, 28, 62, 24, 43, 50, 158, 217, 228,
      ]);
      const expectedBdsState = {
        stack: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0,
        ]),
        stackOffset: 0,
        stackLevels: new Uint8Array([0, 0, 0, 0, 0, 0, 0]),
        auth: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0,
        ]),
        keep: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        treeHash: [
          {
            h: 0,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
          },
          {
            h: 1,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
          },
          {
            h: 2,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
          },
          {
            h: 3,
            nextIdx: 0,
            stackUsage: 0,
            completed: 1,
            node: new Uint8Array([
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
          },
        ],
        retain: new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        nextLeaf: 0,
      };
      const expectedDesc = { hashFunction: 8, signatureType: 11, height: 6, addrFormatType: 11 };
      const expectedXmssTree = {
        xmssParams: expectedXmssParams,
        hashFunction: 8,
        height: 6,
        sk: expectedSk,
        seed: expectedSeed,
        bdsState: expectedBdsState,
        desc: expectedDesc,
      };

      expect(xmssTree.xmssParams).to.deep.equal(expectedXmssTree.xmssParams);
      expect(xmssTree.hashFunction).to.deep.equal(expectedXmssTree.hashFunction);
      expect(xmssTree.height).to.deep.equal(expectedXmssTree.height);
      expect(xmssTree.sk).to.deep.equal(expectedXmssTree.sk);
      expect(xmssTree.seed).to.deep.equal(expectedXmssTree.seed);
      expect(xmssTree.bdsState).to.deep.equal(expectedXmssTree.bdsState);
      expect(xmssTree.desc).to.deep.equal(expectedXmssTree.desc);
      expect(xmssTree).to.deep.equal(expectedXmssTree);
    });
  });

  describe('newXMSSFromHeight', () => {
    it('should generate a xmss tree', () => {
      const height = 6;
      const hashFunction = HASH_FUNCTION.SHAKE_128;
      const xmssTree = newXMSSFromHeight(height, hashFunction);

      expect(Object.getOwnPropertyNames(xmssTree)).to.deep.equal([
        'xmssParams',
        'hashFunction',
        'height',
        'sk',
        'seed',
        'bdsState',
        'desc',
      ]);
    });

    it('should generate a xmss tree from random seed each time', () => {
      const height = 6;
      const hashFunction = HASH_FUNCTION.SHAKE_256;
      const { seed: randomSeed1 } = newXMSSFromHeight(height, hashFunction);
      const { seed: randomSeed2 } = newXMSSFromHeight(height, hashFunction);

      expect(randomSeed1).not.to.deep.equal(randomSeed2);
    });
  });

  describe('getXMSSAddressFromPK', () => {
    it('should throw an error if QRL descriptor address format type is not SHA_256', () => {
      const ePK = new Uint8Array([
        240, 128, 131, 4, 135, 135, 133, 223, 122, 68, 32, 197, 228, 178, 18, 135, 32, 136, 162, 246, 150, 15, 233, 102,
        45, 199, 126, 40, 75, 204, 85, 209, 127, 50, 81, 8, 248, 48, 90, 124, 46, 157, 183, 28, 90, 137, 75, 93, 89, 29,
        44, 113, 173, 190, 146, 102, 4, 89, 139, 253, 157, 197, 232, 37, 24, 102, 164,
      ]);

      expect(() => getXMSSAddressFromPK(ePK)).to.throw('Address format type not supported');
    });

    it('should generate an address for ePK[222, 0, ...]', () => {
      const ePK = new Uint8Array([
        222, 0, 123, 124, 112, 218, 61, 237, 137, 199, 97, 99, 20, 29, 57, 212, 69, 210, 127, 234, 120, 116, 54, 165, 4,
        214, 159, 56, 7, 55, 69, 133, 80, 162, 9, 175, 17, 70, 178, 160, 181, 183, 33, 131, 161, 243, 191, 126, 28, 199,
        159, 138, 103, 215, 227, 22, 164, 233, 196, 23, 139, 213, 127, 155, 96, 241, 35,
      ]);
      const address = getXMSSAddressFromPK(ePK);
      const expectedAddress = new Uint8Array([
        222, 0, 0, 154, 168, 199, 132, 10, 231, 152, 7, 212, 3, 165, 140, 55, 38, 78, 178, 232,
      ]);

      expect(address).to.deep.equal(expectedAddress);
    });

    it('should generate an address for ePK[186, 0, ...]', () => {
      const ePK = new Uint8Array([
        186, 0, 63, 100, 24, 159, 52, 132, 38, 6, 108, 37, 39, 71, 247, 52, 195, 100, 17, 238, 106, 210, 74, 19, 104,
        10, 174, 129, 14, 103, 175, 39, 169, 50, 149, 10, 118, 176, 22, 44, 48, 128, 160, 185, 3, 25, 149, 182, 222,
        137, 136, 191, 152, 247, 158, 83, 8, 172, 192, 142, 47, 202, 137, 234, 207, 251, 203,
      ]);
      const address = getXMSSAddressFromPK(ePK);
      const expectedAddress = new Uint8Array([
        186, 0, 0, 159, 128, 46, 176, 187, 231, 134, 36, 252, 141, 177, 138, 118, 97, 126, 114, 73,
      ]);

      expect(address).to.deep.equal(expectedAddress);
    });
  });
});
