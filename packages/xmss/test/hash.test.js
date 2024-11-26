import { expect } from 'chai';
import { describe, it } from 'mocha';
import { HASH_FUNCTION } from '../src/constants.js';
import { coreHash, hashH, prf } from '../src/hash.js';
import { getUInt8ArrayFromHex } from './testUtility.js';

describe('Test cases for [hash]', () => {
  describe('coreHash', () => {
    it('should generate coreHash output for the hashFunction SHA2_256', () => {
      const outValue = getUInt8ArrayFromHex('0304050c0507220517101704050c2d07220517381704050c2d07220517380329');
      coreHash(
        HASH_FUNCTION.SHA2_256,
        outValue,
        2,
        getUInt8ArrayFromHex('010000000501'),
        6,
        getUInt8ArrayFromHex('09090909'),
        4,
        9
      );
      const expectedOutValue = getUInt8ArrayFromHex('c2d660c43291b8ef1406b1bba683fef08ecfafbd34fa96509dc45478898d41d2');

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate coreHash output for the hashFunction SHAKE_128', () => {
      const outValue = getUInt8ArrayFromHex('0102030405');
      coreHash(
        HASH_FUNCTION.SHAKE_128,
        outValue,
        5,
        getUInt8ArrayFromHex('000000'),
        3,
        getUInt8ArrayFromHex('040506'),
        3,
        4
      );
      const expectedOutValue = getUInt8ArrayFromHex('7301742142');

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate coreHash output for the hashFunction SHAKE_256', () => {
      const outValue = getUInt8ArrayFromHex('08040901000100');
      coreHash(
        HASH_FUNCTION.SHAKE_256,
        outValue,
        7,
        getUInt8ArrayFromHex('0603'),
        2,
        getUInt8ArrayFromHex('090708010508'),
        6,
        1
      );
      const expectedOutValue = getUInt8ArrayFromHex('3245da3bef6636');

      expect(outValue).to.deep.equal(expectedOutValue);
    });
  });

  describe('prf', () => {
    it('should generate prf output for the hashFunction SHA2_256', () => {
      const outValue = getUInt8ArrayFromHex('0704050c2d07620517381704050c2d07220517381704050c2d07220517380301');
      prf(
        HASH_FUNCTION.SHA2_256,
        outValue,
        getUInt8ArrayFromHex('0204050104060708090202040501040607080902020405010406070809020304'),
        getUInt8ArrayFromHex('060302'),
        2
      );
      const expectedOutValue = getUInt8ArrayFromHex('459a2a76416196ebc2b1ddc219500518fc3dfcd69c9f6b8bb71adba6446b4880');

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate prf output for the hashFunction SHAKE_128', () => {
      const outValue = getUInt8ArrayFromHex('08040901000100');
      prf(
        HASH_FUNCTION.SHAKE_128,
        outValue,
        getUInt8ArrayFromHex('0204050104060708090202040501040607080902020405010406070809020304'),
        getUInt8ArrayFromHex('060302'),
        2
      );
      const expectedOutValue = getUInt8ArrayFromHex('97a2b961ff333d');

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate prf output for the hashFunction SHAKE_256', () => {
      const outValue = getUInt8ArrayFromHex('08040901000100');
      prf(
        HASH_FUNCTION.SHAKE_256,
        outValue,
        getUInt8ArrayFromHex('0204050104060708090202040501040607080902020405010406070809020304'),
        getUInt8ArrayFromHex('060302'),
        2
      );
      const expectedOutValue = getUInt8ArrayFromHex('e5946bd3d12bf5');

      expect(outValue).to.deep.equal(expectedOutValue);
    });
  });

  describe('hashH', () => {
    it('should generate hashH output for the hashFunction SHA2_256', () => {
      const outValue = getUInt8ArrayFromHex('4704050c2d07620517381704050c2d07220517381704050c2d07220517380309');
      hashH(
        HASH_FUNCTION.SHA2_256,
        outValue,
        getUInt8ArrayFromHex('02040306'),
        getUInt8ArrayFromHex('08040302'),
        getUInt8ArrayFromHex('0307020702080703'),
        getUInt8ArrayFromHex('20')[0]
      );
      const expectedOutValue = getUInt8ArrayFromHex('134666d0ac117b0f51baffac3b340d1d32b66a15f1dba919b35d74038ff7a26e');

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate hashH output for the hashFunction SHAKE_128', () => {
      const outValue = getUInt8ArrayFromHex('08010003060809020608');
      hashH(
        HASH_FUNCTION.SHAKE_128,
        outValue,
        getUInt8ArrayFromHex('02040304060806'),
        getUInt8ArrayFromHex('0804042b02'),
        getUInt8ArrayFromHex('0307020807030000'),
        getUInt8ArrayFromHex('03')[0]
      );
      const expectedOutValue = getUInt8ArrayFromHex('f38b5506b4d82b482e0b');

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should generate hashH output for the hashFunction SHAKE_256', () => {
      const outValue = getUInt8ArrayFromHex('0203050708090100');
      hashH(
        HASH_FUNCTION.SHAKE_256,
        outValue,
        getUInt8ArrayFromHex('020306'),
        getUInt8ArrayFromHex('040302'),
        getUInt8ArrayFromHex('0300000000000208'),
        getUInt8ArrayFromHex('01')[0]
      );
      const expectedOutValue = getUInt8ArrayFromHex('95c26bb1d0666a4a');

      expect(outValue).to.deep.equal(expectedOutValue);
    });

    it('should modify the out variable correctly if the same variable sliced and passed for input and out', () => {
      const paramHashFunction = HASH_FUNCTION.SHAKE_256;
      const paramOut = getUInt8ArrayFromHex('0203050107030803080309020902070709');
      const paramPubSeed = getUInt8ArrayFromHex('0205010501060306');
      const paramAddr = getUInt8ArrayFromHex('0305010206080302');
      const paramN = getUInt8ArrayFromHex('02')[0];
      const expectedOut = getUInt8ArrayFromHex('02034201d6c9d6eb03d709020902070709');
      hashH(paramHashFunction, paramOut.subarray(2, 10), paramOut.subarray(4, 12), paramPubSeed, paramAddr, paramN);
      expect(paramOut).to.deep.equal(expectedOut);
    });
  });
});
