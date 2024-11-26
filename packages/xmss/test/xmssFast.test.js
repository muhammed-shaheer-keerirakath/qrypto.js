import { expect } from 'chai';
import { newBDSState, newTreeHashInst, newWOTSParams, newXMSSParams } from '../src/classes.js';
import { HASH_FUNCTION } from '../src/constants.js';
import {
  bdsRound,
  bdsTreeHashUpdate,
  expandSeed,
  genChain,
  genLeafWOTS,
  getSeed,
  hashF,
  lTree,
  treeHashMinHeightOnStack,
  treeHashUpdate,
  wOTSPKGen,
} from '../src/xmssFast.js';
import { getUInt32ArrayFromHex, getUInt8ArrayFromHex } from './testUtility.js';

describe('Test cases for [xmssFast]', () => {
  describe('getSeed', () => {
    it('should update the seed variable with hashFunction SHA2_256', () => {
      const seed = getUInt8ArrayFromHex('1704050c2d07220517381704050c2d07220517381704050c2d07220517380304');
      getSeed(
        HASH_FUNCTION.SHA2_256,
        seed,
        getUInt8ArrayFromHex('0205010904090100'),
        1,
        getUInt8ArrayFromHex('0300000000000208')
      );
      const expectedSeed = getUInt8ArrayFromHex('dcf95c61e21dd076674d91fd9bacd3ea0021b0bd8c09b09fd74f7cd8f3974dd6');

      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should update the seed variable with hashFunction SHAKE_128', () => {
      const seed = getUInt8ArrayFromHex('0203050704090100');
      getSeed(
        HASH_FUNCTION.SHAKE_128,
        seed,
        getUInt8ArrayFromHex('0205010904090100'),
        1,
        getUInt32ArrayFromHex('0000000300000000000000000000000000000000000000000000000200000008')
      );
      const expectedSeed = getUInt8ArrayFromHex('345bbd9e3a3c9a5f');

      expect(seed).to.deep.equal(expectedSeed);
    });

    it('should update the seed variable with hashFunction SHAKE_256', () => {
      const seed = getUInt8ArrayFromHex('0203050704090100');
      getSeed(
        HASH_FUNCTION.SHAKE_256,
        seed,
        getUInt8ArrayFromHex('0205010904090100'),
        1,
        getUInt32ArrayFromHex('0000000300000000000000000000000000000000000000000000000200000008')
      );
      const expectedSeed = getUInt8ArrayFromHex('1c58e2fec10caea7');

      expect(seed).to.deep.equal(expectedSeed);
    });
  });

  describe('expandSeed', () => {
    it('should expand the outseeds based on the inseeds provided', () => {
      const outSeeds = getUInt8ArrayFromHex('0305010207020703');
      const inSeeds = getUInt8ArrayFromHex('0902010304040302020703');
      const n = 2;
      const len = 3;
      const expectedOutSeeds = getUInt8ArrayFromHex('4adc67ce33d20703');
      const expectedInSeeds = getUInt8ArrayFromHex('0902010304040302020703');
      expandSeed(HASH_FUNCTION.SHAKE_256, outSeeds, inSeeds, n, len);

      expect(outSeeds).to.deep.equal(expectedOutSeeds);
      expect(inSeeds).to.deep.equal(expectedInSeeds);
    });
  });

  describe('hashF', () => {
    it('should set the result to the out variable, with SHAKE_128', () => {
      const out = getUInt8ArrayFromHex('0305010207020703');
      const input = getUInt8ArrayFromHex('010304040302020703');
      const pubSeed = getUInt8ArrayFromHex('090204050704040302020703');
      const addr = getUInt32ArrayFromHex('0000000700000004000000080000000200000006000000000000000200000005');
      const n = 2;
      const expectedOut = getUInt8ArrayFromHex('744ed2998f2ce23c');
      const expectedInput = getUInt8ArrayFromHex('010304040302020703');
      const expectedPubSeed = getUInt8ArrayFromHex('090204050704040302020703');
      const expectedAddr = getUInt32ArrayFromHex('0000000700000004000000080000000200000006000000000000000200000001');
      hashF(HASH_FUNCTION.SHAKE_128, out, input, pubSeed, addr, n);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should set the result to the out variable, with SHA2_256', () => {
      const out = getUInt8ArrayFromHex(
        '0103040403020207030103040403020207030103040403020207030103040403030501020702070303050102070207030305010207020703'
      );
      const pubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000200000009');
      const n = 32;
      const expectedOut = getUInt8ArrayFromHex(
        '535b1a6f45bdd4796c7db5a811f111e6387f2f39a36f18c42fde67fbd4eff9ca030501020702070303050102070207030305010207020703'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000200000001');
      hashF(HASH_FUNCTION.SHA2_256, out, out, pubSeed, addr, n);

      expect(out).to.deep.equal(expectedOut);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('genChain', () => {
    it('should generate chain in the out variable, with SHA2_256 hashing', () => {
      const out = getUInt8ArrayFromHex(
        '0305010207020703030501020702070303050102070207030305010207020703030501020702070303050102070207030305010207020703'
      );
      const input = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const start = 2;
      const steps = 3;
      const n = 32;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000900000009');
      const expectedOut = getUInt8ArrayFromHex(
        'c57b9ace078f80a2c16d26b4c3adae9224ea50857c9946733a504c56c1bfdd33030501020702070303050102070207030305010207020703'
      );
      const expectedInput = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000400000001');
      genChain(HASH_FUNCTION.SHA2_256, out, input, start, steps, params, pubSeed, addr);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate chain in the out variable, with SHAKE_128 hashing', () => {
      const out = getUInt8ArrayFromHex(
        '0305010207020703030501020702070303050102070207030305010207020703030501020702070303050102070207030305010207020703'
      );
      const input = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const start = 2;
      const steps = 3;
      const n = 32;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000900000009');
      const expectedOut = getUInt8ArrayFromHex(
        '7e9ef0fe02cfa01c59077cd4f18473c0597a78376f6c270cf508c1267909b616581921a5ce1b4ed1bca8a9987b591c9cdddb8b9bbbd0bbe0'
      );
      const expectedInput = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000400000001');
      genChain(HASH_FUNCTION.SHAKE_128, out, input, start, steps, params, pubSeed, addr);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate chain in the out variable, with SHAKE_256 hashing', () => {
      const out = getUInt8ArrayFromHex(
        '0305010207020703030501020702070303050102070207030305010207020703030501020702070303050102070207030305010207020703'
      );
      const input = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const start = 2;
      const steps = 3;
      const n = 32;
      const w = 16;
      const params = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000900000009');
      const expectedOut = getUInt8ArrayFromHex(
        '79923637c41f0a0c136d474e05a89eceee8c710682d51f4c0c904765e67243e3a98944526187afdd4615457c7824c6170f145aca4ebb6957'
      );
      const expectedInput = getUInt8ArrayFromHex(
        '010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703010304040302020703'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '04050301030202070304050708040503010302020703040507080405030103020207030405070804050301030202070304050708'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000400000001');
      genChain(HASH_FUNCTION.SHAKE_256, out, input, start, steps, params, pubSeed, addr);

      expect(out).to.deep.equal(expectedOut);
      expect(input).to.deep.equal(expectedInput);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('wOTSPKGen', () => {
    it('should generate public key, with SHA2_256 hashing', () => {
      const pk = getUInt8ArrayFromHex(
        '04020204090004162137580b21060809020106090004162137580b21090004162137580b210608090204020204090004162137580b21060809020106090004162137580b21090004162137580b210608090204020204090004162137580b21060809020106090004162137580b21090004162137580b2106080902'
      );
      const sk = getUInt8ArrayFromHex('0403020303050102070207030305');
      const w = 5;
      const n = 2;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('08030106090002010305');
      const addr = getUInt32ArrayFromHex('000000160000002c000000050000000700000021000000070000000800000016');
      const expectedPk = getUInt8ArrayFromHex(
        '33220f9103d593369099b733786fd9fc741dab3b8126162137580b21090004162137580b210608090204020204090004162137580b21060809020106090004162137580b21090004162137580b210608090204020204090004162137580b21060809020106090004162137580b21090004162137580b2106080902'
      );
      const expectedSk = getUInt8ArrayFromHex('0403020303050102070207030305');
      const expectedPubSeed = getUInt8ArrayFromHex('08030106090002010305');
      const expectedAddr = getUInt32ArrayFromHex('000000160000002c0000000500000007000000210000000a0000000300000001');
      wOTSPKGen(HASH_FUNCTION.SHA2_256, pk, sk, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate public key, with SHAKE_128 hashing', () => {
      const pk = getUInt8ArrayFromHex(
        '030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703'
      );
      const sk = getUInt8ArrayFromHex('0103040403020207030103040403020303050102070207030305');
      const w = 6;
      const n = 3;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('060301050603');
      const addr = getUInt32ArrayFromHex('000000080000002c000000050000000700000021000000070000000800000016');
      const expectedPk = getUInt8ArrayFromHex(
        'f8db6aea6471ec2c820bdcadece3cc6f1d3168b1dd1bec8f7a8378bf4509d891626ab9525cd1877efd30319c19030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703'
      );
      const expectedSk = getUInt8ArrayFromHex('0103040403020207030103040403020303050102070207030305');
      const expectedPubSeed = getUInt8ArrayFromHex('060301050603');
      const expectedAddr = getUInt32ArrayFromHex('000000080000002c0000000500000007000000210000000e0000000400000001');
      wOTSPKGen(HASH_FUNCTION.SHAKE_128, pk, sk, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate public key, with SHAKE_256 hashing', () => {
      const pk = getUInt8ArrayFromHex(
        '030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703'
      );
      const sk = getUInt8ArrayFromHex('0103040403020207030103040403020303050102070207030305');
      const w = 16;
      const n = 7;
      const wotsParams = newWOTSParams(n, w);
      const pubSeed = getUInt8ArrayFromHex('04050301030202');
      const addr = getUInt32ArrayFromHex('0000000400000003000000020000000200000007000000030000000900000009');
      const expectedPk = getUInt8ArrayFromHex(
        'ce5d0c8fb9644567020aa13bbd60048c71a41b8e4070fa42f03c024c5c2ad51995502c467b9fc916212085cab85fdd3585c823c621ced9505b31c8a3d951bfac81f8eff90f9cecae95700e2c9898ab25f20495b146e99b4c2f86f3e7f23aceddd392637ff9101607bff292f235ec7bb60303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703030501070303070207030303050102070207030305010207020703'
      );
      const expectedSk = getUInt8ArrayFromHex('0103040403020207030103040403020303050102070207030305');
      const expectedPubSeed = getUInt8ArrayFromHex('04050301030202');
      const expectedAddr = getUInt32ArrayFromHex('00000004000000030000000200000002000000070000000f0000000e00000001');
      wOTSPKGen(HASH_FUNCTION.SHAKE_256, pk, sk, wotsParams, pubSeed, addr);

      expect(pk).to.deep.equal(expectedPk);
      expect(sk).to.deep.equal(expectedSk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('lTree', () => {
    it('should generate lTree, with SHA2_256 hashing', () => {
      const n = 2;
      const w = 256;
      const params = newWOTSParams(n, w);
      const leaf = getUInt8ArrayFromHex('214409022d4d050307090207090208020507214409022d4d1738184e63');
      const wotsPk = getUInt8ArrayFromHex(
        '38184e63214438184e6309022d4d1738184e63050307214409022d4d1738184e63214409022d4d1738184e63050307'
      );
      const pubSeed = getUInt8ArrayFromHex('050307090207090208020507214409022d4d1738184e63');
      const addr = getUInt8ArrayFromHex('0403020207030909');
      const expectedLeaf = getUInt8ArrayFromHex('697309022d4d050307090207090208020507214409022d4d1738184e63');
      const expectedWotsPk = getUInt8ArrayFromHex(
        '6973245e214438184e6309022d4d1738184e63050307214409022d4d1738184e63214409022d4d1738184e63050307'
      );
      const expectedPubSeed = getUInt8ArrayFromHex('050307090207090208020507214409022d4d1738184e63');
      const expectedAddr = getUInt8ArrayFromHex('0403020207020002');
      lTree(HASH_FUNCTION.SHA2_256, params, leaf, wotsPk, pubSeed, addr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(wotsPk).to.deep.equal(expectedWotsPk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate lTree, with SHAKE_128 hashing', () => {
      const n = 1;
      const w = 6;
      const params = newWOTSParams(n, w);
      const leaf = getUInt8ArrayFromHex('6304032d4d02060802090308164f02');
      const wotsPk = getUInt8ArrayFromHex(
        '3b022d4d1738184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070406080207051603044d'
      );
      const pubSeed = getUInt8ArrayFromHex('0507214409022d4d173818050307090207090208020507214409022d4d1738184e63');
      const addr = getUInt8ArrayFromHex('0920020703160909');
      const expectedLeaf = getUInt8ArrayFromHex('2e04032d4d02060802090308164f02');
      const expectedWotsPk = getUInt8ArrayFromHex(
        '2e6148181738184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070406080207051603044d'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '0507214409022d4d173818050307090207090208020507214409022d4d1738184e63'
      );
      const expectedAddr = getUInt8ArrayFromHex('0920020703030002');
      lTree(HASH_FUNCTION.SHAKE_128, params, leaf, wotsPk, pubSeed, addr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(wotsPk).to.deep.equal(expectedWotsPk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should generate lTree, with SHAKE_256 hashing', () => {
      const n = 1;
      const w = 6;
      const params = newWOTSParams(n, w);
      const leaf = getUInt8ArrayFromHex('060802090308166304032d4d024f02');
      const wotsPk = getUInt8ArrayFromHex(
        '4409022d4d1738184e3b022d4d1738184e6321630503070438184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070406080207051603044d'
      );
      const pubSeed = getUInt8ArrayFromHex('050307090207090208023707214409022d4d17381807214409022d4d1738184e63');
      const addr = getUInt8ArrayFromHex('2c0b060703160909');
      const expectedLeaf = getUInt8ArrayFromHex('070802090308166304032d4d024f02');
      const expectedWotsPk = getUInt8ArrayFromHex(
        '072970384d1738184e3b022d4d1738184e6321630503070438184e63214409022d4d1738184e630503070438184e63214409022d4d1738184e630503070406080207051603044d'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '050307090207090208023707214409022d4d17381807214409022d4d1738184e63'
      );
      const expectedAddr = getUInt8ArrayFromHex('2c0b060703030002');
      lTree(HASH_FUNCTION.SHAKE_256, params, leaf, wotsPk, pubSeed, addr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(wotsPk).to.deep.equal(expectedWotsPk);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('genLeafWOTS', () => {
    it('should generate leafWOTS, with SHA2_256 hashing', () => {
      const leaf = getUInt8ArrayFromHex('030504070206010501020503020602070305010205030206');
      const skSeed = getUInt8ArrayFromHex('0305010501020503020602070305010205030206');
      const xmssParams = newXMSSParams(2, 2, 5, 2);
      const pubSeed = getUInt8ArrayFromHex('03050105010205030607020602070305010205030206');
      const lTreeAddr = getUInt32ArrayFromHex('0000002c0000000b000000060000000700000003000000160000000900000009');
      const otsAddr = getUInt32ArrayFromHex('0000002c0000000b0000000600000007000000160000002c0000000900000009');
      const expectedLeaf = getUInt8ArrayFromHex('71af04070206010501020503020602070305010205030206');
      const expectedSkSeed = getUInt8ArrayFromHex('0305010501020503020602070305010205030206');
      const expectedPubSeed = getUInt8ArrayFromHex('03050105010205030607020602070305010205030206');
      const expectedLTreeAddr = getUInt32ArrayFromHex(
        '0000002c0000000b000000060000000700000003000000040000000000000002'
      );
      const expectedOtsAddr = getUInt32ArrayFromHex('0000002c0000000b0000000600000007000000160000000a0000000300000001');
      genLeafWOTS(HASH_FUNCTION.SHA2_256, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(lTreeAddr).to.deep.equal(expectedLTreeAddr);
      expect(otsAddr).to.deep.equal(expectedOtsAddr);
    });

    it('should generate leafWOTS, with SHAKE_128 hashing', () => {
      const leaf = getUInt8ArrayFromHex('08030504070206010501020503020608020703050102050302');
      const skSeed = getUInt8ArrayFromHex('0903050105010205030206020703050102050302');
      const xmssParams = newXMSSParams(4, 3, 16, 9);
      const pubSeed = getUInt8ArrayFromHex('09050105010205030607020602070305010205030206');
      const lTreeAddr = getUInt32ArrayFromHex('0000002c0000000b000000060000000700000025000000160000000900000009');
      const otsAddr = getUInt32ArrayFromHex('0000002c0000000b0000000600000007000000160000002c0000006300000009');
      const expectedLeaf = getUInt8ArrayFromHex('919bd67b070206010501020503020608020703050102050302');
      const expectedSkSeed = getUInt8ArrayFromHex('0903050105010205030206020703050102050302');
      const expectedPubSeed = getUInt8ArrayFromHex('09050105010205030607020602070305010205030206');
      const expectedLTreeAddr = getUInt32ArrayFromHex(
        '0000002c0000000b000000060000000700000025000000040000000000000002'
      );
      const expectedOtsAddr = getUInt32ArrayFromHex('0000002c0000000b000000060000000700000016000000090000000e00000001');
      genLeafWOTS(HASH_FUNCTION.SHAKE_128, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(lTreeAddr).to.deep.equal(expectedLTreeAddr);
      expect(otsAddr).to.deep.equal(expectedOtsAddr);
    });

    it('should generate leafWOTS, with SHAKE_256 hashing', () => {
      const leaf = getUInt8ArrayFromHex('04033807162c5629020608020703050102050302');
      const skSeed = getUInt8ArrayFromHex('09030501050102050302060207030501020503022c5629');
      const xmssParams = newXMSSParams(9, 7, 6, 5);
      const pubSeed = getUInt8ArrayFromHex('092c5629050105010205030607020602070305010205030206');
      const lTreeAddr = getUInt32ArrayFromHex('0000002c0000000b000000060000004a00000025000000160000000900000009');
      const otsAddr = getUInt32ArrayFromHex('0000002c0000000b0000003f00000007000000160000002c0000006300000009');
      const expectedLeaf = getUInt8ArrayFromHex('1547a0264413f1a0560608020703050102050302');
      const expectedSkSeed = getUInt8ArrayFromHex('09030501050102050302060207030501020503022c5629');
      const expectedPubSeed = getUInt8ArrayFromHex('092c5629050105010205030607020602070305010205030206');
      const expectedLTreeAddr = getUInt32ArrayFromHex(
        '0000002c0000000b000000060000004a00000025000000060000000000000002'
      );
      const expectedOtsAddr = getUInt32ArrayFromHex('0000002c0000000b0000003f0000000700000016000000270000000400000001');
      genLeafWOTS(HASH_FUNCTION.SHAKE_256, leaf, skSeed, xmssParams, pubSeed, lTreeAddr, otsAddr);

      expect(leaf).to.deep.equal(expectedLeaf);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(lTreeAddr).to.deep.equal(expectedLTreeAddr);
      expect(otsAddr).to.deep.equal(expectedOtsAddr);
    });
  });

  describe('bdsRound', () => {
    it('should run bdsRound, with SHA2_256 hashing', () => {
      const height = 19;
      const k = 7;
      const w = 16;
      const n = 17;
      const bdsState = newBDSState(height, n, k);
      const leadIdx = 5;
      const skSeed = getUInt8ArrayFromHex('46530f313934423f410c2817657471590c33346b0569645f61026364071a57');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('68150237604a400a380f16751c492c54653671064b45311c19712d');
      const addr = getUInt32ArrayFromHex('0000005a0000001800000002000000060000005a0000003b0000000d00000051');
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.treeHash[0].nextIdx = 9;
      expectedBdsState.auth = getUInt8ArrayFromHex(
        '0000000000000000000000000000000000092ad0ca473824bce7fb6b9a73a8653e1f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      );
      const expectedSkSeed = getUInt8ArrayFromHex('46530f313934423f410c2817657471590c33346b0569645f61026364071a57');
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedPubSeed = getUInt8ArrayFromHex('68150237604a400a380f16751c492c54653671064b45311c19712d');
      const expectedAddr = getUInt32ArrayFromHex('0000005a0000001800000002000000060000005a0000003b0000000d00000051');
      bdsRound(HASH_FUNCTION.SHA2_256, bdsState, leadIdx, skSeed, params, pubSeed, addr);

      expect(bdsState).to.be.deep.equal(expectedBdsState);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(params).to.be.deep.equal(expectedParams);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should run bdsRound, with SHAKE_128 hashing', () => {
      const height = 8;
      const k = 8;
      const w = 19;
      const n = 3;
      const bdsState = newBDSState(height, n, k);
      const leadIdx = 13;
      const skSeed = getUInt8ArrayFromHex(
        '633d6e346a023c1d203d182b6f762850140b57071c45764b3e356a744f12665d1a531f0165145c4d0b065e601a47'
      );
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('643b767a1738271b254a680f753f773b5253546f0d6129510d321035716568191d17');
      const addr = getUInt32ArrayFromHex('00000072000000150000001b0000000f00000032000000150000001c00000007');
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex('000000551f69000000000000000000000000000000000000');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '633d6e346a023c1d203d182b6f762850140b57071c45764b3e356a744f12665d1a531f0165145c4d0b065e601a47'
      );
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedPubSeed = getUInt8ArrayFromHex(
        '643b767a1738271b254a680f753f773b5253546f0d6129510d321035716568191d17'
      );
      const expectedAddr = getUInt32ArrayFromHex('00000072000000150000001b0000000f00000032000000150000001c00000007');
      bdsRound(HASH_FUNCTION.SHAKE_128, bdsState, leadIdx, skSeed, params, pubSeed, addr);

      expect(bdsState).to.be.deep.equal(expectedBdsState);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(params).to.be.deep.equal(expectedParams);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should run bdsRound, with SHAKE_256 hashing', () => {
      const height = 7;
      const k = 7;
      const w = 5;
      const n = 2;
      const bdsState = newBDSState(height, n, k);
      const leadIdx = 9;
      const skSeed = getUInt8ArrayFromHex(
        '29550a39602b527b143c1905000f3945061b392b182b6664140e05401f487806085c5f782149552439445e'
      );
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('582b480075135449342214041818320b7711270f422d51264766');
      const addr = getUInt32ArrayFromHex('0000005600000052000000170000001f00000024000000730000002500000046');
      const expectedBdsState = newBDSState(height, n, k);
      expectedBdsState.auth = getUInt8ArrayFromHex('0000087a00000000000000000000');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '29550a39602b527b143c1905000f3945061b392b182b6664140e05401f487806085c5f782149552439445e'
      );
      const expectedParams = newXMSSParams(n, height, w, k);
      const expectedPubSeed = getUInt8ArrayFromHex('582b480075135449342214041818320b7711270f422d51264766');
      const expectedAddr = getUInt32ArrayFromHex('0000005600000052000000170000001f00000024000000730000002500000046');
      bdsRound(HASH_FUNCTION.SHAKE_256, bdsState, leadIdx, skSeed, params, pubSeed, addr);

      expect(bdsState).to.be.deep.equal(expectedBdsState);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(params).to.be.deep.equal(expectedParams);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });
  });

  describe('treeHashMinHeightOnStack', () => {
    it('should update r with stackOffset[0] and modified values', () => {
      const height = 9;
      const k = 5;
      const w = 6;
      const n = 5;
      const state = newBDSState(height, n, k);
      const params = newXMSSParams(n, height, w, k);
      const r = treeHashMinHeightOnStack(state, params, state.treeHash[0]);

      expect(r).to.equal(9);
    });

    it('should update r with stackOffset[6] and modified values', () => {
      const height = 11;
      const k = 4;
      const w = 16;
      const n = 3;
      const params = newXMSSParams(n, height, w, k);
      const state = newBDSState(height, n, k);
      state.stackOffset = 6;
      state.treeHash[0].stackUsage = 4;
      state.stackLevels = getUInt8ArrayFromHex('212d02044d1702');
      const r = treeHashMinHeightOnStack(state, params, state.treeHash[0]);

      expect(r).to.equal(2);
    });

    it('should update r with stackOffset[17] and modified values', () => {
      const height = 5;
      const k = 1;
      const w = 256;
      const n = 2;
      const params = newXMSSParams(n, height, w, k);
      const state = newBDSState(height, n, k);
      state.stackOffset = 17;
      state.treeHash[0].stackUsage = 12;
      state.stackLevels = getUInt8ArrayFromHex('4202054d08066300014202054d08066300014202054d0806630001');
      const r = treeHashMinHeightOnStack(state, params, state.treeHash[0]);

      expect(r).to.equal(0);
    });
  });

  describe('treeHashUpdate', () => {
    it('should update tree hash, with SHA2_256 hashing', () => {
      const height = 5;
      const k = 3;
      const w = 256;
      const n = 4;
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('0c07100c01100c05030f0e140d071503000d070c031504');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('1004181004061007130e0d09030d0a080010100d0412140108');
      const addr = getUInt32ArrayFromHex('0000000300000006000000000000000c00000004000000000000000400000005');
      const expectedTreeHash = newTreeHashInst(n);
      expectedTreeHash.h = 0;
      expectedTreeHash.nextIdx = 0;
      expectedTreeHash.completed = 1;
      expectedTreeHash.node = getUInt8ArrayFromHex('990b9713');
      const expectedSkSeed = getUInt8ArrayFromHex('0c07100c01100c05030f0e140d071503000d070c031504');
      const expectedPubSeed = getUInt8ArrayFromHex('1004181004061007130e0d09030d0a080010100d0412140108');
      const expectedAddr = getUInt32ArrayFromHex('0000000300000006000000000000000c00000004000000000000000400000005');
      treeHashUpdate(HASH_FUNCTION.SHA2_256, bdsState.treeHash[0], bdsState, skSeed, params, pubSeed, addr);

      expect(bdsState.treeHash[0]).to.deep.equal(expectedTreeHash);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should update tree hash, with SHAKE_128 hashing', () => {
      const height = 7;
      const k = 3;
      const w = 7;
      const n = 4;
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('0d09080f1211170704061d1d011810081f16110a120a13090c0c0f1f021b1a01');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('0f150c0113140a01110a0f040b021010120c081108050709');
      const addr = getUInt32ArrayFromHex('0000001e0000000d0000001900000000000000680000002c0000005f0000006e');
      const expectedTreeHash = newTreeHashInst(n);
      expectedTreeHash.h = 0;
      expectedTreeHash.nextIdx = 0;
      expectedTreeHash.completed = 1;
      expectedTreeHash.node = getUInt8ArrayFromHex('4535a877');
      const expectedSkSeed = getUInt8ArrayFromHex('0d09080f1211170704061d1d011810081f16110a120a13090c0c0f1f021b1a01');
      const expectedPubSeed = getUInt8ArrayFromHex('0f150c0113140a01110a0f040b021010120c081108050709');
      const expectedAddr = getUInt32ArrayFromHex('0000001e0000000d0000001900000000000000680000002c0000005f0000006e');
      treeHashUpdate(HASH_FUNCTION.SHAKE_128, bdsState.treeHash[2], bdsState, skSeed, params, pubSeed, addr);

      expect(bdsState.treeHash[2]).to.deep.equal(expectedTreeHash);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });

    it('should update tree hash, with SHAKE_256 hashing', () => {
      const height = 9;
      const k = 5;
      const w = 16;
      const n = 5;
      const bdsState = newBDSState(height, n, k);
      const skSeed = getUInt8ArrayFromHex('1d523a6f1713482b001e7b6e4f39543a581b0a776403647b30480f70114e275504112816');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex(
        '30116f414c37325d415f6429637849126e5147083e2d0a2f062110186074395d39341615530a2a2f101f67106b77711428182a245a362c77041574225b7440'
      );
      const addr = getUInt32ArrayFromHex('000000700000003e000000100000004000000004000000190000007b00000010');
      const expectedTreeHash = newTreeHashInst(n);
      expectedTreeHash.h = 0;
      expectedTreeHash.nextIdx = 0;
      expectedTreeHash.completed = 1;
      expectedTreeHash.node = getUInt8ArrayFromHex('e004bd38ea');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '1d523a6f1713482b001e7b6e4f39543a581b0a776403647b30480f70114e275504112816'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '30116f414c37325d415f6429637849126e5147083e2d0a2f062110186074395d39341615530a2a2f101f67106b77711428182a245a362c77041574225b7440'
      );
      const expectedAddr = getUInt32ArrayFromHex('000000700000003e000000100000004000000004000000190000007b00000010');
      treeHashUpdate(HASH_FUNCTION.SHAKE_256, bdsState.treeHash[3], bdsState, skSeed, params, pubSeed, addr);

      expect(bdsState.treeHash[3]).to.deep.equal(expectedTreeHash);
      expect(skSeed).to.deep.equal(expectedSkSeed);
      expect(pubSeed).to.deep.equal(expectedPubSeed);
      expect(addr).to.deep.equal(expectedAddr);
    });
  });

  describe('bdsTreeHashUpdate', () => {
    it('should update the tree hash, with SHA2_256 hashing', () => {
      const height = 5;
      const k = 1;
      const w = 16;
      const n = 1;
      const bdsState = newBDSState(height, n, k);
      const updates = 7;
      const skSeed = getUInt8ArrayFromHex(
        '30037231306c3b1c5f466a45103b436049194a6b1044164d2f16384813114006303b505436602f051e7516'
      );
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('62302c3c112863384440293142465c045c1e5c3f69220f53781718524a7a34465109272f');
      const addr = getUInt32ArrayFromHex('0000001f00000006000000130000005700000078000000290000000d0000003e');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '30037231306c3b1c5f466a45103b436049194a6b1044164d2f16384813114006303b505436602f051e7516'
      );
      const expectedPubSeed = getUInt8ArrayFromHex(
        '62302c3c112863384440293142465c045c1e5c3f69220f53781718524a7a34465109272f'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000001f00000006000000130000005700000078000000290000000d0000003e');
      const result = bdsTreeHashUpdate(HASH_FUNCTION.SHA2_256, bdsState, updates, skSeed, params, pubSeed, addr);

      expect(result).to.equal(3);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should update the tree hash, with SHAKE_128 hashing', () => {
      const height = 11;
      const k = 4;
      const w = 7;
      const n = 3;
      const bdsState = newBDSState(height, n, k);
      const updates = 9;
      const skSeed = getUInt8ArrayFromHex('13797a694f423f2e074651744426630b016f71690313012d7252155c312228283460327727');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex('455600620f264b675f08016b584760743c1e354f2d29343b344b1f27');
      const addr = getUInt32ArrayFromHex('00000042000000250000000900000028000000780000000c0000002d0000004b');
      const expectedSkSeed = getUInt8ArrayFromHex(
        '13797a694f423f2e074651744426630b016f71690313012d7252155c312228283460327727'
      );
      const expectedPubSeed = getUInt8ArrayFromHex('455600620f264b675f08016b584760743c1e354f2d29343b344b1f27');
      const expectedAddr = getUInt32ArrayFromHex('00000042000000250000000900000028000000780000000c0000002d0000004b');
      const result = bdsTreeHashUpdate(HASH_FUNCTION.SHAKE_128, bdsState, updates, skSeed, params, pubSeed, addr);

      expect(result).to.equal(2);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });

    it('should update the tree hash, with SHAKE_256 hashing', () => {
      const height = 17;
      const k = 13;
      const w = 256;
      const n = 7;
      const bdsState = newBDSState(height, n, k);
      const updates = 17;
      const skSeed = getUInt8ArrayFromHex('360d385c002a5f4647673c734f3112303c646a70');
      const params = newXMSSParams(n, height, w, k);
      const pubSeed = getUInt8ArrayFromHex(
        '78333c58232b4e4601370e5d5151334265192b0e3a1e17786b252f1e5d421c36503b4276512e32'
      );
      const addr = getUInt32ArrayFromHex('0000007300000029000000450000006600000014000000260000005e00000021');
      const expectedSkSeed = getUInt8ArrayFromHex('360d385c002a5f4647673c734f3112303c646a70');
      const expectedPubSeed = getUInt8ArrayFromHex(
        '78333c58232b4e4601370e5d5151334265192b0e3a1e17786b252f1e5d421c36503b4276512e32'
      );
      const expectedAddr = getUInt32ArrayFromHex('0000007300000029000000450000006600000014000000260000005e00000021');
      const result = bdsTreeHashUpdate(HASH_FUNCTION.SHAKE_256, bdsState, updates, skSeed, params, pubSeed, addr);

      expect(result).to.equal(13);
      expect(skSeed).to.be.deep.equal(expectedSkSeed);
      expect(pubSeed).to.be.deep.equal(expectedPubSeed);
      expect(addr).to.be.deep.equal(expectedAddr);
    });
  });
});
