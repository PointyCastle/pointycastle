// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.test.modes.gcm_test;

import "package:pointycastle/pointycastle.dart";
import "package:pointycastle/block/aes_fast.dart";
import "package:pointycastle/block/modes/gcm.dart";
import 'package:test/test.dart';
import "../test/src/helpers.dart";
import "../test/aead_cipher_tests.dart";
import "dart:typed_data";

main() {

  group(gcmAlgorithm.algorithmName, () {

    group('Test cases from GCM spec', () {

      test('Test Case 1', () {
        _testGcm(
            k: "00000000000000000000000000000000",
            p: "",
            iv: "000000000000000000000000",
            a: "",
            c: "",
            t: "58e2fccefa7e3061367f1d57a4e7455a"
        );
      });
      test('Test Case 2', () {
        _testGcm(
            k: "00000000000000000000000000000000",
            p: "00000000000000000000000000000000",
            iv: "000000000000000000000000",
            a: "",
            c: "0388dace60b6a392f328c2b971b2fe78",
            t: "ab6e47d42cec13bdf53a67b21257bddf"
        );
      });
      test('Test Case 3', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b391aafd255",
            iv: "cafebabefacedbaddecaf888",
            a: "",
            c: "42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091473f5985",
            t: "4d5c2af327cd64a62cf35abd2ba6fab4"
        );
      });
      test('Test Case 4', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",
            iv: "cafebabefacedbaddecaf888",
            a: "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",
            c: "42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091",
            t: "5bc94fbc3221a5db94fae95ae7121a47"
        );
      });
      test('Test Case 5', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",
            iv: "cafebabefacedbad",
            a: "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",
            c: "61353b4c2806934a777ff51fa22a4755"
                "699b2a714fcdc6f83766e5f97b6c7423"
                "73806900e49f24b22b097544d4896b42"
                "4989b5e1ebac0f07c23f4598",
            t: "3612d2e79e3b0785561be14aaca2fccb"
        );
      });
      test('Test Case 6', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",
            iv: "9313225df88406e555909c5aff5269aa"
                "6a7a9538534f7da1e4c303d2a318a728"
                "c3c0c95156809539fcf0e2429a6b5254"
                "16aedbf5a0de6a57a637b39b",
            a: "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",
            c: "8ce24998625615b603a033aca13fb894"
                "be9112a5c3a211a8ba262a3cca7e2ca7"
                "01e4a9a4fba43c90ccdcb281d48c7c6f"
                "d62875d2aca417034c34aee5",
            t: "619cc5aefffe0bfa462af43c1699d050"
        );
      });
      test('Test Case 7', () {
        _testGcm(
            k: "00000000000000000000000000000000"
                "0000000000000000",
            p: "",
            iv: "000000000000000000000000",
            a: "",
            c: "",
            t: "cd33b28ac773f74ba00ed1f312572435"
        );
      });
      test('Test Case 8', () {
        _testGcm(
            k: "00000000000000000000000000000000"
                "0000000000000000",
            p: "00000000000000000000000000000000",
            iv: "000000000000000000000000",
            a: "",
            c: "98e7247c07f0fe411c267e4384b0f600",
            t: "2ff58d80033927ab8ef4d4587514f0fb"
        );
      });
      test('Test Case 9', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b391aafd255",
            iv: "cafebabefacedbaddecaf888",
            a: "",
            c: "3980ca0b3c00e841eb06fac4872a2757"
                "859e1ceaa6efd984628593b40ca1e19c"
                "7d773d00c144c525ac619d18c84a3f47"
                "18e2448b2fe324d9ccda2710acade256",
            t: "9924a7c8587336bfb118024db8674a14"
        );
      });
      test('Test Case 10', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",
            iv: "cafebabefacedbaddecaf888",
            a: "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",
            c: "3980ca0b3c00e841eb06fac4872a2757"
                "859e1ceaa6efd984628593b40ca1e19c"
                "7d773d00c144c525ac619d18c84a3f47"
                "18e2448b2fe324d9ccda2710",
            t: "2519498e80f1478f37ba55bd6d27618c"
        );
      });
      test('Test Case 11', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",
            iv: "cafebabefacedbad",
            a: "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",
            c: "0f10f599ae14a154ed24b36e25324db8"
                "c566632ef2bbb34f8347280fc4507057"
                "fddc29df9a471f75c66541d4d4dad1c9"
                "e93a19a58e8b473fa0f062f7",
            t: "65dcc57fcf623a24094fcca40d3533f8"
        );
      });
      test('Test Case 12', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",
            iv: "9313225df88406e555909c5aff5269aa"
                "6a7a9538534f7da1e4c303d2a318a728"
                "c3c0c95156809539fcf0e2429a6b5254"
                "16aedbf5a0de6a57a637b39b",
            a: "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",
            c: "d27e88681ce3243c4830165a8fdcf9ff"
                "1de9a1d8e6b447ef6ef7b79828666e45"
                "81e79012af34ddd9e2f037589b292db3"
                "e67c036745fa22e7e9b7373b",
            t: "dcf566ff291c25bbb8568fc3d376a6d9"
        );
      });
      test('Test Case 13', () {
        _testGcm(
            k: "00000000000000000000000000000000"
                "00000000000000000000000000000000",
            p: "",
            iv: "000000000000000000000000",
            a: "",
            c: "",
            t: "530f8afbc74536b9a963b4f1c4cb738b"
        );
      });
      test('Test Case 14', () {
        _testGcm(
            k: "00000000000000000000000000000000"
                "00000000000000000000000000000000",
            p: "00000000000000000000000000000000",
            iv: "000000000000000000000000",
            a: "",
            c: "cea7403d4d606b6e074ec5d3baf39d18",
            t: "d0d1c8a799996bf0265b98b5d48ab919"
        );
      });
      test('Test Case 15', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c6d6a8f9467308308",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b391aafd255",
            iv: "cafebabefacedbaddecaf888",
            a: "",
            c: "522dc1f099567d07f47f37a32a84427d"
                "643a8cdcbfe5c0c97598a2bd2555d1aa"
                "8cb08e48590dbb3da7b08b1056828838"
                "c5f61e6393ba7a0abcc9f662898015ad",
            t: "b094dac5d93471bdec1a502270e3cc6c"
        );
      });
      test('Test Case 16', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c6d6a8f9467308308",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",
            iv: "cafebabefacedbaddecaf888",
            a: "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",
            c: "522dc1f099567d07f47f37a32a84427d"
                "643a8cdcbfe5c0c97598a2bd2555d1aa"
                "8cb08e48590dbb3da7b08b1056828838"
                "c5f61e6393ba7a0abcc9f662",
            t: "76fc6ece0f4e1768cddf8853bb2d551b"
        );
      });
      test('Test Case 17', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c6d6a8f9467308308",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",
            iv: "cafebabefacedbad",
            a: "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",
            c: "c3762df1ca787d32ae47c13bf19844cb"
                "af1ae14d0b976afac52ff7d79bba9de0"
                "feb582d33934a4f0954cc2363bc73f78"
                "62ac430e64abe499f47c9b1f",
            t: "3a337dbf46a792c45e454913fe2ea8f2"
        );
      });
      test('Test Case 18', () {
        _testGcm(
            k: "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c6d6a8f9467308308",
            p: "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",
            iv: "9313225df88406e555909c5aff5269aa"
                "6a7a9538534f7da1e4c303d2a318a728"
                "c3c0c95156809539fcf0e2429a6b5254"
                "16aedbf5a0de6a57a637b39b",
            a: "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",
            c: "5a8def2f0c9e53f1f75d7853659e2a20"
                "eeb2b22aafde6419a058ab4f6f746bf4"
                "0fc0c3b780f244452da3ebf1c5d82cde"
                "a2418997200ef82e44ae7e3f",
            t: "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"
        );
      });
    });


    final iv = new Uint8List.fromList([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]);
    final tag = new Uint8List.fromList([92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
    210, 145]);
    final aad = new Uint8List.fromList(
        [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
        116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
        54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81]);
    final params = new AEADParameters(
        new KeyParameter(new Uint8List.fromList(
            [177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
            212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
            234, 64, 252])),
        128,
        iv,
        aad);

    
    runAEADBlockCipherTests(gcmAlgorithm,
        params, [

        "The true sign of intelligence is not knowledge but imagination.",
        "e5eca6f135bf73c4ae2b496d277ae9608cce783433ed300bbedbba506f68328e2fa73b3db57fc4152852f2207b8fa8e249d8b0908af76a3c10cda06d403fc0"+formatBytesAsHexString(tag),

    ]);


  });

}

final gcmAlgorithm = GCMBlockCipher(new AESFastEngine());

_testGcm({String k, String p, String iv, String a, String c, String t}) {

  var params = new AEADParameters(
      new KeyParameter(createUint8ListFromHexString(k)),
      128,
      createUint8ListFromHexString(iv),
      createUint8ListFromHexString(a));
  gcmAlgorithm.init(true, params);

  var inp = createUint8ListFromHexString(p);
  var outp = gcmAlgorithm.process(inp);

  var ciphertext = outp.sublist(0,inp.length);
  var tag = outp.sublist(inp.length);

  expect(formatBytesAsHexString(ciphertext), c);
  expect(formatBytesAsHexString(tag), t);

  gcmAlgorithm.init(false, params);

  expect(gcmAlgorithm.process(outp), inp);

  expect(() {
    var params = new AEADParameters(
        new KeyParameter(createUint8ListFromHexString(k)),
        128,
        createUint8ListFromHexString(iv),
        createUint8ListFromHexString("01"));
    gcmAlgorithm.init(false, params);

    expect(gcmAlgorithm.process(outp), inp);

  },throwsA(anything));
}
