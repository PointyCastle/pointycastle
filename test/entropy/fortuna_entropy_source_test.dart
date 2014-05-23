// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.entropy.fortuna_entropy_source_test;

import "dart:async";
import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:cipher/impl/server.dart";
import "package:unittest/unittest.dart";

import "package:cipher/entropy/fortuna_entropy_source.dart";

import "../test/src/null_digest.dart";

void main() {

  initCipher();

  group("Fortuna:", () {

    final digestFactory = () => new Digest("SHA-256");

    test("getBytes", () {
      var source = new EntropySource("SHA-256/Fortuna");

      new Timer(new Duration(milliseconds: 250), () {
        var data = new Uint8List(28);
        source.seed(new FortunaEvent("mouse", data));
        source.seed(new FortunaEvent("keyboard", data));
        source.seed(new FortunaEvent("jitter", data));
      });

      const count = 16;
      return source.getBytes(count).then((bytes) {
        expect(bytes.length, count);
        expect(bytes, [255, 252, 69, 226, 192, 13, 202, 62, 204, 29, 139, 219, 195, 216, 241, 113]);
      });

    });

    test("correct pools used when seeded", () {
      var source = new FortunaEntropySource(digestFactory, now : () => 100);

      // Force first reseed by filling pool 0 with 64 bytes
      source.seed(new FortunaEvent("mouse", new Uint8List(32)));
      source.seed(new FortunaEvent("keyboard", new Uint8List(32)));
      expect(source.getPoolLength(0), 0);

      source.seed(new FortunaEvent("mouse", new Uint8List(10)));
      expect(source.getPoolLength(1), 10);

      source.seed(new FortunaEvent("keyboard", new Uint8List(20)));
      expect(source.getPoolLength(1), 30);

      source.seed(new FortunaEvent("jitter", new Uint8List(30)));
      expect(source.getPoolLength(0), 30);

      source.seed(new FortunaEvent("mouse", new Uint8List(40)));
      expect(source.getPoolLength(2), 40);

    });

    test("pools are rotated when exhausted by a source", () {
      final source = new FortunaEntropySource(digestFactory, now : () => 100);
      final count = 2 * FortunaEntropySource.POOLS_COUNT;

      // Force first reseed by filling pool 0 with 64 bytes
      source.seed(new FortunaEvent("mouse", new Uint8List(32)));
      source.seed(new FortunaEvent("keyboard", new Uint8List(32)));
      expect(source.getPoolLength(0), 0);

      // Seed all pools twice
      for (int i = 0; i < count; i++) {
        source.seed(new FortunaEvent("mouse", new Uint8List(32)));
      }

      // Check seeded lengths
      for (int i = 0; i < FortunaEntropySource.POOLS_COUNT; i++) {
        expect(source.getPoolLength(i), 64);
      }

    });

    test("correct pools used for reseed", () {
      var now = ReseedTimerChecker.MIN_RESEED_PERIOD_MILLIS;
      var source = new FortunaEntropySource(digestFactory, now : () => now);

      // Force first reseed by filling pool 0 with 64 bytes
      source.seed(new FortunaEvent("mouse", new Uint8List(32)));
      source.seed(new FortunaEvent("keyboard", new Uint8List(32)));
      expect(source.getPoolLength(0), 0);

      // Seed pool 0
      source.seed(new FortunaEvent("1", new Uint8List(32)));
      source.seed(new FortunaEvent("2", new Uint8List(32)));
      expect(source.getPoolLength(0), 64);

      // Seed pool 1
      source.seed(new FortunaEvent("1", new Uint8List(32)));
      source.seed(new FortunaEvent("2", new Uint8List(32)));
      expect(source.getPoolLength(1), 64);

      // Make pool 0 drain
      now *= 2;
      source.seed(new FortunaEvent("3", new Uint8List(1)));
      expect(source.getPoolLength(0), 0);

      // Seed pool 0
      source.seed(new FortunaEvent("a", new Uint8List(32)));
      source.seed(new FortunaEvent("b", new Uint8List(32)));
      expect(source.getPoolLength(0), 64);

      // Make pools 0 and 1 drain
      now *= 2;
      source.seed(new FortunaEvent("c", new Uint8List(1)));
      expect(source.getPoolLength(0), 0);
      expect(source.getPoolLength(1), 0);

    });

  });


  group("Pool:", () {

    test("length increased correctly when seeded", () {
      var pool = new Pool(new NullDigest(32));
      expect(pool.length, 0);

      pool.seed(new Uint8List(7), 7);
      expect(pool.length, 7);

      pool.seed(new Uint8List(128), 128);
      expect(pool.length, 135);
    });

    test("length reset to 0 when drained", () {
      var pool = new Pool(new NullDigest(32));
      expect(pool.length, 0);

      pool.seed(new Uint8List(256), 256);
      expect(pool.length, 256);

      pool.drain();
      expect(pool.length, 0);
    });

  });


  group("ReseedTimerChecker:", () {

    test("reseed not allowed in less than 100 ms", () {
      int time = 100;
      int now() => time;

      var checker = new ReseedTimerChecker(now);

      expect(true, checker.shouldReseed());
      expect(false, checker.shouldReseed());
      expect(false, checker.shouldReseed());

      time = 200;
      expect(true, checker.shouldReseed());
      expect(false, checker.shouldReseed());
    });

  });

}

