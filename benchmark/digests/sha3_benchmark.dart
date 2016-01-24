// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.benchmark.digests.sha3_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("SHA-3/224").report();
  new DigestBenchmark("SHA-3/256").report();
  new DigestBenchmark("SHA-3/288").report();
  new DigestBenchmark("SHA-3/384").report();
  new DigestBenchmark("SHA-3/512").report();
}

