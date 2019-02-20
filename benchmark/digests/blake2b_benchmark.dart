// Copyright (c) 2017-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.benchmark.digests.blake2b_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("Blake2b").report();
}
