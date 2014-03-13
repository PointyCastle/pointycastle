// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.benchmark.digests.sha3_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("SHA-3/224").report();
  new DigestBenchmark("SHA-3/256").report();
  new DigestBenchmark("SHA-3/288").report();
  new DigestBenchmark("SHA-3/384").report();
  new DigestBenchmark("SHA-3/512").report();
}

