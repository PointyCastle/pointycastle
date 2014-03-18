// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.benchmark.digests.tiger_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("Tiger").report();
}

