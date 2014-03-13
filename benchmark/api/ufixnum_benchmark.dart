// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.benchmark.api.ufixnum_benchmark;

import "package:bignum/bignum.dart";
import "package:cipher/api/ufixnum.dart";
import "../benchmark/operation_benchmark.dart";

void main() {
  final x8 = 0xFF;
  final y8 = 0x80;
  final x32 = 0xFF00FF00;
  final y32 = 0x80808080;
  final x64 = 0xFF00FF00FF00FF00;
  final y64 = 0x8080808080808080;
  final dx  = 0xFF00FF00.toDouble();
  final dy  = 0x08080808.toDouble();
  final rx64 = new Register64(0xFF00FF00, 0xFF00FF00);
  final ry64 = new Register64(0x80808080, 0x80808080);
  final bix = new BigInteger("FF00FF00", 16);
  final biy = new BigInteger("08080808", 16);

  new OperationBenchmark("sum | smi   ", () => x32 + y32      ).report();
  new OperationBenchmark("sum | double", () => dx + dy        ).report();
  new OperationBenchmark("sum | sum8  ", () => sum8(x8, y8)   ).report();
  new OperationBenchmark("sum | sum32 ", () => sum32(x32, y32)).report();
  new OperationBenchmark("sum | Reg64 ", () => rx64.sum(ry64) ).report();
  new OperationBenchmark("sum | bigint", () => x64 + y64      ).report();
  new OperationBenchmark("sum | bignum", () => bix + biy      ).report();
}
