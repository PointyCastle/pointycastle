// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_collector.source_entropy_collector;

import "dart:async";
import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/entropy_collector/base_polling_entropy_collector.dart";


class SourceEntropyCollector extends BasePollingEntropyCollector {

  final EntropySource _source;

  SourceEntropyCollector(this._source);

  String get algorithmName => "${_source.sourceName}/EntropyCollector";

  Future<Uint8List> pollEvent() => _source.getBytes(bytesPerRound);

}
