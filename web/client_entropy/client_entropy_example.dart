// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.example.client_entropy.client_entropy_example;

import "dart:html";
import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:cipher/impl/client.dart";

import "package:cipher/entropy/fortuna_entropy_source.dart";

void main() {

  final watch = new Stopwatch()..start();

  initCipher(useInstantButUnsafeSecureRandom: true);
  print("cipher initialized");

  waitForDefaultSecureRandom().then((_) {
    watch.stop();
    print("waitForDefaultSecureRandom: OK: ${watch.elapsedMilliseconds}ms");
  }).catchError((err) {
    print("waitForDefaultSecureRandom: ERROR: ${err}");
  });

  final collectors = [new EntropyCollector("PageLoad"), new EntropyCollector("Jitter"),
      new EntropyCollector("Mouse"), new EntropyCollector("Keyboard"), new EntropyCollector(
      "Accelerometer")];
  final source = new EntropySource();

  final table = querySelector("#collectors") as TableElement;
  final startCollectorsButton = querySelector("#start_collectors") as InputElement;
  final stopCollectorsButton = querySelector("#stop_collectors") as InputElement;

  for (int i = 0; i < collectors.length; i++) {
    final collector = collectors[i];

    final estimator = new EntropyEstimator("Shannon");
    final statusRow = new CollectorStatusRow(collector.algorithmName, estimator);

    statusRow.render(table);

    collector.entropy.listen((Uint8List entropy) {
      source.seed(new FortunaEvent("${collector.algorithmName}", entropy));
      statusRow.update(entropy);
    });

    collector.start();
  }

  startCollectorsButton.onClick.listen((event) {
    collectors.forEach((collector) => collector.start());
    startCollectorsButton.disabled = true;
    stopCollectorsButton.disabled = false;
  });

  stopCollectorsButton.onClick.listen((event) {
    collectors.forEach((collector) => collector.stop());
    stopCollectorsButton.disabled = true;
    startCollectorsButton.disabled = false;
  });

  /*
  source.getBytes(2048).then((bytes) {
    estimator.update(bytes, 0, bytes.length);
    print("${100*estimator.estimatedEntropy/estimator.dataLength}%");
  });
  */
}

class CollectorStatusRow {

  static const _COL_NAME = 0;
  static const _COL_EFFICIENCY = 1;
  static const _COL_TOTAL_ENTROPY = 2;
  static const _COL_TOTAL_DATA = 3;
  static const _COL_EVENTS_COUNT = 4;
  static const _COL_LAST_EVENT_TIME = 5;
  static const _COL_LAST_EVENT_LENGTH = 6;

  static const _COLUMNS_COUNT = 7;

  final String _name;
  final EntropyEstimator _estimator;
  int _eventCount = 0;

  TableElement _table;
  List<TableCellElement> _cells;

  CollectorStatusRow(this._name, this._estimator);

  void render(TableElement table) {
    assert(_table == null);
    _table = table;

    final row = table.addRow();
    _cells = new List<TableCellElement>.generate(_COLUMNS_COUNT, (_) => row.addCell());

    _cells[_COL_EFFICIENCY].style.textAlign = "right";
    _cells[_COL_TOTAL_ENTROPY].style.textAlign = "right";
    _cells[_COL_TOTAL_DATA].style.textAlign = "right";
    _cells[_COL_EVENTS_COUNT].style.textAlign = "right";
    _cells[_COL_LAST_EVENT_LENGTH].style.textAlign = "right";

    _cells[_COL_NAME].text = _name;
    _cells[_COL_EFFICIENCY].text = "0%";
    _cells[_COL_TOTAL_ENTROPY].text = "0";
    _cells[_COL_TOTAL_DATA].text = "0";
    _cells[_COL_EVENTS_COUNT].text = "0";
    _cells[_COL_LAST_EVENT_TIME].text = "";
    _cells[_COL_LAST_EVENT_LENGTH].text = "0";
  }

  void update(Uint8List entropy) {
    _estimator.update(entropy, 0, entropy.length);

    final efficiency = 100 * _estimator.estimatedEntropy / _estimator.dataLength;

    _cells[_COL_EFFICIENCY].text = "${efficiency.toStringAsFixed(2)}%";
    _cells[_COL_TOTAL_ENTROPY].text = _estimator.estimatedEntropy.toString();
    _cells[_COL_TOTAL_DATA].text = _estimator.dataLength.toString();
    _cells[_COL_EVENTS_COUNT].text = (++_eventCount).toString();
    _cells[_COL_LAST_EVENT_TIME].text = new DateTime.now().toString();
    _cells[_COL_LAST_EVENT_LENGTH].text = entropy.length.toString();
  }

}