// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

/**
 * This library contains all out-of-the-box implementations of the interfaces provided in the API
 * which are compatible only with client side. It includes the [cipher.impl] library and extends it
 * with more algorithms.
 *
 * You must call [initCipher] method before using this library to load all implementations into
 * cipher's API factories. There's no need to call [initCipher] from [cipher.impl] if you call
 * [initCipher] from this library (though you can do it if your project's layout needs it).
 */
library cipher.impl.client;

import "package:cipher/api.dart";
import "package:cipher/impl/base.dart" as base;
export "package:cipher/impl/base.dart" show waitForDefaultSecureRandom,
    seedDefaultEntropySourceFromCollector;

import "package:cipher/entropy_collector/accelerometer_entropy_collector.dart";
import "package:cipher/entropy_collector/keyboard_entropy_collector.dart";
import "package:cipher/entropy_collector/mouse_entropy_collector.dart";
import "package:cipher/entropy_collector/page_load_entropy_collector.dart";

const _DEFAULT_ENTROPY_COLLECTORS = const ["Accelerometer", "Keyboard", "Mouse", "PageLoad"];

bool _initialized = false;

/// See method [base.initCipher] for a description of what this method does.
void initCipher({bool useInstantButUnsafeSecureRandom:
    base.DEFAULT_USE_INSTANT_BUT_UNSAFE_SECURE_RANDOM}) {

  if (!_initialized) {
    _initialized = true;

    base.initCipher(useInstantButUnsafeSecureRandom: useInstantButUnsafeSecureRandom);

    _registerEntropyCollectors();

    _startCollectorsForDefaultEntropySource();
  }
}

void _registerEntropyCollectors() {
  EntropyCollector.registry["Accelerometer"] = (_) => new AccelerometerEntropyCollector();
  EntropyCollector.registry["Keyboard"] = (_) => new KeyboardEntropyCollector();
  EntropyCollector.registry["Mouse"] = (_) => new MouseEntropyCollector();
  EntropyCollector.registry["PageLoad"] = (_) => new PageLoadEntropyCollector();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void _startCollectorsForDefaultEntropySource() {
  _DEFAULT_ENTROPY_COLLECTORS.forEach((collectorName) {
    base.seedDefaultEntropySourceFromCollector(new EntropyCollector(collectorName));
  });
}
