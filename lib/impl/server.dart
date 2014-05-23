// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

/**
 * This library contains all out-of-the-box implementations of the interfaces provided in the API
 * which are compatible only with server side. It includes the [cipher.impl] library and extends it
 * with more algorithms.
 *
 * You must call [initCipher] method before using this library to load all implementations into
 * cipher's API factories. There's no need to call [initCipher] from [cipher.impl] if you call
 * [initCipher] from this library (though you can do it if your project's layout needs it).
 */
library cipher.impl.server;

import "dart:io";

import "package:cipher/api.dart";
import "package:cipher/impl/base.dart" as base;
export "package:cipher/impl/base.dart" show waitForDefaultSecureRandom,
    seedDefaultEntropySourceFromCollector;

import "package:cipher/entropy/command_entropy_source.dart";
import "package:cipher/entropy/file_entropy_source.dart";
import "package:cipher/entropy/url_entropy_source.dart";

import "package:cipher/entropy_collector/source_entropy_collector.dart";

const _DEFAULT_ENTROPY_COLLECTORS = const ["random.org", "/dev/random", "CryptoAPI"];

bool _initialized = false;

/// See method [base.initCipher] for a description of what this method does.
void initCipher({bool useInstantButUnsafeSecureRandom:
    base.DEFAULT_USE_INSTANT_BUT_UNSAFE_SECURE_RANDOM}) {

  if (!_initialized) {
    _initialized = true;

    base.initCipher(useInstantButUnsafeSecureRandom: useInstantButUnsafeSecureRandom);

    _registerEntropySources();
    _registerEntropyCollectors();

    _startCollectorsForDefaultEntropySource();
  }
}

void _registerEntropySources() {
  EntropySource.registry["random.org"] = (_) => new UrlEntropySource(
      "https://www.random.org/cgi-bin/randbyte?nbytes={count}&format=f", sourceName: "random.org");

  if (_devRandomAvailable()) {
    EntropySource.registry["/dev/random"] = (_) => new FileEntropySource("/dev/random", sourceName:
        "/dev/random");
  }

  if (_cryptoAPIAvailable()) {
    // TODO: EntropySource.registry["CryptoAPI"]
  }

  EntropySource.registry.registerDynamicFactory(_fileEntropySourceFactory);
  EntropySource.registry.registerDynamicFactory(_urlEntropySourceFactory);
  EntropySource.registry.registerDynamicFactory(_commandEntropySourceFactory);
}

void _registerEntropyCollectors() {
  EntropyCollector.registry["random.org/EntropyCollector"] = (_) => new SourceEntropyCollector(
      new EntropySource("random.org"));

  if (_devRandomAvailable()) {
    EntropyCollector.registry["/dev/random/EntropyCollector"] = (_) => new SourceEntropyCollector(
        new EntropySource("/dev/random"));
  }

  if (_cryptoAPIAvailable()) {
    EntropyCollector.registry["CryptoAPI/EntropyCollector"] = (_) => new SourceEntropyCollector(
        new EntropySource("CryptoAPI"));
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void _startCollectorsForDefaultEntropySource() {
  _DEFAULT_ENTROPY_COLLECTORS.forEach((collectorName) {
    try {
      base.seedDefaultEntropySourceFromCollector(new EntropyCollector(collectorName));
    } catch (_) {
      // Ignore because some collectors may not be available depending on the context
    }
  });
}

////////////////////////////////////////////////////////////////////////////////////////////////////

EntropySource _fileEntropySourceFactory(String algorithmName) {
  if (algorithmName.startsWith("file://")) {
    var filePath = algorithmName.substring(7);
    return new FileEntropySource(filePath);
  }

  return null;
}

EntropySource _urlEntropySourceFactory(String algorithmName) {
  if (algorithmName.startsWith("http://") || algorithmName.startsWith("https://")) {
    return new UrlEntropySource(algorithmName);
  }

  return null;
}

EntropySource _commandEntropySourceFactory(String algorithmName) {
  if (algorithmName.startsWith("command:")) {
    final cmdLine = algorithmName.substring(8);
    final parts = cmdLine.split("|");
    return new CommandEntropySource(1024, parts[0], parts.sublist(1));
  }

  return null;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

bool _devRandomAvailable() => new File("/dev/random").existsSync();
bool _cryptoAPIAvailable() => false; // TODO: _cryptoApiAvailable
