// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy.fortuna_entropy_source;

import "dart:async";
import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/params/key_parameter.dart";
import "package:cipher/random/fortuna_random.dart";


// TODO: incrementar pools a medida que se va usando el ultimo

/// A [Digest] factory function.
typedef Digest FortunaDigestFactory();

/// A function to estimate the entropy in a given event.
typedef int _EntropyEstimator(FortunaEvent event);

/// The default entropy estimator counts all data as valid entropy.
int _defaultEntropyEstimator(FortunaEvent event) => event.data.length;

/// Implementation of Fortuna random number generator.
class FortunaEntropySource implements EntropySource {

  static const MAX_EVENT_DATA_SIZE = 32;
  static const MIN_POOL_SIZE = 64;
  static const POOLS_COUNT = 32;

  String _sourceName;

  final List<Pool> _pools;
  int _nextSourceId = 0;
  final _nextSourcePool = new Map<int, int>();
  final _sourceId = new Map<String, int>();
  final _EntropyEstimator _entropyEstimator;

  final _prng = new FortunaRandom();

  ReseedTimerChecker _reseedTimerChecker;
  Completer _reseedCompleter;
  int _reseedCount = 0;
  final _lastReseedKey = new Uint8List(MAX_EVENT_DATA_SIZE);

  final Digest _digest;

  FortunaEntropySource(FortunaDigestFactory digestFactory, {NowFunction now: null, _EntropyEstimator
      entropyEstimator: _defaultEntropyEstimator, String sourceName: null})
      : _pools = new List<Pool>.generate(POOLS_COUNT, (_) => new Pool(digestFactory())),
        _digest = digestFactory(),
        _reseedTimerChecker = new ReseedTimerChecker(now),
        _entropyEstimator = entropyEstimator {

    if (_digest.digestSize != MAX_EVENT_DATA_SIZE) {
      throw new ArgumentError("Digest does not produce 256 bit hashes: ${_digest.algorithmName}");
    }

    if (sourceName == null) {
      _sourceName = "${_digest.algorithmName}/Fortuna";
    } else {
      _sourceName = sourceName;
    }
  }

  String get sourceName => _sourceName;

  int getPoolLength(int pool) => _pools[pool].length;

  void seedFromCollector(EntropyCollector collector) {
    collector.entropy.listen((entropy) {
      seed(new FortunaEvent("${collector.algorithmName}", entropy));
    });
    collector.start();
  }

  void seed(FortunaEvent event) {
    var sourceId = _sourceId[event.source];
    if (sourceId == null) {
      sourceId = _nextSourceId++;
      _sourceId[event.source] = sourceId;
      _nextSourcePool[sourceId] = 0;
    }

    var data = event.data;
    var estimatedEntropy = _entropyEstimator(event);
    if (data.length > MAX_EVENT_DATA_SIZE) {
      data = _digest.process(event.data);
    }

    var poolIndex = _nextSourcePool[sourceId]++;
    _nextSourcePool[sourceId] %= POOLS_COUNT;

    var s = new Uint8List(2 + data.length);
    s[0] = sourceId;
    s[1] = data.length;
    s.setAll(2, data);

    _pools[poolIndex].seed(s, estimatedEntropy);

    if ((_pools[0].length >= MIN_POOL_SIZE) && _reseedTimerChecker.shouldReseed()) {
      _reseed();
    }
  }

  Future<Uint8List> getBytes(int count) {
    if (_reseedCount == 0) {
      return _waitForReseed().then((_) => _prng.nextBytes(count));
    } else {
      return new Future.value(_prng.nextBytes(count));
    }
  }

  void _reseed() {
    _reseedCount++;

    var s = new List<int>();
    var hashedEntropy = new Uint8List(MAX_EVENT_DATA_SIZE);
    for (int i = 0,
        div = 1; (i < _pools.length) && ((_reseedCount % div) == 0); i++, div <<= i) {
      var entropy = _pools[i].drain();

      _digest.reset();
      _digest.update(entropy, 0, entropy.length);
      _digest.doFinal(hashedEntropy, 0);

      s.addAll(hashedEntropy);
    }

    var data = new Uint8List(_lastReseedKey.length + s.length);
    data.setRange(0, _lastReseedKey.length, _lastReseedKey);
    data.setRange(_lastReseedKey.length, data.length, s);
    var firstHash = _digest.process(data);
    _digest.reset();
    _digest.update(firstHash, 0, firstHash.length);
    _digest.doFinal(_lastReseedKey, 0);

    _prng.seed(new KeyParameter(_lastReseedKey));

    if (_reseedCompleter != null) {
      _reseedCompleter.complete();
    }
  }

  Future _waitForReseed() {
    if (_reseedCompleter == null) {
      _reseedCompleter = new Completer();
      _reseedCompleter.future.whenComplete(() {
        _reseedCompleter = null;
      });
    }

    return _reseedCompleter.future;
  }

}

class Pool {

  final Digest _digest;

  int _length = 0;

  Pool(this._digest);

  int get length => _length;

  void seed(Uint8List data, int estimatedEntropy) {
    _length += estimatedEntropy;
    _digest.update(data, 0, data.length);
  }

  Uint8List drain() {
    var out = new Uint8List(_digest.digestSize);
    _digest.doFinal(out, 0);

    _length = 0;
    _digest.reset();

    return out;
  }

}

/// [FortunaEvent]s are used to seed the Fortuna CSRNG
class FortunaEvent {

final String source;
final Uint8List data;

FortunaEvent(this.source, this.data);

}

/// A function to get the current time.
typedef int NowFunction();

/// The class reponsible for reseed time checks.
class ReseedTimerChecker {

  static const MIN_RESEED_PERIOD_MILLIS = 100;

  int _lastReseed;
  NowFunction _now;

  ReseedTimerChecker([NowFunction now = null]) {
    if (now == null) {
      _now = () => new DateTime.now().millisecondsSinceEpoch;
    } else {
      _now = now;
    }
  }

  bool shouldReseed() {
    if (_lastReseed == null) {
      _lastReseed = _now();
      return true;
    }

    if ((_now() - _lastReseed) >= MIN_RESEED_PERIOD_MILLIS) {
      _lastReseed = _now();
      return true;
    } else {
      return false;
    }
  }

}

