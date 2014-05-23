part of cipher.impl.base;

const _RESEED_PERIOD = const Duration(seconds: 5);

final _defaultEntropySource = new FortunaEntropySource(() => new Digest("SHA-256"));
final _defaultSecureRandom = new AutoSeedBlockCtrRandom(new BlockCipher("AES"), false);

bool _defaultRandomnessInitialized = false;
final _defaultSecureRandomAvailable = new Completer();

/**
 * This method returns a [Future] that gets completed as soon as the default [SecureRandom] is
 * securely seeded.
 */
Future waitForDefaultSecureRandom() => _defaultSecureRandomAvailable.future;

/// Make the default [EntropySource] use the entropy from [collector] to seed itself continously.
void seedDefaultEntropySourceFromCollector(EntropyCollector collector) {
  _defaultEntropySource.seedFromCollector(collector);
}

/**
 * Init the default [SecureRandom] and [EntropySource] algorithms. The default [SecureRandom] is
 * periodically seeded with entropy from the default [EntropySource].
 */
void _initDefaultRandomness(bool useInstantButUnsafeSecureRandom) {
  if (!_defaultRandomnessInitialized) {
    _defaultRandomnessInitialized = true;

    _initDefaultEntropySource();
    _initDefaultSecureRandom(useInstantButUnsafeSecureRandom);
  }
}

void _initDefaultEntropySource() {
  EntropySource.registry[""] = (_) => _defaultEntropySource;
}

void _initDefaultSecureRandom(bool useInstantButUnsafeSecureRandom) {
  if (useInstantButUnsafeSecureRandom) {
    _unsafelySeedSecureRandom();
    _makeDefaultSecureRandomAvailable();
  }

  return _defaultEntropySource.getBytes(32).then((entropy) {
    _defaultSecureRandom.seed(new KeyParameter(entropy));
    _scheduleDefaultSecureRandomReseedEvent(_RESEED_PERIOD);

    if (!useInstantButUnsafeSecureRandom) {
      _makeDefaultSecureRandomAvailable();
    }
  }).catchError((err) {
    _defaultSecureRandomAvailable.completeError(err);
  });
}

void _unsafelySeedSecureRandom() {
  var now = new DateTime.now().millisecondsSinceEpoch.toString();

  if (now.length > 32) {
    now = now.substring(0, 32);
  }

  while (now.length < 32) {
    now = "0" + now;
  }

  final seed = new Uint8List.fromList(now.codeUnits);
  _defaultSecureRandom.seed(new KeyParameter(seed));
}

void _makeDefaultSecureRandomAvailable() {
  SecureRandom.registry[""] = (_) => _defaultSecureRandom;
  _defaultSecureRandomAvailable.complete();
}

/// Schedule a new default secure random reseed to be run after [period] duration
void _scheduleDefaultSecureRandomReseedEvent(Duration period) {
  new Timer(period, () {
    _defaultEntropySource.getBytes(32).then((entropy) {
      print("cipher: default SecureRandom reseed");
      _defaultSecureRandom.seed(new KeyParameter(entropy));
      _scheduleDefaultSecureRandomReseedEvent(period);
    });
  });
}
