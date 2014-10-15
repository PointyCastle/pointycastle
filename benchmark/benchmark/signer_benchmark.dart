// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.benchmark.benchmark.signer_benchmark;

import "dart:typed_data";

import "package:cipher/cipher.dart";

import "../benchmark/rate_benchmark.dart";

typedef CipherParameters CipherParametersFactory();

class SignerBenchmark extends RateBenchmark {

  final String _signerName;
  final Uint8List _data;
  final CipherParametersFactory _cipherParametersFactory;
  final bool _forSigning;

  Signer _signer;

  SignerBenchmark(String signerName, bool forSigning, this._cipherParametersFactory,
      [int dataLength = 1024*1024]) :
    super("Signer | $signerName - ${forSigning ? 'sign' : 'verify' }"),
    _signerName = signerName,
    _forSigning = forSigning,
    _data = new Uint8List(dataLength);

  void setup() {
    initCipher();
    _signer = new Signer(_signerName);
    _signer.init(_forSigning, _cipherParametersFactory());
  }

  void run() {
    _signer.generateSignature(_data);
    addSample(_data.length);
  }

}
