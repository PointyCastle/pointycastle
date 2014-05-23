// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.params.entropy_collector.polling_entropy_collector_params;

import "package:cipher/api.dart";


/// [CipherParameters] used by polling entropy collectors.
class PollingEntropyCollectorParameters extends CipherParameters {

  final int periodMillis;
  final int bytesPerRound;

  PollingEntropyCollectorParameters(this.periodMillis, this.bytesPerRound);

}
