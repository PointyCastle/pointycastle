// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

/**
 * This is the main entry point to the cipher library API. It includes libraries [cipher.api]
 * (which comprises the whole API specification) and [cipher.impl] (which defines algorithm
 * implementations and all [CipherParameters] to be used with them).
 */
library cipher;

export "package:cipher/api.dart";
export "package:cipher/impl.dart";