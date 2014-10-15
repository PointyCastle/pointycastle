// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

/**
 * This is the main entry point to the cipher library API. It includes libraries [cipher.api]
 * (which comprises the whole API specification) and [cipher.impl] (which defines algorithm
 * implementations and all [CipherParameters] to be used with them).
 */
library cipher.cipher;

export "package:cipher/api.dart";
export "package:cipher/impl.dart";