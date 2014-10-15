// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

/**
 * This is the API specification library for the cipher project.
 *
 * It declares all abstract types used by the cipher library. In addition, it implements the factories mechanism that allows
 * users to instantiate algorithms by their standard name.
 */
library cipher.api;

import "dart:typed_data";

import "package:bignum/bignum.dart";

import "package:cipher/registry/registry.dart";
export "package:cipher/registry/registry.dart";

part "./src/api/asymmetric.dart";
part "./src/api/parameters.dart";
part "./src/api/random.dart";
part "./src/api/symmetric.dart";
part "./src/api/unkeyed.dart";




