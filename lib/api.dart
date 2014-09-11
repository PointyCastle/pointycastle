// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

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




