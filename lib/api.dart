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

import "src/registry/registry.dart";

part "src/api/algorithm.dart";
part "src/api/registry_factory_exception.dart";
part "src/api/assymetric_block_cipher.dart";
part "src/api/assymetric_key.dart";
part "src/api/assymetric_key_pair.dart";
part "src/api/assymetric_key_parameter.dart";
part "src/api/block_cipher.dart";
part "src/api/cipher_parameters.dart";
part "src/api/digest.dart";
part "src/api/key_derivator.dart";
part "src/api/key_generator.dart";
part "src/api/key_generator_parameters.dart";
part "src/api/key_parameter.dart";
part "src/api/mac.dart";
part "src/api/padded_block_cipher.dart";
part "src/api/padded_block_cipher_parameters.dart";
part "src/api/padding.dart";
part "src/api/parameters_with_iv.dart";
part "src/api/parameters_with_random.dart";
part "src/api/private_key.dart";
part "src/api/private_key_parameter.dart";
part "src/api/public_key.dart";
part "src/api/public_key_parameter.dart";
part "src/api/secure_random.dart";
part "src/api/signature.dart";
part "src/api/signer.dart";
part "src/api/stream_cipher.dart";





