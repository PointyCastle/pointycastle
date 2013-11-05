// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.params.padded_block_cipher_parameters;

import "package:cipher/api.dart";

class PaddedBlockCipherParameters
        <UnderlyingCipherParameters extends CipherParameters, 
         PaddingCipherParameters extends CipherParameters> 
    implements CipherParameters {
  
  final UnderlyingCipherParameters underlyingCipherParameters;
  final UnderlyingCipherParameters paddingCipherParameters;

  PaddedBlockCipherParameters( this.underlyingCipherParameters, this.paddingCipherParameters );

}
