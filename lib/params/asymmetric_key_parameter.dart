// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.params.asymmetric_key_parameters;

import "package:cipher/api.dart";

class AsymmetricKeyParameter implements CipherParameters
{
    final bool private;

    AsymmetricKeyParameter(this.private);

}
