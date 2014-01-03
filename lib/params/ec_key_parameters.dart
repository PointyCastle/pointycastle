// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.params.ec_key_parameters;

import "package:cipher/api.dart";
import "package:cipher/params/asymmetric_key_parameter.dart";

class ECKeyParameters extends AsymmetricKeyParameter implements CipherParameters {

  final ECDomainParameters parameters;

  ECKeyParameters( bool private, ECDomainParameters  this.parameters ) : super(private);

}

class ECPrivateKeyParameters extends ECKeyParameters {
    
  final BigInteger d;

  ECPrivateKeyParameters( this.d, ECDomainParameters  params ) : super(true,params);

}

class ECPublicKeyParameters extends ECKeyParameters {
    
  final ECPoint Q;

  ECPublicKeyParameters( this.Q, ECDomainParameters params ) : super(false,params);

}
