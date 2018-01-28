// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.
library pointycastle.src.registry.impl.reflectable;

import "registry.dart";

/// The method used by the importing library to create a new concrete
/// registry instance.
FactoryRegistry makeRegistry() => new _DisabledFactoryRegistry();

abstract class Registrable {}


class _DisabledFactoryRegistry implements FactoryRegistry {
  dynamic /* Registrable */ create(Type type, String registrableName) {
    throw new UnsupportedError("The PointyCastle registry is disabled.");
  }
}


