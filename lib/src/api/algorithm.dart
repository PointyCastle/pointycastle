// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// All algorithms defined by Pointy Castle inherit from this class.
abstract class Algorithm {
  /// Get this algorithm's standard name.
  String get algorithmName;
}
