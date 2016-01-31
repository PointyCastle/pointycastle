
// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.src.registry;


abstract class FactoryConfig {
}

class StaticFactoryConfig extends FactoryConfig {
  final String algorithmName;
  StaticFactoryConfig(this.algorithmName);
}

class DynamicFactoryConfig extends FactoryConfig {
  final RegExp regExp;
  final DynamicConstructorFactory factory;

  DynamicFactoryConfig(this.regExp, this.factory);

  DynamicFactoryConfig.regex(String regexString, DynamicConstructorFactory factory)
    : this(new RegExp(regexString), factory);

  /// A dynamic registry that matches by prefix.
  /// The part after the prefix will be in `match.group(1)`.
  DynamicFactoryConfig.prefix(String prefix, DynamicConstructorFactory factory)
    : this.regex("^${escapeRegExp(prefix)}(.+)\$", factory);

  /// A dynamic registry that matches by suffix.
  /// The part before the suffix will be in `match.group(1)`.
  DynamicFactoryConfig.suffix(String suffix, DynamicConstructorFactory factory)
    : this.regex("^(.+)${escapeRegExp(suffix)}\$", factory);

  /// Invokes the factory when it matches. Else returns null.
  RegistrableConstructor tryFactory(String algorithmName) {
    Match match = regExp.firstMatch(algorithmName);
    if (match == null) {
      return null;
    }
    return factory(algorithmName, match);
  }
}