
// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.src.registry;


abstract class FactoryConfig {
  final Type type;
  FactoryConfig(this.type);
}

class StaticFactoryConfig extends FactoryConfig {
  final String algorithmName;
  StaticFactoryConfig(Type type, this.algorithmName) : super(type);
}

class DynamicFactoryConfig extends FactoryConfig {
  final RegExp regExp;
  final DynamicConstructorFactory factory;

  DynamicFactoryConfig(Type type, this.regExp, this.factory) : super(type);

  DynamicFactoryConfig.regex(
      Type type, String regexString, DynamicConstructorFactory factory)
      : this(type, new RegExp(regexString), factory);

  /// A dynamic registry that matches by prefix.
  /// The part after the prefix will be in `match.group(1)`.
  DynamicFactoryConfig.prefix(
      Type type, String prefix, DynamicConstructorFactory factory)
      : this.regex(type, "^${escapeRegExp(prefix)}(.+)\$", factory);

  /// A dynamic registry that matches by suffix.
  /// The part before the suffix will be in `match.group(1)`.
  DynamicFactoryConfig.suffix(
      Type type, String suffix, DynamicConstructorFactory factory)
      : this.regex(type, "^(.+)${escapeRegExp(suffix)}\$", factory);

  /// Invokes the factory when it matches. Else returns null.
  RegistrableConstructor tryFactory(String algorithmName) {
    Match match = regExp.firstMatch(algorithmName);
    if (match == null) {
      return null;
    }
    return factory(algorithmName, match);
  }
}