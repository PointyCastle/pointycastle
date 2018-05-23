// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.src.registry;


import "registry_disabled.dart"
  if (dart.library.mirrors) "registry_reflectable.dart";
export  "registry_disabled.dart"
  if (dart.library.mirrors) "registry_reflectable.dart";

final FactoryRegistry registry = makeRegistry();

abstract class FactoryRegistry {
  dynamic /* Registrable */ create(Type type, String registrableName);
}

typedef /*Registrable*/ RegistrableConstructor();
typedef RegistrableConstructor DynamicConstructorFactory(
    String registrableName, Match match);


abstract class FactoryConfig {
  final Type type;
  FactoryConfig(this.type);
}

class StaticFactoryConfig extends FactoryConfig {
  final String algorithmName;
  StaticFactoryConfig(Type type, this.algorithmName) : super(type);
}


// From the PatternCharacter rule here:
// http://ecma-international.org/ecma-262/5.1/#sec-15.10
final _specialRegExpChars = new RegExp(r'([\\\^\$\.\|\+\[\]\(\)\{\}])');

/// Escapes special regular exppression characters in [str] so that it can be
/// used as a literal match inside of a [RegExp].
///
/// The special characters are: \ ^ $ . | + [ ] ( ) { }
/// as defined here: http://ecma-international.org/ecma-262/5.1/#sec-15.10
String _escapeRegExp(String str) => str.splitMapJoin(_specialRegExpChars,
    onMatch: (Match m) => '\\${m.group(0)}', onNonMatch: (s) => s);


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
      : this.regex(type, "^${_escapeRegExp(prefix)}(.+)\$", factory);

  /// A dynamic registry that matches by suffix.
  /// The part before the suffix will be in `match.group(1)`.
  DynamicFactoryConfig.suffix(
      Type type, String suffix, DynamicConstructorFactory factory)
      : this.regex(type, "^(.+)${_escapeRegExp(suffix)}\$", factory);

  /// Invokes the factory when it matches. Else returns null.
  RegistrableConstructor tryFactory(String algorithmName) {
    Match match = regExp.firstMatch(algorithmName);
    if (match == null) {
      return null;
    }
    return factory(algorithmName, match);
  }
}
