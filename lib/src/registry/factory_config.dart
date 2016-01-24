
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

  DynamicFactoryConfig.prefix(String prefix, DynamicConstructorFactory factory)
    : this.regex("^${escapeRegExp(prefix)}.+\$", factory);

  DynamicFactoryConfig.suffix(String suffix, DynamicConstructorFactory factory)
    : this.regex("^.+${escapeRegExp(suffix)}\$", factory);

  /// Invokes the factory when it matches. Else returns null.
  RegistrableConstructor tryFactory(String algorithmName) {
    Match match = regExp.firstMatch(algorithmName);
    if (match == null) {
      return null;
    }
    return factory(algorithmName, match);
  }
}