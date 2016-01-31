// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.src.registry;

import "package:reflectable/reflectable.dart";
import "package:quiver_collection/collection.dart";
import "package:quiver_pattern/regexp.dart";

import "package:pointycastle/api.dart";

part "factory_config.dart";
part "registrable.dart";


typedef Registrable RegistrableConstructor();
typedef RegistrableConstructor DynamicConstructorFactory(
    String registrableName, Match match);

/// Matches all `pointycastle.impl.<category>.<algo>.<className>` libs.
/// The match's groups are <category>, <algo> and <className> as
/// groups 1, 2 and 3 respectively.
const String IMPL_CLASS_REGEX = r"^pointycastle\.impl\.([^.]+)\.(.*)\.([^.]+)$";

FactoryRegistry registry = new FactoryRegistry();


class FactoryRegistry {

  static const String FIELD = "FACTORY_CONFIG";

  static const int CONSTRUCTOR_CACHE_SIZE = 25;

  static const Reflectable reflector = const RegistryImplementationReflector();
  static final ClassMirror registrable = reflector.annotatedClasses.firstWhere(
      (cm) => cm.qualifiedName == "pointycastle.src.registry.Registrable");

  final Map<String, Map<String, RegistrableConstructor>> staticFactories;
  final Map<String, Set<DynamicFactoryConfig>> dynamicFactories;

  final LruMap<String, RegistrableConstructor> constructorCache =
  new LruMap<String, RegistrableConstructor>(maximumSize: CONSTRUCTOR_CACHE_SIZE);

  FactoryRegistry()
    : staticFactories  = new Map<String, Map<String, RegistrableConstructor>>(),
      dynamicFactories = new Map<String, Set<DynamicFactoryConfig>>();

  Registrable create(String category, String registrableName) {
    RegistrableConstructor factory = getConstructor(category, registrableName);
    Registrable result = factory();
    //TODO interesting test:
//    assert(result is! Algorithm || result.algorithmName == algorithmName);
    return result;
  }

  RegistrableConstructor getConstructor(String category, String registrableName) {
    RegistrableConstructor constructor = constructorCache["$category.$registrableName"];
    if (constructor == null) {
      constructor = createConstructor(category, registrableName);
      constructorCache["$category.$registrableName"] = constructor;
    }
    return constructor;
  }

  RegistrableConstructor createConstructor(String category, String registrableName) {
    // Init lazy
    _checkInit();
    // Look for a static factory
    if (staticFactories.containsKey(category) &&
        staticFactories[category].containsKey(registrableName)) {
      return staticFactories[category][registrableName];
    }
    // Look for a dynamic factory
    if (dynamicFactories.containsKey(category)) {
      for (DynamicFactoryConfig factory in dynamicFactories[category]) {
        RegistrableConstructor constructor = factory.tryFactory(
          registrableName);
        if (constructor != null) {
          return constructor;
        }
      }
    }
    // No factory found
    throw new RegistryFactoryException.unknown(registrableName, category);
  }

  bool initialized = false;
  void _checkInit() {
    if (!initialized) {
      initialize();
    }
  }

  void initialize() {
    RegExp regex = new RegExp(IMPL_CLASS_REGEX);
    for(ClassMirror mirror in reflector.annotatedClasses) {
      Match matchName = regex.firstMatch(mirror.qualifiedName);
      if (matchName == null || !mirror.isSubtypeOf(registrable)) {
        // not interesting
        continue;
      }
      String category = matchName.group(1);
      if (!mirror.staticMembers.containsKey(FIELD)) {
        // no factory config found
//        print("No factory config found for implementation "
//          "${mirror.qualifiedName}");
        continue;
      }
      FactoryConfig config = mirror.invokeGetter(FIELD);
      // check if dynamic or static factory
      if (config is StaticFactoryConfig) {
        // static factory
        _addStaticFactoryConfig(category, config, mirror);
      } else if (config is DynamicFactoryConfig) {
        // dynamic factory
        _addDynamicFactoryConfig(category, config);
      }
    }
    initialized = true;
  }

  void _addStaticFactoryConfig(String category, StaticFactoryConfig config, ClassMirror mirror) {
    Map factories = staticFactories.putIfAbsent(category,
        () => new Map<String, RegistrableConstructor>());
    factories[config.algorithmName] = _createStaticFactory(mirror);
  }

  void _addDynamicFactoryConfig(String category, DynamicFactoryConfig config) {
    Set factories = dynamicFactories.putIfAbsent(category,
      () => new Set<DynamicFactoryConfig>());
    factories.add(config);
  }

}


class RegistryImplementationReflector extends Reflectable {
  const RegistryImplementationReflector()
    : super(
      declarationsCapability,
      newInstanceCapability,
      staticInvokeCapability,
      subtypeQuantifyCapability,
      typeRelationsCapability
    );
}

RegistrableConstructor _createStaticFactory(ClassMirror classMirror) =>
    () => classMirror.newInstance("", []);

