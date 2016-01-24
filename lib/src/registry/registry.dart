// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.src.registry;

@GlobalQuantifyCapability(LIBRARY_REGEX, FactoryRegistry.reflector)
import "package:reflectable/reflectable.dart";
import "package:quiver_collection/collection.dart";
import "package:quiver_pattern/regexp.dart";

import "package:pointycastle/api.dart";

part "factory_config.dart";
part "registrable.dart";


typedef Registrable RegistrableConstructor();
typedef RegistrableConstructor DynamicConstructorFactory(
    String registrableName, Match match);

/// Matches all `cipher.impl.<category>.<algo>` libs.
/// The match's groups are <category> and <algo> as group 1 and 2 respectively.
const String LIBRARY_REGEX = r"^cipher\.impl\.([^.]+)\.(.*)$";

FactoryRegistry registry = new FactoryRegistry();


class FactoryRegistry {

  static const String FIELD = "FACTORY_CONFIG";

  static const int CONSTRUCTOR_CACHE_SIZE = 25;

  static const Reflectable reflector = const RegistryImplementationReflector();
  static final ClassMirror registrable =
  reflector.findLibrary("cipher.src.registry").declarations["Registrable"];

  final Map<String, Map<String, RegistrableConstructor>> staticFactories;
  final Map<String, Set<DynamicFactoryConfig>> dynamicFactories;

  final LruMap<String, RegistrableConstructor> constructorCache =
  new LruMap<String, RegistrableConstructor>(maximumSize: CONSTRUCTOR_CACHE_SIZE);

  FactoryRegistry()
    : staticFactories = new Map<String, Map<String, RegistrableConstructor>>(),
      dynamicFactories = new Map<String, Set<DynamicFactoryConfig>>();

  Registrable create(String category, String registrableName) {
    RegistrableConstructor factory = getConstructor(category, registrableName);
    Registrable result = factory();
    //TODO interesting test:
//    assert(result is! Algorithm || result.algorithmName == algorithmName);
    return result;
  }

  RegistrableConstructor getConstructor(String category, String registrableName) {
    RegistrableConstructor factory = constructorCache["$category.$registrableName"];
    if (factory == null) {
      factory = createConstructor(category, registrableName);
      constructorCache["$category.$registrableName"] = factory;
    }
    return factory;
  }

  RegistrableConstructor createConstructor(String category, String registrableName) {
    // Init lazy
    _checkInit();
    // Check if this is a static algorithm
    if(staticFactories.containsKey(category) &&
        staticFactories[category].containsKey(registrableName)) {
      return staticFactories[category][registrableName];
    }
    // Find dynamic factory
    if (dynamicFactories.containsKey(category)) {
      for(DynamicFactoryConfig factory in dynamicFactories[category]) {
        RegistrableConstructor constructor = factory.tryFactory(
          registrableName);
        if(constructor != null) {
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
    RegExp regex = new RegExp(LIBRARY_REGEX);
    reflector.libraries.values.forEach((LibraryMirror lm) {
      Match matchName = regex.firstMatch(lm.qualifiedName);
      if (matchName != null) {
        String category = matchName.group(1);
        // go over all Algorithm classes in library
        lm.declarations.values.where(_isRegistrableDeclaration).forEach((decl) {
          ClassMirror mirror = decl as ClassMirror;
          if (!mirror.staticMembers.containsKey(FIELD)) {
            // no dynamic factory found
//            print("No dynamic factory found for implementation "
//              "${mirror.qualifiedName}");
            return;
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
        });
      }
    });
    initialized = true;
  }

  bool _isRegistrableDeclaration(DeclarationMirror declaration) {
    if (declaration.isPrivate)
      return false;
    if (declaration is! ClassMirror)
      return false;
    return (declaration as ClassMirror).isSubtypeOf(registrable);
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
    : super(libraryCapability, staticInvokeCapability, declarationsCapability,
    newInstanceCapability, typeRelationsCapability);
}

RegistrableConstructor _createStaticFactory(ClassMirror classMirror) =>
    () => classMirror.newInstance("", []);

