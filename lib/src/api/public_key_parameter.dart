
part of cipher.api;

/// A [CipherParameters] to hold an asymmetric public key
class PublicKeyParameter<T extends PublicKey> extends AsymmetricKeyParameter<T> {

  PublicKeyParameter(PublicKey key) : super(key);

}