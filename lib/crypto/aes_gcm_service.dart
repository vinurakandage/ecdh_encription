import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

class AesGcmService {
  static final _algo = AesGcm.with256bits();

  /// Encrypts string and returns map with iv, cipherText, tag
  static Future<Map<String, String>> encrypt({
    required String plainText,
    required Uint8List key,
  }) async {
    final secretKey = SecretKey(key);

    final nonce = _randomBytes(12); // 12 bytes for GCM

    final box = await _algo.encrypt(
      utf8.encode(plainText),
      secretKey: secretKey,
      nonce: nonce,
    );

    return {
      "iv": base64Encode(nonce),
      "cipherText": base64Encode(box.cipherText),
      "tag": base64Encode(box.mac.bytes),
    };
  }

  /// Decrypts map returned by server
  static Future<String> decrypt({
    required Map<String, dynamic> payload,
    required Uint8List key,
  }) async {
    final secretKey = SecretKey(key);

    final box = SecretBox(
      base64Decode(payload["cipherText"]),
      nonce: base64Decode(payload["iv"]),
      mac: Mac(base64Decode(payload["tag"])),
    );

    final decrypted = await _algo.decrypt(box, secretKey: secretKey);
    return utf8.decode(decrypted);
  }

  static Uint8List _randomBytes(int length) {
    final rnd = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => rnd.nextInt(256)));
  }
}
