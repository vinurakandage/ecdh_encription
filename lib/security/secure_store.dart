import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'dart:convert';
import 'dart:typed_data';

class SecureStore {
  static const _storage = FlutterSecureStorage();

  static Future<void> saveSession(String sessionId, Uint8List key) async {
    await _storage.write(key: "sessionId", value: sessionId);
    await _storage.write(key: "aesKey", value: base64Encode(key));
  }

  static Future<(String?, Uint8List?)> loadSession() async {
    final sessionId = await _storage.read(key: "sessionId");
    final keyBase64 = await _storage.read(key: "aesKey");
    final key = keyBase64 != null ? base64Decode(keyBase64) : null;
    return (sessionId, key);
  }

  static Future<void> clear() async => await _storage.deleteAll();
}
