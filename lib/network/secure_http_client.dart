import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import '../crypto/aes_gcm_service.dart';

class SecureHttpClient {
  final String baseUrl;
  final String sessionId;
  final Uint8List aesKey;

  SecureHttpClient({
    required this.baseUrl,
    required this.sessionId,
    required this.aesKey,
  });

  Future<Map<String, dynamic>> post(String path, Map<String, dynamic> body) async {
    // Encrypt request
    final encrypted = await AesGcmService.encrypt(
      plainText: jsonEncode(body),
      key: aesKey,
    );

    // Send encrypted request
    final res = await http.post(
      Uri.parse("$baseUrl$path"),
      headers: {
        "Content-Type": "application/json",
        "X-Session-Id": sessionId,
      },
      body: jsonEncode(encrypted),
    );

    // Decrypt response
    final decrypted = await AesGcmService.decrypt(
      payload: jsonDecode(res.body),
      key: aesKey,
    );

    return jsonDecode(decrypted);
  }
}
