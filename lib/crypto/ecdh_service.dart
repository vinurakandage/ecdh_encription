import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;

class EcdhService {
  final _ecdh = Ecdh.p256(length: 256);

  Future<EcKeyPair> generateKeyPair() async {
    final keyPair = await _ecdh.newKeyPair();
    return keyPair;
  }

  Future<String> getPublicKeyBase64(EcKeyPair keyPair) async {
    final publicKey = await keyPair.extractPublicKey();

    Uint8List trim(List<int> bytes) {
      final list = Uint8List.fromList(bytes);
      if (list.length == 33 && list[0] == 0) {
        return list.sublist(1);
      }
      return list;
    }

    final x = trim(publicKey.x);
    final y = trim(publicKey.y);

    if (x.length != 32 || y.length != 32) {
      throw Exception("Invalid P-256 public key length");
    }

    // Uncompressed format: 04 || X || Y
    final uncompressed = Uint8List(65)
      ..[0] = 0x04
      ..setRange(1, 33, x)
      ..setRange(33, 65, y);

    return base64Encode(uncompressed);
  }

  /// Returns (sessionId, AES key)
  Future<(String, Uint8List)> establishSession(String baseUrl) async {
    // 1️⃣ Generate keypair
    final keyPair = await generateKeyPair();

    final clientPubBase64 = await getPublicKeyBase64(keyPair);

    // 2️⃣ Send to backend
    final res = await http.post(
      Uri.parse("$baseUrl/api/keyexchange"),
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({"clientPublicKey": clientPubBase64}),
    );

    if (res.statusCode != 200) {
      throw Exception("Key exchange failed: ${res.body}");
    }

    final json = jsonDecode(res.body);
    final sessionId = json["sessionId"] as String;
    final serverPubBase64 = json["serverPublicKey"];

    final serverBytes = base64Decode(serverPubBase64);

    // 🔥 IMPORTANT: remove 0x04 prefix
    if (serverBytes.length != 65 || serverBytes[0] != 0x04) {
      throw Exception("Invalid server public key format");
    }

    final x = serverBytes.sublist(1, 33);
    final y = serverBytes.sublist(33, 65);

    // ✅ Create EcPublicKey (NOT SimplePublicKey)
    final serverPublicKey = EcPublicKey(
      x: x,
      y: y,
      type: KeyPairType.p256,
    );

    // 3️⃣ Compute shared secret
    final sharedSecret = await _ecdh.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: serverPublicKey,
    );
    print("Shared Secret created Successfully!!!");
    final hash = await Sha256().hash(await sharedSecret.extractBytes());
    final aesKey = Uint8List.fromList(hash.bytes);

    return (sessionId, aesKey);
  }
}
