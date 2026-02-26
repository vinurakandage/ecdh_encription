import 'package:flutter/material.dart';
import 'crypto/ecdh_service.dart';
import 'network/secure_http_client.dart';
import 'security/secure_store.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _serverResponse = "Waiting for response...";

  @override
  void initState() {
    super.initState();
    _initSecureSession();
  }

  Future<void> _initSecureSession() async {
    try {
      final ecdhService = EcdhService();
      // final keyPair = await ecdhService.generateKeyPair();
      // final clientPublicKey = await ecdhService.getPublicKeyBase64(keyPair);
      //
      // print("Client privateee key: $keyPair");
      // print("Client publicccc key: $clientPublicKey");

      //1️⃣ Establish session with backend
      final (sessionId, aesKey) = await ecdhService.establishSession("http://192.168.60.212:5000");

      //2️⃣ Save session securely
      await SecureStore.saveSession(sessionId, aesKey);

      //3️⃣ Create secure HTTP client
      final apiClient = SecureHttpClient(
        baseUrl: "http://192.168.60.212:5000",
        sessionId: sessionId,
        aesKey: aesKey,
      );

      // 4️⃣ Make an encrypted request
      final response = await apiClient.post("/api/secure", {
        "name": "Vinura",
        "role": "flutter"
      });

      setState(() {
        _serverResponse = response.toString();
      });
    } catch (e) {
      print(e);
      setState(() {
        _serverResponse = "Error: $e";
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Secure API Demo',
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Flutter AES-GCM + ECDH Demo'),
        ),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(16.0),
            child: Text(
              _serverResponse,
              style: const TextStyle(fontSize: 18),
              textAlign: TextAlign.center,
            ),
          ),
        ),
      ),
    );
  }
}
