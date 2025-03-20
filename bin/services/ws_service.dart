// import 'dart:async';
// import 'dart:convert';
// import 'package:shelf_web_socket/shelf_web_socket.dart';
//
// class WebSocketService {
//   // Обработчик WebSocket-соединений
//   static webSocketHandler(Null Function(dynamic webSocket) param0) {
//     return webSocketHandler((webSocket) {
//       webSocket.stream.listen((message) {
//         print('Received: $message');
//         // Эхо-сообщение
//         webSocket.add('Echo: $message');
//       });
//     });
//   }
// }
