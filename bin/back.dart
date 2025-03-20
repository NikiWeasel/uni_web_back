import 'dart:io';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_cors_headers/shelf_cors_headers.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'dart:convert';
import 'package:dart_amqp/dart_amqp.dart';
import 'package:shelf_web_socket/shelf_web_socket.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

const String secretKey = 'secret_key';
const String loginUser = '123';
const String passwordUser = '123';

const String loginAdmin = '456';
const String passwordAdmin = '456';

List<WebSocketChannel> clients = [];

String generateToken(String role, String email) {
  final jwt = JWT({
    'id': 123,
    'email': email,
    'role': role,
    'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000, // Время выпуска
    'exp':
        DateTime.now().add(const Duration(hours: 10)).millisecondsSinceEpoch ~/
            1000, //exp date
  });

  String token = jwt.sign(SecretKey(secretKey));
  return token;
}

bool verifyToken(String token) {
  try {
    final jwt = JWT.verify(token, SecretKey(secretKey));
    print('Проверка успешна! Данные токена: ${jwt.payload}');
    return true;
  } catch (e) {
    print('Ошибка верификации: $e');
    return false;
  }
}

Future<Response> _handleRequest(Request request) async {
  print(request.url.path);
  if (request.url.path == 'auth' && request.method == 'POST') {
    var payload = await request.readAsString();
    var data = jsonDecode(payload);

    String username = data['username'];
    String password = data['password'];

    if (username == loginUser && password == passwordUser) {
      String token = generateToken('user', 'user@mail.com');

      return Response.ok(jsonEncode({'token': token}),
          headers: {'Content-Type': 'application/json'});
    }
    if (username == loginAdmin && password == passwordAdmin) {
      String token = generateToken('admin', 'admin@mail.com');

      return Response.ok(jsonEncode({'token': token}),
          headers: {'Content-Type': 'application/json'});
    } else {
      return Response.forbidden('Invalid credentials');
    }
  }

  if (request.url.path == 'protected' && request.method == 'GET') {
    final authorizationHeader = request.headers['Authorization'];
    if (authorizationHeader != null &&
        authorizationHeader.startsWith('Bearer ')) {
      final token = authorizationHeader.substring(7);

      // Тут проверка токена (например, сверка с сохранённым значением)
      if (verifyToken(token)) {
        return Response.ok('Access granted');
      } else {
        return Response.forbidden('Invalid token');
      }
    } else {
      return Response.forbidden('Authorization header is missing or invalid');
    }
  }
  if (request.url.path == 'send_message' && request.method == 'POST') {
    final body = await request.readAsString();
    final data = jsonDecode(body);

    if (data['author'] == null ||
        data['title'] == null ||
        data['source'] == null ||
        data['description'] == null) {
      return Response(400, body: 'Missing message field');
    }

    // await rabbitMQ.sendMessage(body);

    return Response.ok('Message sent to RabbitMQ');
  }
  if (request.url.path == 'ws') {
    print('WS !!!');
    print(request.context['shelf.io.connection']);

    var httpRequest = request.context['shelf.io.connection'] as HttpRequest?;
    if (httpRequest == null) {
      return Response.forbidden('path null');
    }

    WebSocket socket = await WebSocketTransformer.upgrade(httpRequest);
    print('Клиент подключился!');

    // Подключение к RabbitMQ
    final client = Client();
    final channel = await client.channel();
    final queue = await channel.queue('my_queue');

    // Получение сообщений из RabbitMQ и отправка их клиенту
    final consumer = await queue.consume();

    consumer.listen((message) {
      socket.add('Сообщение из RabbitMQ: ${message.payloadAsString}');
    });

    // Обработка входящих сообщений от клиента
    socket.listen((data) {
      print('Получено от клиента: $data');
      queue.publish(data);
    });
    return Response.ok('Access granted');
  }

  return Response.notFound('Not Found');
}

void handleWebSocket(WebSocketChannel channel) {
  print('Новое WebSocket подключение');
  clients.add(channel);

  // Работаем с потоком данных, доступным через channel.stream
  channel.stream.listen(
    (message) {
      print('Получено сообщение: $message');

      for (var client in clients) {
        client.sink.add(message);
      }

      // channel.sink.add('$message'); // Отправляем обратно
    },
    onError: (error) => print('Ошибка WebSocket: $error'),
    onDone: () => print('WebSocket соединение закрыто'),
  );
}

void main() async {
  final handler = Cascade()
      .add(webSocketHandler(handleWebSocket)) // WebSocket обработчик
      .add(Pipeline()
          .addMiddleware(corsHeaders(
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
              'Access-Control-Allow-Headers':
                  'Origin, Content-Type, Authorization',
              'Access-Control-Allow-Credentials': 'true',
            },
          ))
          .addMiddleware(logRequests())
          .addHandler(_handleRequest))
      .handler;

  final server = await io.serve(handler, InternetAddress.anyIPv4, 8080);
  //62.249.129.109
  //InternetAddress.anyIPv4
  print(server.address.host);

  print('Сервер запущен на http://${server.address.host}:${server.port}');
}
