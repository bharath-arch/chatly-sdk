
// import { WebSocketServer, WebSocket } from 'ws';

// export class ChatServer {
//   private wss: WebSocketServer;

//   constructor(port: number) {
//     this.wss = new WebSocketServer({ port });
//     this.initialize();
//   }

//   private initialize(): void {
//     this.wss.on('connection', (ws: WebSocket) => {
//       console.log('Client connected');

//       ws.on('message', (message: Buffer) => {
//         console.log('Received message:', message.toString());
//         // Broadcast the message to all other clients
//         this.wss.clients.forEach((client) => {
//           if (client !== ws && client.readyState === WebSocket.OPEN) {
//             client.send(message);
//           }
//         });
//       });

//       ws.on('close', () => {
//         console.log('Client disconnected');
//       });
//     });

//     console.log(`WebSocket server started on port ${this.wss.options.port}`);
//   }
// }
