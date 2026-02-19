import type { Env } from '../types';

interface SignalingMessage {
  type: 'offer' | 'answer' | 'candidate' | 'endpoint' | 'ping';
  from: string; // device_id
  to?: string; // target device_id (omit for broadcast)
  payload: unknown;
}

interface SessionInfo {
  deviceId: string;
  networkId: string;
}

export class SignalingRoom implements DurableObject {
  private state: DurableObjectState;
  private sessions: Map<WebSocket, SessionInfo> = new Map();

  constructor(state: DurableObjectState, _env: Env) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/websocket') {
      if (request.headers.get('Upgrade') !== 'websocket') {
        return new Response('Expected WebSocket', { status: 426 });
      }

      const deviceId = url.searchParams.get('device_id');
      const networkId = url.searchParams.get('network_id');

      if (!deviceId || !networkId) {
        return new Response('Missing device_id or network_id', { status: 400 });
      }

      const pair = new WebSocketPair();
      const [client, server] = [pair[0], pair[1]];

      this.state.acceptWebSocket(server, [networkId, deviceId]);

      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response('Not found', { status: 404 });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string') return;

    let msg: SignalingMessage;
    try {
      msg = JSON.parse(message);
    } catch {
      ws.send(JSON.stringify({ type: 'error', payload: 'Invalid JSON' }));
      return;
    }

    const tags = this.state.getTags(ws);
    if (!tags || tags.length < 2) return;
    const [_networkId, fromDeviceId] = tags;

    // Stamp the sender
    msg.from = fromDeviceId;

    if (msg.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
      return;
    }

    // Route to specific peer or broadcast
    const sockets = this.state.getWebSockets();
    for (const socket of sockets) {
      if (socket === ws) continue;

      const peerTags = this.state.getTags(socket);
      if (!peerTags || peerTags.length < 2) continue;
      const [_peerNetworkId, peerDeviceId] = peerTags;

      if (msg.to && msg.to !== peerDeviceId) continue;

      socket.send(JSON.stringify(msg));
    }
  }

  async webSocketClose(ws: WebSocket, code: number, _reason: string, _wasClean: boolean): Promise<void> {
    const tags = this.state.getTags(ws);
    if (!tags || tags.length < 2) return;
    const [_networkId, deviceId] = tags;

    // Notify other peers
    const sockets = this.state.getWebSockets();
    for (const socket of sockets) {
      if (socket === ws) continue;
      socket.send(JSON.stringify({
        type: 'peer_left',
        from: deviceId,
        payload: { code },
      }));
    }

    ws.close(code, 'Closed');
  }

  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    ws.close(1011, 'Internal error');
  }
}
