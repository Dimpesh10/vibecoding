/*
 * =============================================================================
 *  WEBSOCKET SERVER: KNOWLEDGE FILE (interview notes + working code)
 * =============================================================================
 *
 *  HOW TO RUN
 *  ----------
 *    1. npm install ws            (one time; installs the WebSocket library)
 *    2. node websocket-server.js
 *    3. Open http://localhost:3000 in TWO browser tabs and chat between them.
 *
 * -----------------------------------------------------------------------------
 *  1. WHAT IS A WEBSOCKET?  (definition for interviews)
 * -----------------------------------------------------------------------------
 *  WebSocket is a communication protocol (RFC 6455) that gives you a
 *  PERSISTENT, FULL-DUPLEX connection between a client and a server over a
 *  single TCP connection.
 *
 *   - Persistent:  the connection stays open after it is created. A normal
 *                  HTTP request opens, gets one response, then is done.
 *   - Full-duplex: both sides can send data at the same time, whenever they
 *                  want. The server can PUSH data without the client asking.
 *   - Half-duplex (for contrast): only one side talks at a time, like a
 *                  walkie-talkie. Classic HTTP is request -> response.
 *
 *  One-line answer: "WebSocket is a protocol that upgrades an HTTP connection
 *  into a long-lived, two-way channel, so the server and client can push
 *  messages to each other in real time with very little overhead."
 *
 * -----------------------------------------------------------------------------
 *  2. THE HANDSHAKE  (how a connection starts; a very common question)
 * -----------------------------------------------------------------------------
 *  A WebSocket connection STARTS as a normal HTTP/1.1 GET request:
 *
 *     Client -> Server
 *       GET /chat HTTP/1.1
 *       Host: localhost:3000
 *       Upgrade: websocket              <- "please switch protocols"
 *       Connection: Upgrade
 *       Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==   <- random base64 value
 *       Sec-WebSocket-Version: 13
 *
 *     Server -> Client
 *       HTTP/1.1 101 Switching Protocols  <- status 101 = upgrade accepted
 *       Upgrade: websocket
 *       Connection: Upgrade
 *       Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
 *
 *  Sec-WebSocket-Accept = base64( SHA1( key + fixed GUID ) ).
 *  It proves the server really understands WebSockets. It is NOT security
 *  or authentication.
 *
 *  After the 101 response the same TCP socket stops speaking HTTP and
 *  carries WebSocket FRAMES instead.
 *
 * -----------------------------------------------------------------------------
 *  3. KEY TERMS
 * -----------------------------------------------------------------------------
 *   - ws://   : unencrypted WebSocket (like http://)
 *   - wss://  : WebSocket over TLS, encrypted (like https://). Use in production.
 *   - Frame   : the unit of data on a WebSocket. Frame types (opcodes):
 *                 text, binary, ping, pong, close, continuation
 *   - Ping/Pong: built-in heartbeat frames that check the other side is alive
 *   - Close frame: a graceful shutdown carrying a code (1000 = normal close,
 *                  1001 = going away, 1006 = abnormal, no close frame received)
 *   - Masking : frames sent client -> server MUST be masked (XOR with a 4-byte
 *               key). This stops cache-poisoning attacks on proxies.
 *
 * -----------------------------------------------------------------------------
 *  4. WEBSOCKET vs OTHER REAL-TIME TECHNIQUES
 * -----------------------------------------------------------------------------
 *  | Technique      | Direction        | How it works                        | Overhead |
 *  |----------------|------------------|-------------------------------------|----------|
 *  | Short polling  | client -> server | client asks "anything new?" every N | High     |
 *  |                |                  | seconds                             |          |
 *  | Long polling   | client -> server | server holds request open until it  | Medium   |
 *  |                |                  | has data, then client re-requests   |          |
 *  | SSE (Server-   | server -> client | one long HTTP response streaming    | Low      |
 *  | Sent Events)   | ONLY             | events (text only, auto-reconnect)  |          |
 *  | WebSocket      | BOTH ways        | persistent full-duplex TCP channel  | Lowest   |
 *
 *  Use WebSocket for chat, multiplayer games, live collaboration (Google
 *  Docs-style), trading tickers, live dashboards and notifications.
 *  Do NOT use it for plain CRUD and data fetching: REST/HTTP is simpler,
 *  cacheable and stateless.
 *
 * -----------------------------------------------------------------------------
 *  5. STATEFUL NATURE & SCALING  (senior-level question)
 * -----------------------------------------------------------------------------
 *  A WebSocket server is STATEFUL: it keeps every open connection in memory
 *  (see the `clients` Set below). Consequences:
 *   - User A on server 1 and user B on server 2 cannot see each other's
 *     messages by default.
 *   - Fix: a pub/sub layer (Redis Pub/Sub, Kafka, NATS). Each server
 *     publishes incoming messages and subscribes to deliver them to its own
 *     local clients.
 *   - Load balancers need WebSocket support (Upgrade headers) and often
 *     "sticky sessions" so a client stays on the same server.
 *   - Each connection uses memory and a file descriptor, so capacity is
 *     planned in "concurrent connections".
 *
 * -----------------------------------------------------------------------------
 *  6. QUICK INTERVIEW Q&A
 * -----------------------------------------------------------------------------
 *  Q: Which port does WebSocket use?
 *  A: The same ones as HTTP: 80 (ws) and 443 (wss). That is why it gets
 *     through most firewalls.
 *
 *  Q: How do you authenticate a WebSocket?
 *  A: During the handshake: send a token (cookie, or a query param such as
 *     ?token=...) and verify it before accepting the upgrade. Browsers cannot
 *     set custom headers on `new WebSocket()`.
 *
 *  Q: How do you detect dead connections?
 *  A: A heartbeat. The server sends a ping every N seconds. If no pong comes
 *     back before the next ping, it terminates the socket. (Implemented below.)
 *
 *  Q: What happens if the network drops?
 *  A: The client gets `onclose` (often with code 1006) and should
 *     auto-reconnect, ideally with exponential backoff. (Implemented in the
 *     client below.)
 *
 *  Q: Security concerns?
 *  A: Use wss://, validate the Origin header (stops Cross-Site WebSocket
 *     Hijacking), authenticate on handshake, validate and size-limit every
 *     message, rate-limit clients, and never trust client data.
 *
 *  Q: WebSocket vs Socket.IO?
 *  A: WebSocket is the protocol. Socket.IO is a library built on top of it
 *     that adds rooms, auto-reconnect, acknowledgements and fallbacks to
 *     long polling. A Socket.IO client cannot talk to a plain WS server.
 * =============================================================================
 */

// -----------------------------------------------------------------------------
// IMPORTS
// -----------------------------------------------------------------------------
// `http` is built into Node. We create ONE HTTP server that does two jobs:
//   (a) serve the chat web page on normal HTTP requests
//   (b) accept WebSocket upgrade requests on the same port
const http = require("http");

// `ws` is the most popular, fast, minimal WebSocket library for Node.
// Node 22 has a built-in WebSocket CLIENT, but no built-in SERVER, so we use `ws`.
const { WebSocketServer, WebSocket } = require("ws");

const PORT = 3000;

// -----------------------------------------------------------------------------
// STATE (this is what makes the server "stateful")
// -----------------------------------------------------------------------------
// A Set of every connected client socket. To broadcast, we loop over it.
// Note: `wss.clients` also exists in the `ws` library. We keep our own Set
// to make the idea visible.
const clients = new Set();

// Fun random nicknames, just for vibes
const ADJECTIVES = ["Sneaky", "Cosmic", "Spicy", "Sleepy", "Turbo", "Funky", "Mighty", "Chill"];
const NOUNS = ["Samosa", "Panda", "Wizard", "Mango", "Ninja", "Penguin", "Taco", "Robot"];
const COLORS = ["#ff4ecd", "#4ef0ff", "#a3ff4e", "#ffd84e", "#ff8a4e", "#b04eff"];

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

// -----------------------------------------------------------------------------
// HTTP SERVER: serves the chat page (the client code is at the bottom)
// -----------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  // Every normal HTTP request gets the HTML page.
  // WebSocket upgrade requests never reach this handler: `ws` intercepts
  // them through the server's "upgrade" event.
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(CLIENT_HTML);
});

// -----------------------------------------------------------------------------
// WEBSOCKET SERVER: attached to the same HTTP server
// -----------------------------------------------------------------------------
// Passing `{ server }` makes `ws` listen for the HTTP "upgrade" event and
// perform the handshake (the 101 Switching Protocols response) for us.
// `maxPayload` caps message size at 64 KB (a security limit against huge payloads).
const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 });

// Helper: send a JS object to ALL connected clients as a JSON string.
// WebSockets carry text or binary, so we serialize objects with JSON.
function broadcast(data) {
  const message = JSON.stringify(data);
  for (const client of clients) {
    // readyState values: CONNECTING(0), OPEN(1), CLOSING(2), CLOSED(3).
    // Only send to sockets that are fully open.
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  }
}

// Helper: tell everyone how many people are online.
function broadcastOnlineCount() {
  broadcast({ type: "online", count: clients.size });
}

// "connection" fires once per client, right after a successful handshake.
// `socket` = this one client's connection. `req` = the original HTTP request
// (useful for auth: read cookies, query params, or the Origin header from it).
wss.on("connection", (socket, req) => {
  // Attach per-connection info directly to the socket object
  socket.name = `${pick(ADJECTIVES)} ${pick(NOUNS)}`;
  socket.color = pick(COLORS);
  socket.isAlive = true; // used by the heartbeat below

  clients.add(socket);
  console.log(`+ ${socket.name} connected from ${req.socket.remoteAddress} (online: ${clients.size})`);

  // Send a private welcome message to THIS client only (socket.send, not broadcast)
  socket.send(JSON.stringify({ type: "welcome", name: socket.name, color: socket.color }));

  // Tell everyone that someone joined
  broadcast({ type: "system", text: `${socket.name} joined the chat` });
  broadcastOnlineCount();

  // ---------------------------------------------------------------------------
  // "message": fires every time this client sends something
  // ---------------------------------------------------------------------------
  // `raw` is a Buffer; `isBinary` says whether it was a binary or text frame.
  socket.on("message", (raw, isBinary) => {
    if (isBinary) return; // this chat only accepts text frames

    // NEVER trust client input: parse safely and validate
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return socket.send(JSON.stringify({ type: "error", text: "Invalid JSON" }));
    }

    const text = typeof data.text === "string" ? data.text.trim().slice(0, 500) : "";
    if (!text) return; // ignore empty messages

    // Send the chat message to everyone, including the sender
    broadcast({
      type: "chat",
      name: socket.name,
      color: socket.color,
      text,
      time: Date.now(),
    });
  });

  // ---------------------------------------------------------------------------
  // "pong": the client answered our ping, so it is still alive
  // ---------------------------------------------------------------------------
  // Browsers reply to ping frames with pong AUTOMATICALLY; no client code needed.
  socket.on("pong", () => {
    socket.isAlive = true;
  });

  // ---------------------------------------------------------------------------
  // "close": the connection ended (tab closed, network lost, terminated)
  // ---------------------------------------------------------------------------
  socket.on("close", (code) => {
    clients.delete(socket); // ALWAYS clean up state, or you leak memory
    console.log(`- ${socket.name} disconnected (code ${code}, online: ${clients.size})`);
    broadcast({ type: "system", text: `${socket.name} left the chat` });
    broadcastOnlineCount();
  });

  // "error": log it. A "close" event always follows, so cleanup happens there.
  socket.on("error", (err) => {
    console.error(`! Error from ${socket.name}:`, err.message);
  });
});

// -----------------------------------------------------------------------------
// HEARTBEAT: detect and remove dead connections
// -----------------------------------------------------------------------------
// Problem: if a client's Wi-Fi dies, TCP may NOT notice for minutes, so the
// server keeps a "zombie" connection.
// Solution: every 30s, mark everyone as not alive and send a ping.
// Clients that answer with pong are marked alive again. Anyone still not
// alive at the NEXT tick never answered, so we terminate them.
const HEARTBEAT_MS = 30_000;
const heartbeat = setInterval(() => {
  for (const socket of clients) {
    if (!socket.isAlive) {
      socket.terminate(); // hard kill (no close handshake); triggers "close"
      continue;
    }
    socket.isAlive = false;
    socket.ping();
  }
}, HEARTBEAT_MS);

// -----------------------------------------------------------------------------
// START THE SERVER
// -----------------------------------------------------------------------------
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`WebSocket endpoint: ws://localhost:${PORT}`);
  console.log("Open the URL in two browser tabs and start chatting!");
});

// -----------------------------------------------------------------------------
// GRACEFUL SHUTDOWN (Ctrl+C)
// -----------------------------------------------------------------------------
// Close every client with code 1001 ("going away") so clients know the server
// is shutting down on purpose, then stop the HTTP server.
process.on("SIGINT", () => {
  console.log("\nShutting down...");
  clearInterval(heartbeat);
  for (const socket of clients) socket.close(1001, "Server shutting down");
  wss.close();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref(); // fallback if something hangs
});

// =============================================================================
// CLIENT (browser side): the HTML page served above
// =============================================================================
// Kept in this same file so everything lives in one place.
// The browser's built-in `WebSocket` API has 4 main events:
//   onopen    -> connection established (handshake done)
//   onmessage -> a message arrived from the server (event.data)
//   onclose   -> connection closed (event.code tells you why)
//   onerror   -> something went wrong (always followed by onclose)
// and 2 main methods: socket.send(data) and socket.close(code, reason)
var CLIENT_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vibe Chat</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; height: 100vh; display: flex; flex-direction: column;
         background: #0d0b1a; color: #e8e6ff; font-family: system-ui, sans-serif; }
  header { padding: 14px 16px; border-bottom: 1px solid #2a2550;
           display: flex; justify-content: space-between; align-items: center; }
  h1 { margin: 0; font-size: 20px; color: #ff4ecd; text-shadow: 0 0 10px #ff4ecd; }
  #status { font-size: 13px; color: #9b96c9; }
  #messages { flex: 1; overflow-y: auto; padding: 16px; display: flex;
              flex-direction: column; gap: 8px; }
  .msg { background: #1a1633; padding: 8px 12px; border-radius: 10px; max-width: 80%;
         word-wrap: break-word; }
  .msg .name { font-weight: 700; font-size: 13px; }
  .msg .time { font-size: 11px; color: #6f6a99; margin-left: 6px; }
  .system { color: #8a85b8; font-style: italic; font-size: 13px; align-self: center; }
  form { display: flex; gap: 8px; padding: 12px 16px; border-top: 1px solid #2a2550; }
  input { flex: 1; padding: 12px; border-radius: 10px; border: 1px solid #3a3470;
          background: #14112a; color: #fff; font-size: 15px; outline: none; }
  input:focus { border-color: #4ef0ff; box-shadow: 0 0 8px #4ef0ff55; }
  button { padding: 0 20px; border: 0; border-radius: 10px; background: #ff4ecd;
           color: #0d0b1a; font-weight: 700; cursor: pointer; }
</style>
</head>
<body>
  <header>
    <h1>⚡ Vibe Chat</h1>
    <span id="status">connecting...</span>
  </header>
  <div id="messages"></div>
  <form id="form">
    <input id="input" placeholder="Type a message and press Enter" autocomplete="off" maxlength="500">
    <button>Send</button>
  </form>

<script>
  var messagesEl = document.getElementById("messages");
  var statusEl = document.getElementById("status");
  var inputEl = document.getElementById("input");
  var socket;
  var myName = "";
  var online = 0;
  var retryDelay = 1000; // reconnect delay, doubles each failure (exponential backoff)

  function addSystem(text) {
    var div = document.createElement("div");
    div.className = "system";
    div.textContent = text;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function addChat(m) {
    var div = document.createElement("div");
    div.className = "msg";
    var name = document.createElement("span");
    name.className = "name";
    name.style.color = m.color;
    name.textContent = m.name + (m.name === myName ? " (you)" : "");
    var time = document.createElement("span");
    time.className = "time";
    time.textContent = new Date(m.time).toLocaleTimeString();
    var text = document.createElement("div");
    // textContent (NOT innerHTML) so users cannot inject HTML/JS (XSS protection)
    text.textContent = m.text;
    div.append(name, time, text);
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function updateStatus() {
    statusEl.textContent = myName ? myName + " · " + online + " online" : "connecting...";
  }

  function connect() {
    // Use wss:// if the page is served over https, otherwise ws://
    var protocol = location.protocol === "https:" ? "wss://" : "ws://";
    socket = new WebSocket(protocol + location.host); // starts the handshake

    socket.onopen = function () {
      retryDelay = 1000; // connected, so reset the backoff
    };

    socket.onmessage = function (event) {
      var m = JSON.parse(event.data); // the server always sends JSON strings
      if (m.type === "welcome") { myName = m.name; addSystem("You are " + m.name + " ✨"); }
      else if (m.type === "chat") addChat(m);
      else if (m.type === "system") addSystem(m.text);
      else if (m.type === "online") online = m.count;
      else if (m.type === "error") addSystem("Error: " + m.text);
      updateStatus();
    };

    socket.onclose = function (event) {
      // Auto-reconnect with exponential backoff (1s, 2s, 4s ... max 10s)
      statusEl.textContent = "disconnected (code " + event.code + "), retrying...";
      setTimeout(connect, retryDelay);
      retryDelay = Math.min(retryDelay * 2, 10000);
    };
  }

  document.getElementById("form").addEventListener("submit", function (e) {
    e.preventDefault();
    var text = inputEl.value.trim();
    // Only send while the socket is OPEN (readyState 1)
    if (text && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ text: text }));
      inputEl.value = "";
    }
  });

  connect();
</script>
</body>
</html>`;
