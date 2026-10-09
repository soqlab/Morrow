// Local fixtures test the runner itself, not a customer's production readiness.
const assert = require("node:assert/strict");
const http = require("node:http");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { run } = require("./gateway-journeys");

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "airlock-journey-test-"));
  const file = path.join(directory, "fixture.txt"); fs.writeFileSync(file, "TEST_UPLOAD_ONLY");
  process.env.AIRLOCK_TEST_UPLOAD = file;
  process.env.AIRLOCK_TEST_PASSWORD = "TEST_PRIVATE_VALUE";
  let logins = 0, forms = 0, uploads = 0, sockets = 0;
  const server = http.createServer(async (req, res) => {
    let body = ""; for await (const chunk of req) body += chunk;
    res.setHeader("Content-Type", "text/html");
    if (req.url === "/login" && req.method === "POST") {
      assert.ok(body.includes("TEST_PRIVATE_VALUE")); logins++;
      res.setHeader("Set-Cookie", "session=fixture; HttpOnly; SameSite=Lax; Path=/");
      res.writeHead(303, { Location: "/account" }); return res.end();
    }
    if (req.url === "/account") return res.end(req.headers.cookie?.includes("session=fixture") ? "Signed in" : "Not authenticated");
    if (req.url === "/submit" && req.method === "POST") { forms++; return res.end("Form accepted"); }
    if (req.url === "/upload" && req.method === "POST") { assert.ok(body.includes("TEST_UPLOAD_ONLY")); uploads++; return res.end("Upload accepted"); }
    res.end('<form action="/login" method="post"><input name="password" type="password"><button id="login">Sign in</button></form>' +
      '<form action="/submit" method="post"><input name="message"><button id="submit">Submit</button></form>' +
      '<form action="/upload" method="post" enctype="multipart/form-data"><input name="file" type="file"><button id="upload">Upload</button></form>');
  });
  server.on("upgrade", (req, socket) => {
    const accept = createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.once("data", () => { sockets++; socket.end(Buffer.from([0x81, 4, 112, 111, 110, 103])); });
    socket.on("error", () => {});
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const manifest = { base_url: `http://127.0.0.1:${server.address().port}`, tests: [
    { kind: "login", steps: [{ action: "visit", path: "/" }, { action: "fill", selector: "[name=password]", value_env: "AIRLOCK_TEST_PASSWORD" }, { action: "click", selector: "#login" }, { action: "expect_path", path: "/account" }, { action: "expect_text", text: "Signed in" }] },
    { kind: "forms", steps: [{ action: "visit", path: "/" }, { action: "fill", selector: "[name=message]", value: "Fixture" }, { action: "click", selector: "#submit" }, { action: "expect_text", text: "Form accepted" }] },
    { kind: "uploads", steps: [{ action: "visit", path: "/" }, { action: "upload", selector: "[name=file]", file_env: "AIRLOCK_TEST_UPLOAD" }, { action: "click", selector: "#upload" }, { action: "expect_text", text: "Upload accepted" }] },
    { kind: "websocket", steps: [{ action: "visit", path: "/" }, { action: "websocket", path: "/socket", send: "ping", expect: "pong" }] },
  ] };
  try {
    await assert.rejects(run(manifest, false), /approved/);
    const report = await run(manifest, true);
    assert.equal(report.passed, true, JSON.stringify(report));
    assert.deepEqual([logins, forms, uploads, sockets], [1, 1, 1, 1]);
    assert.ok(!JSON.stringify(report).includes("TEST_PRIVATE_VALUE"));
    manifest.tests[0].steps = [{ action: "unsupported", value: "TEST_PRIVATE_VALUE" }];
    const failed = await run(manifest, true);
    assert.equal(failed.passed, false);
    assert.ok(!JSON.stringify(failed).includes("TEST_PRIVATE_VALUE"));
    console.log("PASS: customer runner approval, actual login cookie, form submission, multipart upload, bidirectional WebSocket, and sanitized failure report.");
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.unlinkSync(file); fs.rmdirSync(directory);
    delete process.env.AIRLOCK_TEST_UPLOAD; delete process.env.AIRLOCK_TEST_PASSWORD;
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
