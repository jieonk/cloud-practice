// server.js
import express from "express";
import multer from "multer";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import zlib from "zlib";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

/** 기본 설정 */
app.use(morgan("combined"));                       // 요청 로그
app.use(express.json());                           // JSON 바디 파서
app.use(express.urlencoded({ extended: true }));   // 폼 바디 파서
app.use((req, res, next) => {                      // CORS (실습 편의)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// 전역 rate-limit (IP당 분당 120회)
app.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

/** --- API 엔드포인트 --- */

// 1) 에코: 보낸 것 그대로 돌려주기
app.all("/echo", (req, res) => {
  res.json({
    ok: true,
    method: req.method,
    path: req.path,
    headers: req.headers,
    query: req.query,
    body: req.body,
  });
});

// 2) 기본 인증 예제 (환경변수로 계정 설정)
const USER = process.env.BASIC_USER || "admin";
const PASS = process.env.BASIC_PASS || "secret";
app.get("/auth", (req, res) => {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Basic ")) {
    return res.status(401).set("WWW-Authenticate","Basic realm=\"curl-lab\"").send("Auth required");
  }
  const [u, p] = Buffer.from(auth.slice(6), "base64").toString().split(":");
  if (u === USER && p === PASS) return res.json({ ok: true, user: u });
  return res.status(403).json({ ok: false, reason: "invalid credentials" });
});

// 3) 파일 업로드 (멀티파트)
app.post("/upload", upload.single("file"), (req, res) => {
  res.json({
    ok: true,
    filename: req.file?.originalname || null,
    size: req.file?.size || 0,
    mimetype: req.file?.mimetype || null,
  });
});

// 4) 지연 응답
app.get("/delay/:ms", (req, res) => {
  const ms = Math.min(parseInt(req.params.ms || "0", 10) || 0, 10000);
  setTimeout(() => res.json({ ok: true, delayed: ms }), ms);
});

// 5) 리다이렉트
app.get("/redirect", (req, res) => res.redirect(302, "/echo?from=redirect"));

// 6) 임의 상태코드
app.get("/status/:code", (req, res) => {
  const n = Math.max(100, Math.min(599, parseInt(req.params.code, 10) || 200));
  res.status(n).json({ ok: n < 400, status: n });
});

// 7) 제한 엔드포인트 (IP당 분당 20회)
const limiter20 = rateLimit({ windowMs: 60_000, max: 20 });
app.get("/limited", limiter20, (req, res) => res.json({ ok: true, note: "rate-limited endpoint" }));

// 8) gzip 응답
app.get("/gzip", (_req, res) => {
  const payload = JSON.stringify({ hello: "world", ts: Date.now() });
  zlib.gzip(payload, (_e, buf) => {
    res.set("Content-Encoding", "gzip").type("application/json").send(buf);
  });
});

// 9) 페이지네이션 샘플
app.get("/items", (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const size = Math.min(50, Math.max(1, parseInt(req.query.size || "5", 10)));
  const total = 42;
  const start = (page - 1) * size + 1;
  const items = Array.from({ length: size }, (_, i) => ({ id: start + i }));
  res.json({ page, size, total, items });
});

// OpenAPI 스펙 정적 제공 (선택)
app.get("/openapi.yaml", (_req, res) => res.sendFile(path.join(__dirname, "openapi.yaml")));

// 문서 페이지(정적)
app.use("/", express.static(path.join(__dirname, "public")));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`listening on ${port}`));
