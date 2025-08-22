import express from "express";
import multer from "multer";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import zlib from "zlib";
import path from "path";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const CONSENT_COOKIE = "lab_consent";

/** 기본 설정 */
app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use((req, _res, next) => { console.log("HIT", req.method, req.url); next(); });
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true }));

/** --- API 엔드포인트 --- */
// 에코
app.all("/echo", (req, res) => {
  res.json({ ok: true, method: req.method, path: req.path, headers: req.headers, query: req.query, body: req.body });
});

// 인증
const USER = process.env.BASIC_USER || "admin";
const PASS = process.env.BASIC_PASS || "secret";
app.get("/auth", (req, res) => {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Basic ")) return res.status(401).set("WWW-Authenticate","Basic realm=\"curl-lab\"").send("Auth required");
  const [u, p] = Buffer.from(auth.slice(6), "base64").toString().split(":");
  if (u === USER && p === PASS) return res.json({ ok: true, user: u });
  return res.status(403).json({ ok: false, reason: "invalid credentials" });
});

// 파일 업로드
app.post("/upload", upload.single("file"), (req, res) => {
  res.json({ ok: true, filename: req.file?.originalname, size: req.file?.size, mimetype: req.file?.mimetype });
});
const multiUpload = upload.array("files", 3);
app.post("/uploads", (req, res) => {
  multiUpload(req, res, (err) => {
    if (err) return res.status(400).json({ ok: false, error: String(err) });
    const files = (req.files || []).map(f => ({ field: f.fieldname, filename: f.originalname, size: f.size, mimetype: f.mimetype }));
    res.json({ ok: true, count: files.length, files });
  });
});
const imgOnly = multer({ storage: multer.memoryStorage(), fileFilter: (_req, file, cb) => (/^image\//.test(file.mimetype) ? cb(null, true) : cb(new Error("Only image/* allowed"))) }).single("image");
app.post("/upload-image", (req, res) => {
  imgOnly(req, res, (err) => {
    if (err) return res.status(400).json({ ok: false, error: String(err) });
    res.json({ ok: true, filename: req.file?.originalname, size: req.file?.size, mimetype: req.file?.mimetype });
  });
});

// 쿠키
app.get("/cookie/set", (req, res) => {
  const value = req.query.value || "true";
  res.cookie(CONSENT_COOKIE, value, { httpOnly: true, sameSite: "Lax", path: "/" });
  res.json({ ok: true, set: { CONSENT_COOKIE, value } });
});
app.get("/cookie/require", (req, res) => {
  if (req.cookies[CONSENT_COOKIE] !== "true") {
    return res.status(403).json({ ok: false, reason: `Cookie "${CONSENT_COOKIE}=true" required`, got: req.cookies });
  }
  res.json({ ok: true, note: "Consent cookie present" });
});
app.get("/cookie/clear", (req, res) => {
  res.clearCookie(CONSENT_COOKIE, { path: "/" });
  res.json({ ok: true, cleared: CONSENT_COOKIE });
});

// 기타 기능 (delay, redirect, status, limited, gzip, items)
app.get("/delay/:ms", (req, res) => { const ms = Math.min(parseInt(req.params.ms || "0", 10) || 0, 10000); setTimeout(() => res.json({ ok: true, delayed: ms }), ms); });
app.get("/redirect", (_req, res) => res.redirect(302, "/echo?from=redirect"));
app.get("/status/:code", (req, res) => { const n = Math.max(100, Math.min(599, parseInt(req.params.code, 10) || 200)); res.status(n).json({ ok: n < 400, status: n }); });
const limiter20 = rateLimit({ windowMs: 60_000, max: 20 });
app.get("/limited", limiter20, (_req, res) => res.json({ ok: true, note: "rate-limited endpoint" }));
app.get("/gzip", (_req, res) => { const payload = JSON.stringify({ hello: "world", ts: Date.now() }); zlib.gzip(payload, (_e, buf) => res.set("Content-Encoding", "gzip").type("application/json").send(buf)); });
app.get("/items", (req, res) => { const page = Math.max(1, parseInt(req.query.page || "1", 10)); const size = Math.min(50, Math.max(1, parseInt(req.query.size || "5", 10))); const total = 42; const start = (page - 1) * size + 1; const items = Array.from({ length: size }, (_, i) => ({ id: start + i })); res.json({ page, size, total, items }); });

// 정적 문서 & 스펙
app.get("/openapi.yaml", (_req, res) => res.sendFile(path.join(__dirname, "openapi.yaml")));
app.use("/", express.static(path.join(__dirname, "public")));

// 서버 시작
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`listening on ${port}`));
