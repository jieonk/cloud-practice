import express from "express";
import multer from "multer";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import zlib from "zlib";
import path from "path";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";
import fs from "fs";
import fsp from "fs/promises";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const CONSENT_COOKIE = "lab_consent";

const BASE_DIR = "/tmp/uploads"; // Render 등에서 쓰기 가능한 임시 디렉터리
await fsp.mkdir(BASE_DIR, { recursive: true });

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

// 경로 안전화 (디렉터리 탈출 방지)
function safePath(userPath = ".") {
  const target = path.normalize(path.join(BASE_DIR, userPath));
  if (!target.startsWith(BASE_DIR)) throw new Error("Invalid path");
  return target;
}

// 디렉터리 생성: POST /fs/mkdir  { "dir": "classA" }
app.post("/fs/mkdir", async (req, res) => {
  try {
    const dir = String(req.body?.dir || "").trim();
    if (!dir) return res.status(400).json({ ok: false, error: "dir required" });
    const full = safePath(dir);
    await fsp.mkdir(full, { recursive: true });
    res.json({ ok: true, dir, full });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// 디렉터리 목록: GET /fs/list?dir=classA
app.get("/fs/list", async (req, res) => {
  try {
    const dir = req.query.dir ? String(req.query.dir) : ".";
    const full = safePath(dir);
    const entries = await fsp.readdir(full, { withFileTypes: true });
    res.json({
      ok: true,
      cwd: dir,
      items: await Promise.all(entries.map(async (ent) => {
        const p = path.join(full, ent.name);
        const st = await fsp.stat(p);
        return { name: ent.name, isDir: ent.isDirectory(), size: st.size, mtime: st.mtimeMs };
      }))
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// 업로드 저장 경로를 디렉터리별로: POST /fs/upload?dir=classA (필드명 file)
const diskStorage = multer.diskStorage({
  destination(req, file, cb) {
    try {
      const dir = safePath(req.query.dir ? String(req.query.dir) : ".");
      fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    } catch (e) {
      cb(e);
    }
  },
  filename(_req, file, cb) {
    cb(null, file.originalname);
  }
});
const uploadDisk = multer({
  storage: diskStorage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
}).single("file");

app.post("/fs/upload", (req, res) => {
  uploadDisk(req, res, (err) => {
    if (err) return res.status(400).json({ ok: false, error: String(err) });
    res.json({
      ok: true,
      saved: path.join(String(req.query.dir || "."), req.file.originalname),
      size: req.file.size,
      mimetype: req.file.mimetype
    });
  });
});

// 파일 읽기: GET /fs/file?path=classA/notes.txt
app.get("/fs/file", async (req, res) => {
  try {
    const p = req.query.path ? String(req.query.path) : "";
    if (!p) return res.status(400).json({ ok: false, error: "path required" });
    const full = safePath(p);
    res.sendFile(full);
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// 파일 덮어쓰기(수정): PUT /fs/file?path=classA/notes.txt   --data-binary @local.txt
app.put("/fs/file", async (req, res) => {
  try {
    const p = req.query.path ? String(req.query.path) : "";
    if (!p) return res.status(400).json({ ok: false, error: "path required" });
    const full = safePath(p);
    // 바디를 스트림으로 받아 그대로 저장
    await new Promise((resolve, reject) => {
      const ws = fs.createWriteStream(full);
      req.pipe(ws);
      req.on("end", resolve);
      req.on("error", reject);
      ws.on("error", reject);
    });
    const st = await fsp.stat(full);
    res.json({ ok: true, path: p, size: st.size, replaced: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// 파일 삭제: DELETE /fs/file?path=classA/old.txt
app.delete("/fs/file", async (req, res) => {
  try {
    const p = req.query.path ? String(req.query.path) : "";
    if (!p) return res.status(400).json({ ok: false, error: "path required" });
    const full = safePath(p);
    await fsp.unlink(full);
    res.json({ ok: true, deleted: p });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});


// 정적 문서 & 스펙
app.get("/openapi.yaml", (_req, res) => res.sendFile(path.join(__dirname, "openapi.yaml")));
app.use("/", express.static(path.join(__dirname, "public")));

// 서버 시작
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`listening on ${port}`));


