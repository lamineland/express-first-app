# Task Manager REST API

A secure REST API where users authenticate with **email/password (JWT)** or **Google OAuth**, and manage only their own tasks.

## Stack

Express 4 · Mongoose 9 · JWT · Passport (Google OAuth 2.0) · bcrypt · helmet · express-rate-limit · express-validator · Jest + Supertest

## Quick start

```bash
npm install
cp .env.example .env     # then edit the values
npm run dev              # http://localhost:4000
```

The API needs a MongoDB instance. Point `MONGO_URI` at one — local
(`mongodb://127.0.0.1:27017/task_manager`), Docker, or a hosted Atlas cluster.

```bash
npm test                 # 64 tests, uses an in-memory MongoDB
```

## Environment

Everything lives in `.env` (see `.env.example` for the annotated list). The
values that matter most:

| Variable | Purpose |
| --- | --- |
| `JWT_SECRET` | Signs tokens. **Required** in production, min 32 chars. |
| `MONGO_URI` | MongoDB connection string. |
| `NODE_ENV` | Cookies are marked `Secure` whenever this is `production`. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth credentials. Leave blank to disable Google routes (they return `503`). |
| `CORS_ORIGIN` | Comma-separated allowlist of browser origins. |
| `AUTH_RATE_LIMIT_MAX` | Login/signup attempts per IP per window (default `5` / 15 min). |
| `EXPOSE_TOKEN_IN_RESPONSE` | Dev convenience: also return the JWT in JSON. Keep `false` in production. |

The app **fails to start** in production if `JWT_SECRET` is missing, is the
placeholder, or is shorter than 32 characters.

## Endpoints

### Auth

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/api/auth/signup` | – | Create an account, sets the auth cookie |
| `POST` | `/api/auth/login` | – | Log in, sets the auth cookie |
| `POST` | `/api/auth/logout` | – | Clears the auth cookie |
| `GET` | `/api/auth/google` | – | Redirect to Google consent screen |
| `GET` | `/api/auth/google/callback` | – | Google redirect target, sets the cookie |
| `GET` | `/api/auth/me` | ✅ | Current user |

### Tasks (all require auth)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/tasks` | Create a task |
| `GET` | `/api/tasks` | List **your** tasks (`?status=&priority=&sort=&page=&limit=`) |
| `GET` | `/api/tasks/:id` | Read one of your tasks |
| `PATCH` | `/api/tasks/:id` | Update one of your tasks |
| `DELETE` | `/api/tasks/:id` | Delete one of your tasks |
| `GET` | `/health` | Liveness check |

### Examples

```bash
# signup (stores the cookie in cookies.txt)
curl -c cookies.txt -X POST http://localhost:4000/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"name":"Ada","email":"ada@example.com","password":"sup3rSecret","passwordConfirm":"sup3rSecret"}'

# create a task
curl -b cookies.txt -X POST http://localhost:4000/api/tasks \
  -H 'Content-Type: application/json' \
  -d '{"title":"Ship the API","priority":"high"}'

# list your tasks
curl -b cookies.txt http://localhost:4000/api/tasks

# delete a task
curl -b cookies.txt -X DELETE http://localhost:4000/api/tasks/<id>
```

A `Bearer <token>` header also works for API clients that cannot hold cookies.

## Response shapes

Success:

```json
{ "status": "success", "data": { "task": { "_id": "...", "title": "..." } } }
```

Error (consistent shape everywhere, including 404s and 500s):

```json
{
  "status": "fail",
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": [{ "field": "password", "message": "Password must be at least 8 characters" }]
  }
}
```

`error.code` is a stable, machine-readable identifier (`NO_TOKEN`,
`INVALID_CREDENTIALS`, `TASK_NOT_FOUND`, `TOO_MANY_REQUESTS`, …).

## Security notes

- **JWT in an HTTP-only cookie** — `httpOnly` (XSS cannot read it), `sameSite=Lax`
  (blocks the main CSRF vector), `Secure` in production.
- **Token revocation** — changing a password stamps `passwordChangedAt`; older
  tokens are rejected. Deleted/deactivated users lose access immediately because
  the user is re-loaded on every request.
- **Ownership in the query** — tasks are always fetched with
  `{ _id, owner: req.user._id }`. A task belonging to someone else returns
  **404, not 403**, so task ids cannot be probed for existence.
- **Mass-assignment protection** — only `title`, `description`, `status`,
  `priority` and `dueDate` are copied from the body; `owner` in a request body is
  ignored.
- **No user enumeration** — wrong email and wrong password return the same 401
  message, and a dummy bcrypt comparison keeps timings comparable.
- **Input sanitization** — `express-mongo-sanitize` strips `$`/`.` operators
  (NoSQL injection), `xss-clean` escapes HTML.
- **Rate limiting** — strict on credential routes, broad across `/api`.
- **OAuth `state` without sessions** — the app is stateless, so `state` is a
  signed JWT containing a nonce that must match an HTTP-only cookie. This blocks
  login-CSRF without needing `express-session`.
- **No open redirects** — the post-login `?redirect=` value must be a relative
  path; absolute and protocol-relative URLs are discarded.
- **Error hygiene** — stacks and driver internals are shown in development only;
  production returns a generic 500 message.

## Project layout

```
src/
  app.js                 # express app (no listen; importable in tests)
  server.js              # entrypoint: connect DB, listen, graceful shutdown
  config/
    env.js               # env parsing + validation
    db.js                # mongoose connection
    passport.js          # Google strategy
  models/                # User, Task
  controllers/           # authController, taskController
  routes/                # authRoutes, taskRoutes
  middleware/
    verifyToken.js       # protects private routes
    restrictTo.js        # role gate (for future admin routes)
    validateAuth.js      # signup/login rules + validate()
    validateTask.js      # task rules
    security.js          # helmet, CORS, mongo-sanitize, xss-clean
    rateLimiter.js       # auth + global limiters
    errorHandler.js      # centralized error middleware
    notFound.js          # 404 fallback
  utils/
    AppError.js          # operational error class
    catchAsync.js        # async wrapper
    jwt.js               # sign / verify
    cookie.js            # cookie set/clear/read
tests/                   # 64 tests (auth, tasks, errors, rate limiting)
```

## Deploying

1. Set `NODE_ENV=production`, a strong `JWT_SECRET`, and a real `MONGO_URI`.
2. Serve over HTTPS — cookies are `Secure`, so they will not be sent over plain
   HTTP.
3. Set `CORS_ORIGIN` to your frontend's exact origin (not `*`; credentials
   require an explicit origin).
4. Register `<your-domain>/api/auth/google/callback` as an authorized redirect
   URI in the Google Cloud console and set `GOOGLE_CALLBACK_URL` to match.
