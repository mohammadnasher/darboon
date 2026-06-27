import * as Joi from 'joi';

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().default(3000),

  // Role: 'api' serves HTTP only, 'worker' consumes queues only, 'all' does both.
  DARBOON_ROLE: Joi.string().valid('api', 'worker', 'all').default('all'),

  // ── Database ────────────────────────────────────────────────────────────────
  DATABASE_URL: Joi.string().uri().required(),
  RUN_MIGRATIONS: Joi.boolean().default(false),

  // ── Redis (BullMQ + throttler storage + RBAC cache) ─────────────────────────
  REDIS_URL: Joi.string().uri().required(),

  // ── Issuer / tokens ─────────────────────────────────────────────────────────
  // The canonical issuer URL (e.g. https://auth.domain.com). Embedded as `iss`
  // and used to build the OIDC discovery document.
  DARBOON_ISSUER: Joi.string().uri().required(),
  ACCESS_TOKEN_TTL: Joi.number().default(900), // seconds (15 min)
  REFRESH_TOKEN_TTL: Joi.number().default(2592000), // seconds (30 days)
  JWT_ALG: Joi.string().valid('ES256', 'RS256').default('ES256'),

  // ── Signing-key encryption ──────────────────────────────────────────────────
  // 32-byte master key (hex or base64) used to AES-256-GCM encrypt signing
  // private keys at rest. Sourced from a k8s Secret / KMS; NEVER committed.
  KEY_ENCRYPTION_SECRET: Joi.string().min(32).required(),
  KEY_ROTATION_DAYS: Joi.number().default(90),

  // ── chapar notification gateway ─────────────────────────────────────────────
  CHAPAR_BASE_URL: Joi.string().uri().default('http://chapar:3000'),
  CHAPAR_API_KEY: Joi.string().required(), // plaintext, sent as X-API-Key
  OTP_APP_NAME: Joi.string().default('Darboon'),

  // ── OTP ─────────────────────────────────────────────────────────────────────
  OTP_LENGTH: Joi.number().default(6),
  OTP_TTL_SECONDS: Joi.number().default(300), // 5 min
  OTP_MAX_ATTEMPTS: Joi.number().default(5),
  OTP_RESEND_WINDOW_SECONDS: Joi.number().default(60),

  // ── Google social login ─────────────────────────────────────────────────────
  GOOGLE_CLIENT_ID: Joi.string().optional(),
  GOOGLE_CLIENT_SECRET: Joi.string().optional(),
  GOOGLE_REDIRECT_URI: Joi.string().uri().optional(),

  // ── Password hashing (argon2id) ─────────────────────────────────────────────
  ARGON_MEMORY_COST: Joi.number().default(19456), // KiB (~19 MiB)
  ARGON_TIME_COST: Joi.number().default(2),
  ARGON_PARALLELISM: Joi.number().default(1),

  // ── Account lockout ─────────────────────────────────────────────────────────
  LOCKOUT_MAX_FAILURES: Joi.number().default(5),
  LOCKOUT_BASE_SECONDS: Joi.number().default(60),

  // ── Rate limiting ───────────────────────────────────────────────────────────
  THROTTLE_TTL: Joi.number().default(60),
  THROTTLE_LIMIT: Joi.number().default(100),

  // ── Admin auth ──────────────────────────────────────────────────────────────
  // SHA-256 (hex) of the admin API key for machine access to /admin endpoints.
  // Generate: node -e "console.log(require('crypto').createHash('sha256').update('KEY').digest('hex'))"
  ADMIN_API_KEY_HASH: Joi.string().required(),
  // Bootstrap admin user seeded by the first migration.
  ADMIN_BOOTSTRAP_EMAIL: Joi.string().email().optional(),
  ADMIN_BOOTSTRAP_PASSWORD: Joi.string().optional(),

  // ── CORS ────────────────────────────────────────────────────────────────────
  // Comma-separated list of allowed dashboard origins. '*' allows any (dev only).
  CORS_ALLOWED_ORIGINS: Joi.string().default('*'),
});
