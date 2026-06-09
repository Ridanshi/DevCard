import { randomBytes } from 'node:crypto';

import { encrypt } from '../utils/encryption.js';

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

const GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';

// Follow-capable tokens are stored under a dedicated platform key so that
// the authentication flow (read:user user:email scope, key = 'github') and
// the connect flow (user:follow scope, key = 'github_follow') never share
// the same OAuthToken record.
const GITHUB_FOLLOW_PLATFORM = 'github_follow';

// Nonce TTL: 10 minutes — generous for a login round-trip, short enough to
// limit the window a leaked state URL could be abused.
const OAUTH_NONCE_TTL_SECONDS = 600;

interface OAuthCallbackQuery {
  code: string;
  state?: string;
}

interface ParsedOAuthState {
  userId: string;
  nonce: string;
}

export async function connectRoutes(app: FastifyInstance) {
  // ─── Status ───

  app.get('/status', {
    preHandler: [(req, rep) => app.authenticate(req, rep)],
  }, async (request: FastifyRequest, _reply: FastifyReply) => {
    const userId = (request.user as any).id;

    const tokens = await app.prisma.oAuthToken.findMany({
      where: { userId },
      select: { platform: true, createdAt: true, scopes: true },
    });

    return { connectedPlatforms: tokens };
  });

  // ─── GitHub Connect ───

  app.get('/github', {
    preHandler: [(req, rep) => app.authenticate(req, rep)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = (request.user as any).id;
    const nonce = generateNonce();

    // Persist the nonce server-side before issuing the redirect.
    // Fail closed: if Redis is unavailable we must not issue the redirect —
    // a missing nonce store would leave the callback with no way to validate state.
    try {
      await app.redis.set(
        `oauth:nonce:${nonce}`,
        userId,
        'EX',
        OAUTH_NONCE_TTL_SECONDS,
      );
    } catch (err) {
      app.log.error({ err }, 'Failed to persist OAuth nonce — aborting connect flow');
      return reply.status(500).send({ error: 'Failed to initiate OAuth flow' });
    }

    const state = Buffer.from(JSON.stringify({ userId, nonce })).toString('base64');
    const redirectUri = `${process.env.BACKEND_URL}/api/connect/github/callback`;
    const params = new URLSearchParams({
      client_id: process.env.GITHUB_CLIENT_ID ?? '',
      redirect_uri: redirectUri,
      scope: 'user:follow',
      state,
    });

    return reply.redirect(`${GITHUB_AUTH_URL}?${params}`);
  });

  app.get('/github/callback', async (
    request: FastifyRequest<{ Querystring: OAuthCallbackQuery }>,
    reply: FastifyReply,
  ) => {
    const { code, state } = request.query;

    if (!code || !state) {
      return reply.redirect(`${process.env.PUBLIC_APP_URL}/settings?error=missing_params`);
    }

    try {
      // ── Step 1: parse state ────────────────────────────────────────────────
      const decodedState = parseOAuthState(state);
      if (!decodedState) {
        app.log.warn('OAuth callback received malformed or unparseable state payload');
        return reply.redirect(`${process.env.PUBLIC_APP_URL}/settings?error=connect_failed`);
      }

      // ── Step 2: validate nonce server-side ────────────────────────────────
      // Any failure — unknown nonce, expired nonce, replay, userId mismatch,
      // or Redis error — fails closed: callback is rejected, no token exchanged.
      //
      // The nonce is deleted BEFORE the token exchange so that a mid-flight
      // error cannot leave a reusable nonce in the store.
      let storedUserId: string | null;
      try {
        const nonceKey = `oauth:nonce:${decodedState.nonce}`;
        storedUserId = await app.redis.get(nonceKey);
        if (storedUserId !== null) {
          // Consume immediately — one-time use regardless of what follows.
          await app.redis.del(nonceKey);
        }
      } catch (err) {
        app.log.error({ err }, 'Redis error during OAuth nonce lookup — aborting callback');
        return reply.redirect(`${process.env.PUBLIC_APP_URL}/settings?error=server_error`);
      }

      if (storedUserId === null) {
        // Nonce unknown or already expired/consumed — replay or forged request.
        app.log.warn('OAuth callback nonce not found in Redis — possible replay or forged state');
        return reply.redirect(`${process.env.PUBLIC_APP_URL}/settings?error=connect_failed`);
      }

      if (storedUserId !== decodedState.userId) {
        // Nonce exists but was issued for a different user — state was tampered.
        app.log.warn('OAuth nonce userId mismatch — state payload does not match issuing session');
        return reply.redirect(`${process.env.PUBLIC_APP_URL}/settings?error=connect_failed`);
      }

      // Use the Redis-sourced userId as authoritative.
      // The userId from the client-controlled state parameter is never trusted.
      const userId = storedUserId;

      // ── Step 3: exchange code for token ───────────────────────────────────
      const tokenRes = await fetch(GITHUB_TOKEN_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          client_id: process.env.GITHUB_CLIENT_ID,
          client_secret: process.env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: `${process.env.BACKEND_URL}/api/connect/github/callback`,
        }),
      });

      const tokenData = (await tokenRes.json()) as any;

      if (tokenData.error) {
        app.log.error('GitHub token exchange failed during connect flow');
        return reply.redirect(`${process.env.PUBLIC_APP_URL}/settings?error=connect_failed`);
      }

      // ── Step 4: persist encrypted token ───────────────────────────────────
      // Store under the dedicated follow-scope key so that a subsequent login
      // (which writes to 'github') cannot overwrite this follow-capable credential.
      const encryptedToken = encrypt(tokenData.access_token);

      await app.prisma.oAuthToken.upsert({
        where: {
          userId_platform: {
            userId,
            platform: GITHUB_FOLLOW_PLATFORM,
          },
        },
        update: {
          accessToken: encryptedToken,
          scopes: tokenData.scope ?? 'user:follow',
        },
        create: {
          userId,
          platform: GITHUB_FOLLOW_PLATFORM,
          accessToken: encryptedToken,
          scopes: tokenData.scope ?? 'user:follow',
        },
      });

      // ── Step 5: redirect back to the originating client ───────────────────
      if (decodedState.nonce.startsWith('mobile_')) {
        return reply.redirect(`${process.env.MOBILE_REDIRECT_URI ?? 'devcard://connect'}?connected=github`);
      }

      return reply.redirect(`${process.env.PUBLIC_APP_URL}/settings?connected=github`);

    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      app.log.error({ err, message }, 'GitHub connect error');
      return reply.redirect(`${process.env.PUBLIC_APP_URL}/settings?error=server_error`);
    }
  });


  // ─── Disconnect ───

  app.delete('/:platform', {
    preHandler: [(req, rep) => app.authenticate(req, rep)],
  }, async (request: FastifyRequest<{ Params: { platform: string } }>, reply: FastifyReply) => {
    const userId = (request.user as any).id;
    const { platform } = request.params;

    const SUPPORTED_PLATFORMS = ['github', 'google', 'twitter', 'linkedin'];
    if (!SUPPORTED_PLATFORMS.includes(platform)) {
      return reply.status(400).send({ error: `Unsupported platform: ${platform}` });
    }

    try {
      await app.prisma.oAuthToken.delete({
        where: {
          userId_platform: {
            userId,
            platform,
          },
        },
      });
      return { success: true };
    } catch {
      return reply.status(404).send({ error: 'Connection not found' });
    }
  });
}

function parseOAuthState(state: string): ParsedOAuthState | null {
  try {
    const decoded = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));

    if (typeof decoded !== 'object' || decoded === null) {
      return null;
    }
    if (typeof decoded.userId !== 'string' || typeof decoded.nonce !== 'string') {
      return null;
    }
    return decoded as ParsedOAuthState;
  } catch {
    return null;
  }
}

function generateNonce(): string {
  return randomBytes(32).toString('hex');
}
