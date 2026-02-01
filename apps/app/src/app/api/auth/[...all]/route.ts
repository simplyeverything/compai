import { auth } from '@/utils/auth';
import { toNextJsHandler } from 'better-auth/next-js';

const base = toNextJsHandler(auth.handler);

// Comma-separated list of exact origins (no wildcards when using credentials)
const allowedOrigins = (process.env.AUTH_TRUSTED_ORIGINS ?? '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function withCors(req: Request, res: Response) {
  const origin = req.headers.get('origin') ?? '';
  if (!origin) return res;

  // Only allow origins we explicitly trust
  if (!allowedOrigins.includes(origin)) return res;

  res.headers.set('Access-Control-Allow-Origin', origin);
  res.headers.set('Vary', 'Origin');
  res.headers.set('Access-Control-Allow-Credentials', 'true');
  res.headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');

  const reqHeaders =
    req.headers.get('access-control-request-headers') ?? 'content-type,authorization';
  res.headers.set('Access-Control-Allow-Headers', reqHeaders);

  res.headers.set('Access-Control-Max-Age', '600');
  return res;
}

export async function GET(req: Request) {
  const res = await base.GET(req);
  return withCors(req, res);
}

export async function POST(req: Request) {
  const res = await base.POST(req);
  return withCors(req, res);
}

// Critical for browser preflight from portal -> app
export async function OPTIONS(req: Request) {
  const res = new Response(null, { status: 204 });
  return withCors(req, res);
}
