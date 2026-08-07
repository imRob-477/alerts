// netlify/functions/post-alert.js
// Publica un tweet de alerta sísmica en X (API v2) usando OAuth 1.0a user context.
// No requiere paquetes externos: firma la petición a mano con el módulo "crypto" de Node.

const crypto = require('crypto');

const API_KEY = process.env.X_API_KEY;
const API_SECRET = process.env.X_API_SECRET;
const ACCESS_TOKEN = process.env.X_ACCESS_TOKEN;
const ACCESS_SECRET = process.env.X_ACCESS_SECRET;

function percentEncode(str) {
  return encodeURIComponent(str)
    .replace(/[!*()']/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function buildOAuthHeader(method, url, extraParams = {}) {
  const oauthParams = {
    oauth_consumer_key: API_KEY,
    oauth_nonce: crypto.randomBytes(16).toString('hex'),
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_token: ACCESS_TOKEN,
    oauth_version: '1.0',
    ...extraParams,
  };

  const allParams = { ...oauthParams };
  const paramString = Object.keys(allParams)
    .sort()
    .map(k => `${percentEncode(k)}=${percentEncode(allParams[k])}`)
    .join('&');

  const baseString = [
    method.toUpperCase(),
    percentEncode(url),
    percentEncode(paramString),
  ].join('&');

  const signingKey = `${percentEncode(API_SECRET)}&${percentEncode(ACCESS_SECRET)}`;
  const signature = crypto
    .createHmac('sha1', signingKey)
    .update(baseString)
    .digest('base64');

  oauthParams.oauth_signature = signature;

  const header = 'OAuth ' + Object.keys(oauthParams)
    .sort()
    .map(k => `${percentEncode(k)}="${percentEncode(oauthParams[k])}"`)
    .join(', ');

  return header;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Método no permitido' }) };
  }

  if (!API_KEY || !API_SECRET || !ACCESS_TOKEN || !ACCESS_SECRET) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Faltan variables de entorno de X' }) };
  }

  let payload;
  try {
    payload = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: 'Body inválido' }) };
  }

  const { text } = payload;
  if (!text) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Falta el texto del tweet' }) };
  }

  const url = 'https://api.twitter.com/2/tweets';

  try {
    const authHeader = buildOAuthHeader('POST', url);

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text }),
    });

    const data = await res.json();

    if (!res.ok) {
      return {
        statusCode: res.status,
        body: JSON.stringify({ error: data.detail || data.title || 'Error al publicar en X', raw: data }),
      };
    }

    const tweetId = data.data && data.data.id;
    return {
      statusCode: 200,
      body: JSON.stringify({
        ok: true,
        id: tweetId,
        url: tweetId ? `https://x.com/i/web/status/${tweetId}` : null,
      }),
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
};
