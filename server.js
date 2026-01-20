/*
  All rights reserved 2026 © Syntaxial - Pro Modernis
  Proprietary and confidential.
*/
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
const admin = require('firebase-admin');

// --- INITIALIZATION ---
const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Firebase Admin for Railway
// Expects the full JSON content in the FIREBASE_SERVICE_ACCOUNT env var
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log("Firebase Admin initialized successfully.");
  } else {
    console.warn("WARNING: FIREBASE_SERVICE_ACCOUNT not set. Auth tokens will not be generated.");
    admin.initializeApp(); // Attempt default init (might fail in prod without creds)
  }
} catch (e) {
  console.error("Firebase Admin Init Error:", e.message);
}

// --- CRITICAL CONFIGURATION ---
const APP_ID = process.env.APP_ID || 'default-app-id';
const FIREBASE_CONFIG_PUBLIC = process.env.FIREBASE_CONFIG_PUBLIC || '{}';
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const DSI_API_KEY = process.env.DSI_API_KEY;

// --- MIDDLEWARE ---
app.use(helmet({
  contentSecurityPolicy: false // Disabled to allow inline scripts for config injection
}));
app.use(cors({ origin: true }));
app.use(bodyParser.json({ verify: rawBodySaver }));

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300
});
app.use('/api/', limiter);

function rawBodySaver(req, res, buf, encoding) {
  if (buf && buf.length) req.rawBody = buf.toString(encoding || 'utf8');
}

// --- CORE LOGIC: DSI PROCESSOR ---
function processDsiSchema(data, config) {
  if (!config.jsonLdTemplate) return "{}";
  
  let jsonString = config.jsonLdTemplate;
  const finalSchema = JSON.parse(jsonString);

  function traverse(obj) {
    for (const key in obj) {
      if (typeof obj[key] === 'string' && obj[key].startsWith('[') && obj[key].endsWith(']')) {
        const sourceKey = obj[key].slice(1, -1);
        if (data[sourceKey] !== undefined) {
          obj[key] = data[sourceKey];
        } else {
          delete obj[key];
        }
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        traverse(obj[key]);
      }
    }
  }
  traverse(finalSchema);
  return JSON.stringify(finalSchema, null, 2);
}

// --- API ENDPOINTS ---

// 1. Health Check
app.get('/api/v1/dsi/pulse', (req, res) => {
  res.json({ status: 'active', platform: 'railway', timestamp: new Date().toISOString() });
});

// 2. DSI Schema Injection
app.post('/api/dsi/schema', async (req, res) => {
  try {
    const clientApiKey = req.headers['x-dsi-api-key'] || req.headers['x-dsi-api-key'.toLowerCase()];
    if (clientApiKey !== DSI_API_KEY) {
      return res.status(401).json({ error: 'Unauthorized: Invalid API Key' });
    }

    const { appId, productData } = req.body;
    const targetAppId = appId || APP_ID;

    const config = await prisma.appConfig.findUnique({
      where: { id: targetAppId }
    });

    if (!config) {
      return res.json({ schema: "{}", note: "No config found" });
    }

    const finalSchema = processDsiSchema(productData, config);
    res.json({ schema: finalSchema, timestamp: new Date().toISOString() });

  } catch (e) {
    console.error('DSI Error:', e);
    res.status(500).json({ error: 'Internal processing failed.' });
  }
});

// --- SERVE REACT ADMIN APP ---

app.use(express.static(path.join(__dirname, 'dist')));

app.get('*', async (req, res) => {
  const indexPath = path.join(__dirname, 'dist', 'index.html');
  const fs = require('fs');

  if (fs.existsSync(indexPath)) {
    let html = fs.readFileSync(indexPath, 'utf8');
    let authToken = '';

    // Mint Custom Token for Frontend
    try {
      if (admin.apps.length) {
        const uid = `shopify-admin-${APP_ID}`;
        authToken = await admin.auth().createCustomToken(uid, { role: 'admin' });
      }
    } catch (e) {
      console.error("Token Minting Error:", e.message);
    }

    // INJECTION
    const injection = `
      <script>
        window.__app_id = "${APP_ID}";
        window.__firebase_config = '${FIREBASE_CONFIG_PUBLIC}';
        window.__initial_auth_token = "${authToken}";
      </script>
    `;
    
    html = html.replace('</head>', `${injection}</head>`);
    res.send(html);
  } else {
    res.status(200).send(`
      <div style="font-family: sans-serif; padding: 2rem;">
        <h1>Syntaxial Engine Active</h1>
        <p>API is running. Frontend build (/dist) not found.</p>
        <p>Ensure <code>npm run build</code> ran successfully.</p>
      </div>
    `);
  }
});

app.listen(PORT, () => {
  console.log(`Syntaxial Engine running on port ${PORT}`);
});
