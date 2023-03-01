const express = require('express');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const { config } = require('dotenv');
const { execSync } = require('child_process');

const app = express();

let isUsingHTTPS = true;

config();

app.use((req, res, next) => {
  if (req.protocol !== 'https' && isUsingHTTPS) {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  return next();
});

app.use((req, _, next) => {
  console.log(`${req.method} ${req.url} from ${req.ip}`);
  return next();
});

app.use(express.json({
  verify: (req, _, buf, encoding) => {
    if (buf && buf.length) {
      req.rawBody = buf.toString(encoding || 'utf8');
    }
  },
}));

app.use(express.static('public'));

function verifyPostData(req, res, next) {
  if (!(process.env.SECRET && process.env.SIG_HEADER_NAME && process.env.SIG_HASH_ALG)) {
    res.status(403);
    return next('Secret not defined');
  }

  if (!req.rawBody) {
    res.status(400);
    return next('Request body empty');
  }

  const sig = Buffer.from(req.get(process.env.SIG_HEADER_NAME) || '', 'utf8');
  const hmac = crypto.createHmac(process.env.SIG_HASH_ALG, process.env.SECRET);
  const digest = Buffer.from(
    `${process.env.SIG_HASH_ALG}=${hmac.update(req.rawBody).digest('hex')}`,
    'utf8'
  );
  if (sig.length !== digest.length || !crypto.timingSafeEqual(digest, sig)) {
    res.status(401);
    return next(`Request body digest did not match ${process.env.SIG_HASH_ALG} (${sig})`);
  }

  return next();
}

app.get('/', (req, res) => {
  res.send(`Welcome ${req.ip}`);
});

app.post('/update', verifyPostData, (_, res) => {
  try {
    execSync('git pull', { encoding: 'utf-8' });
    execSync('npm i --omit=dev');
    res.sendStatus(200);
    // NOTE: This will cause the server to shut down, run it with pm2 or
    // something similar to ensure it starts back up again.
    process.exit();
  } catch (err) {
    res.sendStatus(500);
    console.error(err);
  }
});

app.get('/heartbeat', (_, res) => {
  const timestamp = Date.now();
  res.send(`${timestamp}`)
});

const httpPort = process.env.HTTP_PORT;
const httpsPort = process.env.HTTPS_PORT;

try {
  const privateKeyPath = process.env.SSL_KEY;
  const publicKeyPath = process.env.SSL_CERT;
  const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
  const certificate = fs.readFileSync(publicKeyPath, 'utf8');
  const credentials = { key: privateKey, cert: certificate };
  const httpsServer = https.createServer(credentials, app);
  httpsServer.listen(httpsPort, () => {
    isUsingHTTPS = true;
    console.log(`HTTPS Server listening on port ${httpsPort}`);
  });
} catch (ex) {
  isUsingHTTPS = false;
  console.error('Certificates not found. Not using HTTPS');
  if (process.env.NODE_ENV === 'production') process.exit();
}

const httpServer = http.createServer(app);

httpServer.listen(httpPort, () => {
  console.log(`HTTP Server listening on port ${httpPort}`);
});
