import express from 'express';
import http from 'http';
import https from 'https';
import crypto from 'crypto';
import fs from 'fs';
import { config } from 'dotenv';
import { execSync } from 'child_process';

const app = express();

let isUsingHTTPS = true;

type CustomRequest = express.Request & {
	rawBody: string;
};

function hasRawBody(request: express.Request): request is CustomRequest {
	return (request as CustomRequest).rawBody !== undefined;
}

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
	verify: (req, _, buf, encoding: BufferEncoding) => {
		if (buf && buf.length) {
			(req as CustomRequest).rawBody = buf.toString(encoding || 'utf8');
		}
	},
}));

app.use(express.static('src/public'));

function verifyPostData(req: express.Request, res: express.Response, next: express.NextFunction) {
	if (!(process.env.SECRET && process.env.SIG_HEADER_NAME && process.env.SIG_HASH_ALG)) {
		res.status(403);
		return next('Secret not defined');
	}

	if (!hasRawBody(req)) {
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

app.post('/update', verifyPostData, (_, res) => {
	try {
		execSync('git pull', { encoding: 'utf-8' });
		execSync('npm i --omit=dev');
		execSync('npm run build');
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
	res.send(`${timestamp}`);
});

const httpPort = process.env.HTTP_PORT;
const httpsPort = process.env.HTTPS_PORT;

try {
	const privateKeyPath = process.env.SSL_KEY;
	const publicKeyPath = process.env.SSL_CERT;
	if (!privateKeyPath || !publicKeyPath) throw new Error();
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
