import express from 'express';
import { loadConfig } from './config.js';
import {
  cors,
  createLogger,
  csrf,
  errorHandler,
  nonce,
  requestLog,
  securityHeaders,
  session,
} from './middleware.js';
import { createRoutes } from './routes.js';
import { createHtml, createViews } from './views.js';

const { profile, instance, port } = loadConfig();
const log = createLogger(instance);
const views = createViews(createHtml(profile.escapeHtml), instance);

const app = express();
if (profile.hidePoweredBy) app.disable('x-powered-by');

// Order matters - see README "Middleware order".
app.use(requestLog(profile, log)); //            1. log every request
app.use(nonce); //                                2. per-request CSP nonce
app.use(securityHeaders(profile)); //             3. CSP, framing, static headers
app.use(cors(profile, log)); //                   4. CORS decision (+ preflight)
app.use('/static', express.static('public')); //     static files (still get the headers above)
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));
app.use(session(profile)); //                     5. who is this?
app.use(csrf(profile, log)); //                   6. anti-CSRF on POST
app.use(createRoutes(profile, views, log)); //    7. routes
app.use(errorHandler(profile, log)); //           8. errors

app.listen(port, '0.0.0.0', () => {
  log(`listening on :${port} with profile "${profile.name}"`);
});
