const EXACT_STANDALONE_HOST = "127.0.0.1";
const EXACT_STANDALONE_PORT = "3000";
const GESTIONCHURCH_MODULE_PORT = "3300";

export function resolveStandaloneBinding(source = process.env) {
  const host = source.NOMBRAMIENTOS_WEB_HOST ?? EXACT_STANDALONE_HOST;
  const integrated = source.GESTIONCHURCH_MODULE_MODE === "true";
  const expectedPort = integrated ? GESTIONCHURCH_MODULE_PORT : EXACT_STANDALONE_PORT;
  const port = source.NOMBRAMIENTOS_WEB_PORT ?? expectedPort;
  if (host !== EXACT_STANDALONE_HOST || port !== expectedPort) {
    throw new Error(`The standalone web runtime must bind exactly to 127.0.0.1:${expectedPort}`);
  }
  return { host: EXACT_STANDALONE_HOST, port: expectedPort };
}
