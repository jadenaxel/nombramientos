const EXACT_STANDALONE_HOST = "127.0.0.1";
const EXACT_STANDALONE_PORT = "3000";

export function resolveStandaloneBinding(source = process.env) {
  const host = source.NOMBRAMIENTOS_WEB_HOST ?? EXACT_STANDALONE_HOST;
  const port = source.NOMBRAMIENTOS_WEB_PORT ?? EXACT_STANDALONE_PORT;
  if (host !== EXACT_STANDALONE_HOST || port !== EXACT_STANDALONE_PORT) {
    throw new Error("The standalone web runtime must bind exactly to 127.0.0.1:3000");
  }
  return { host: EXACT_STANDALONE_HOST, port: EXACT_STANDALONE_PORT };
}
