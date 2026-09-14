import { DatabaseRuntime, EncryptedFileSecretProvider } from "@nombramientos/database";
import { parseApiConfig } from "./config.js";
import { safeLogError } from "./lib/log-safety.js";
import { buildServer } from "./server.js";

async function main(): Promise<void> {
  const config = parseApiConfig();
  const secretProvider = new EncryptedFileSecretProvider(config.secretFile, config.secretMasterKey);
  const database = new DatabaseRuntime({
    control: {
      connectionString: config.controlDatabaseUrl,
      application_name: "nombramientos-api-control",
      max: 5,
      ssl: false,
    },
    secretProvider,
    tenantPoolMax: config.tenantPoolMax,
    tenantPoolIdleMs: config.tenantPoolIdleMs,
  });
  const app = await buildServer({ config, database });

  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, "Stopping API");
    await app.close();
    process.exitCode = 0;
  };
  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));

  try {
    await app.listen({ host: config.host, port: config.port });
  } catch (error) {
    app.log.fatal({ safeError: safeLogError(error) }, "API failed to start");
    await app.close();
    process.exitCode = 1;
  }
}

void main().catch((error: unknown) => {
  process.stderr.write(`API initialization failed: ${JSON.stringify(safeLogError(error))}\n`);
  process.exitCode = 1;
});
