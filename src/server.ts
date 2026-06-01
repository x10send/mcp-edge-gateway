import { buildApp } from "./app.js";
import { buildAdminApp } from "./admin-app.js";
import { initBootstrap } from "./admin-auth.js";
import { ConfigService } from "./config-service.js";
import { StateStore } from "./state.js";

const configPath = process.env.GATEWAY_CONFIG ?? "/config/gateway.yaml";
const statePath = process.env.GATEWAY_STATE_DIR ?? "/config/state";

let configService: ConfigService;
try {
  configService = new ConfigService(configPath);
} catch (error) {
  console.error("Failed to load configuration:", error);
  process.exit(1);
}

const stateStore = new StateStore(statePath);
try {
  stateStore.open();
} catch (error) {
  console.error("Failed to initialize state store:", error);
  process.exit(1);
}

const config = configService.config;
const app = buildApp(config);

// Admin listener
let adminApp: ReturnType<typeof buildAdminApp> | undefined;
if (config.admin.enabled) {
  adminApp = buildAdminApp({
    db: stateStore.database,
    config,
    configPath,
    onConfigSaved: () => {
      try {
        configService.reload();
        app.log.info("configuration reloaded");
      } catch (error) {
        app.log.error(
          { error },
          "configuration reload failed — restart required",
        );
      }
    },
  });

  const bootstrapResult = initBootstrap(stateStore.database);
  if (bootstrapResult.plaintext) {
    console.log("==========================================================");
    console.log("ADMIN BOOTSTRAP CREDENTIAL (one-time use, shown once):");
    console.log(bootstrapResult.plaintext);
    console.log(
      "Navigate to http://<host>:8789/admin/setup to complete setup.",
    );
    console.log("==========================================================");
  }
}

async function shutdown(signal: string): Promise<void> {
  app.log.info({ signal }, "shutting down");
  await app.close();
  if (adminApp) {
    await adminApp.close();
  }
  stateStore.close();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

try {
  await app.listen({ host: config.server.host, port: config.server.port });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}

if (adminApp) {
  try {
    await adminApp.listen({
      host: config.admin.host,
      port: config.admin.port,
    });
  } catch (error) {
    app.log.error(error, "admin listener failed to start");
    process.exit(1);
  }
}
