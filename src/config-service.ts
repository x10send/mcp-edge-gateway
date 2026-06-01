import { loadConfig, type GatewayConfig } from "./config.js";

export class ConfigService {
  private current: GatewayConfig;

  constructor(private readonly configPath: string) {
    this.current = loadConfig(configPath);
  }

  get config(): GatewayConfig {
    return this.current;
  }

  // Reloads the config from disk, validating it before replacing the current
  // config. Throws if the new config is invalid, leaving the current config
  // unchanged.
  reload(): void {
    this.current = loadConfig(this.configPath);
  }
}
