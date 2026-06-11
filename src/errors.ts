export class GlassBondError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GlassBondError";
  }
}

export class ConfigurationError extends GlassBondError {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}
