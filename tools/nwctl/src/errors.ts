export class CliError extends Error {
  constructor(
    public code: string,
    message: string,
    public exitCode: number,
    public status?: number,
  ) {
    super(message);
  }
}
export const invalid = (message: string): never => {
  throw new CliError("INVALID_ARGUMENT", message, 2);
};
export const incompatible = (): never => {
  throw new CliError(
    "CONTRACT_MISMATCH",
    "Server response is incompatible with nwctl.",
    6,
  );
};
