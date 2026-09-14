export class ApiError extends Error {
  public constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function unauthorized(message = "Authentication is required"): ApiError {
  return new ApiError(401, "AUTHENTICATION_REQUIRED", message);
}

export function forbidden(permission?: string): ApiError {
  return new ApiError(403, "PERMISSION_DENIED", "The operation is not permitted", permission ? { permission } : undefined);
}
