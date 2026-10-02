// In-memory object identity, never a JSON/header flag or reusable bearer grant.
const approvals = new WeakMap<Request, { userId: string; action: string }>();
export function isApprovedOperation(
  request: Request,
  userId: string,
  action: string,
): boolean {
  const proof = approvals.get(request);
  return proof?.userId === userId && proof.action === action;
}
export async function runApprovedOperation(
  request: Request,
  userId: string,
  action: string,
  run: () => Promise<Response>,
): Promise<Response> {
  approvals.set(request, { userId, action });
  try {
    return await run();
  } finally {
    approvals.delete(request);
  }
}
