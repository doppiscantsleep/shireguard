import type { D1Database } from '@cloudflare/workers-types';

export async function logAudit(
  db: D1Database,
  opts: {
    userId: string;
    action: string;
    resourceType: string;
    resourceId?: string | null;
    detail?: string | null;
    ip?: string | null;
    networkId?: string | null;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO audit_log (user_id, action, resource_type, resource_id, detail, ip, network_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      opts.userId,
      opts.action,
      opts.resourceType,
      opts.resourceId ?? null,
      opts.detail ?? null,
      opts.ip ?? null,
      opts.networkId ?? null,
    )
    .run();
}
