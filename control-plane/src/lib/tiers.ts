export type Tier = 'free' | 'solo' | 'team';

export const TIER_LIMITS: Record<Tier, { devices: number; networks: number; members: number }> = {
  free: { devices: 5,        networks: 1, members: 5 },
  solo: { devices: 10,       networks: 3, members: Infinity },
  team: { devices: 10,       networks: 5, members: Infinity },
};

export async function getUserTier(db: D1Database, userId: string): Promise<Tier> {
  const row = await db
    .prepare('SELECT tier FROM users WHERE id = ?')
    .bind(userId)
    .first<{ tier: string }>();
  const t = row?.tier ?? 'free';
  return (t === 'solo' || t === 'team') ? t : 'free';
}
