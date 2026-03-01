export type Tier = 'free' | 'solo' | 'team' | 'comped';

export const TIER_LIMITS: Record<Tier, { devices: number; networks: number; members: number }> = {
  free:   { devices: 3,        networks: 1,        members: 0 },
  solo:   { devices: 10,       networks: 3,        members: 3 },
  team:   { devices: 10,       networks: 5,        members: Infinity },
  comped: { devices: 50,       networks: Infinity, members: Infinity },
};

const VALID_TIERS: readonly Tier[] = ['free', 'solo', 'team', 'comped'];

export async function getUserTier(db: D1Database, userId: string): Promise<Tier> {
  const row = await db
    .prepare('SELECT tier FROM users WHERE id = ?')
    .bind(userId)
    .first<{ tier: string }>();
  const t = row?.tier ?? 'free';
  return (VALID_TIERS as readonly string[]).includes(t) ? t as Tier : 'free';
}
