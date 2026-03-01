import { Hono } from 'hono';
import type { Env } from '../types';
import { authMiddleware } from '../auth/middleware';
import { getUserTier, type Tier } from '../lib/tiers';
import { stripeRequest, verifyWebhookSignature } from '../lib/stripe';

const billing = new Hono<{ Bindings: Env }>();

// ── POST /checkout — create Stripe Checkout session ──
billing.post('/checkout', authMiddleware, async (c) => {
  const userId = c.get('userId') as string;
  const { plan } = await c.req.json<{ plan: string }>();

  if (plan !== 'solo' && plan !== 'team') {
    return c.json({ error: 'plan must be "solo" or "team"' }, 400);
  }

  const tier = await getUserTier(c.env.DB, userId);
  if (tier === 'comped') {
    return c.json({ error: 'Your account has a complimentary plan' }, 400);
  }
  if (tier === plan) {
    return c.json({ error: `You are already on the ${plan} plan` }, 400);
  }

  // Get user email for Stripe customer
  const user = await c.env.DB.prepare('SELECT email, stripe_customer_id FROM users WHERE id = ?')
    .bind(userId)
    .first<{ email: string; stripe_customer_id: string | null }>();

  if (!user) return c.json({ error: 'User not found' }, 404);

  // Find or create Stripe customer
  let customerId = user.stripe_customer_id;
  if (!customerId) {
    const customer = await stripeRequest(c.env.STRIPE_SECRET_KEY, 'POST', '/customers', {
      email: user.email,
      'metadata[user_id]': userId,
    });
    customerId = customer.id;
    await c.env.DB.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?')
      .bind(customerId, userId)
      .run();
  }

  const lookupKey = plan === 'solo' ? 'solo_monthly' : 'team_monthly';

  // Look up price by lookup_key
  const prices = await stripeRequest(
    c.env.STRIPE_SECRET_KEY,
    'GET',
    `/prices?lookup_keys[]=${lookupKey}&active=true&limit=1`,
  );

  if (!prices.data?.length) {
    return c.json({ error: 'Price not found — please contact support' }, 500);
  }

  const priceId = prices.data[0].id;

  const origin = new URL(c.req.url).origin;
  const session = await stripeRequest(c.env.STRIPE_SECRET_KEY, 'POST', '/checkout/sessions', {
    customer: customerId!,
    mode: 'subscription',
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    'subscription_data[metadata][user_id]': userId,
    'subscription_data[metadata][plan]': plan,
    success_url: `${origin}/dashboard#billing`,
    cancel_url: `${origin}/dashboard#billing`,
  });

  return c.json({ url: session.url });
});

// ── POST /portal — create Stripe Customer Portal session ──
billing.post('/portal', authMiddleware, async (c) => {
  const userId = c.get('userId') as string;

  const user = await c.env.DB.prepare('SELECT stripe_customer_id FROM users WHERE id = ?')
    .bind(userId)
    .first<{ stripe_customer_id: string | null }>();

  if (!user?.stripe_customer_id) {
    return c.json({ error: 'No billing account found' }, 400);
  }

  const origin = new URL(c.req.url).origin;
  const session = await stripeRequest(c.env.STRIPE_SECRET_KEY, 'POST', '/billing_portal/sessions', {
    customer: user.stripe_customer_id,
    return_url: `${origin}/dashboard#billing`,
  });

  return c.json({ url: session.url });
});

// ── GET /status — billing status for dashboard ──
billing.get('/status', authMiddleware, async (c) => {
  const userId = c.get('userId') as string;

  const user = await c.env.DB.prepare(
    'SELECT tier, stripe_customer_id, stripe_subscription_id FROM users WHERE id = ?',
  )
    .bind(userId)
    .first<{ tier: string; stripe_customer_id: string | null; stripe_subscription_id: string | null }>();

  if (!user) return c.json({ error: 'User not found' }, 404);

  return c.json({
    tier: user.tier || 'free',
    has_subscription: !!user.stripe_subscription_id,
    has_billing_account: !!user.stripe_customer_id,
  });
});

// ── POST /webhook — Stripe webhook handler (no auth middleware) ──
billing.post('/webhook', async (c) => {
  const sigHeader = c.req.header('stripe-signature');
  if (!sigHeader) return c.json({ error: 'Missing signature' }, 400);

  const payload = await c.req.text();

  let event: any;
  try {
    event = await verifyWebhookSignature(payload, sigHeader, c.env.STRIPE_WEBHOOK_SECRET);
  } catch (err: any) {
    console.error('[stripe webhook] signature verification failed:', err.message);
    return c.json({ error: 'Invalid signature' }, 400);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed':
        await handleCheckoutCompleted(c.env.DB, event.data.object);
        break;
      case 'customer.subscription.updated':
        await handleSubscriptionUpdated(c.env.DB, event.data.object);
        break;
      case 'customer.subscription.deleted':
        await handleSubscriptionDeleted(c.env.DB, event.data.object);
        break;
      case 'invoice.payment_failed':
        await handlePaymentFailed(c.env.DB, event.data.object);
        break;
    }
  } catch (err: any) {
    console.error(`[stripe webhook] error handling ${event.type}:`, err.message);
  }

  // Always return 200 so Stripe doesn't retry
  return c.json({ received: true });
});

// ── Webhook event handlers (all idempotent) ──

async function handleCheckoutCompleted(db: D1Database, session: any) {
  const userId = session.metadata?.user_id || session.subscription_data?.metadata?.user_id;
  const subscriptionId = session.subscription;
  if (!subscriptionId) return;

  // Fetch subscription to get plan from metadata
  // The metadata is on the subscription, not the session
  let plan: Tier | undefined;

  // First try session metadata
  if (session.metadata?.plan) {
    plan = session.metadata.plan as Tier;
  }

  // If not on session, it's on the subscription (set via subscription_data[metadata])
  if (!plan && userId) {
    // We set it via subscription_data[metadata][plan], so it should be on the subscription
    // But at checkout.session.completed time, we can read from session.metadata too
    // Fall back to looking at the subscription object if needed
    plan = 'solo'; // safe default; will be corrected by subscription.updated event
  }

  if (!userId) return;

  await db.prepare(
    'UPDATE users SET tier = ?, stripe_subscription_id = ? WHERE id = ? AND tier != ?',
  )
    .bind(plan, subscriptionId, userId, 'comped')
    .run();
}

async function handleSubscriptionUpdated(db: D1Database, subscription: any) {
  const userId = subscription.metadata?.user_id;
  if (!userId) return;

  const status = subscription.status;
  const plan = subscription.metadata?.plan as Tier | undefined;

  if (status === 'active' && plan) {
    // Ensure tier matches subscription
    await db.prepare('UPDATE users SET tier = ?, stripe_subscription_id = ? WHERE id = ? AND tier != ?')
      .bind(plan, subscription.id, userId, 'comped')
      .run();
  } else if (status === 'past_due' || status === 'unpaid') {
    // Downgrade to free
    await db.prepare(
      "UPDATE users SET tier = 'free' WHERE id = ? AND tier NOT IN ('comped')",
    )
      .bind(userId)
      .run();
  }
}

async function handleSubscriptionDeleted(db: D1Database, subscription: any) {
  const userId = subscription.metadata?.user_id;
  if (!userId) return;

  await db.prepare(
    "UPDATE users SET tier = 'free', stripe_subscription_id = NULL WHERE id = ? AND tier != ?",
  )
    .bind(userId, 'comped')
    .run();
}

async function handlePaymentFailed(db: D1Database, invoice: any) {
  const customerId = invoice.customer;
  if (!customerId) return;

  await db.prepare(
    "UPDATE users SET tier = 'free' WHERE stripe_customer_id = ? AND tier NOT IN ('comped')",
  )
    .bind(customerId)
    .run();
}

export { billing };
