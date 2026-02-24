import type { Env } from '../types';

export async function sendEmail(env: Env, opts: {
  to: string;
  subject: string;
  html: string;
  from?: string;
}): Promise<void> {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: opts.from ?? 'Shireguard <hello@shireguard.com>',
      to: [opts.to],
      subject: opts.subject,
      html: opts.html,
    }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Email send failed: ${err}`);
  }
}

export function inviteEmailHtml(opts: {
  inviterEmail: string;
  networkName: string;
  inviteUrl: string;
  role: string;
  expiresHours: number;
}): string {
  const expiresDays = opts.expiresHours >= 24
    ? `${Math.round(opts.expiresHours / 24)} days`
    : `${opts.expiresHours} hours`;

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
</head>
<body style="margin:0;padding:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="540" cellpadding="0" cellspacing="0" style="background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;">
          <tr>
            <td style="padding:32px 40px 24px;border-bottom:1px solid #21262d;">
              <span style="font-size:20px;font-weight:700;color:#e6edf3;letter-spacing:-0.5px;">Shireguard</span>
            </td>
          </tr>
          <tr>
            <td style="padding:32px 40px;">
              <h1 style="margin:0 0 16px;font-size:24px;font-weight:600;color:#e6edf3;line-height:1.3;">
                You're invited to join a network
              </h1>
              <p style="margin:0 0 24px;font-size:15px;color:#8b949e;line-height:1.6;">
                <strong style="color:#c9d1d9;">${opts.inviterEmail}</strong> has invited you to join
                <strong style="color:#c9d1d9;">${opts.networkName}</strong> on Shireguard as a
                <strong style="color:#c9d1d9;">${opts.role}</strong>.
              </p>
              <table cellpadding="0" cellspacing="0" style="margin:0 0 24px;">
                <tr>
                  <td style="background:#2563eb;border-radius:8px;">
                    <a href="${opts.inviteUrl}" style="display:inline-block;padding:12px 28px;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;">
                      Accept Invite
                    </a>
                  </td>
                </tr>
              </table>
              <p style="margin:0 0 8px;font-size:13px;color:#6e7681;">
                Or copy this link into your browser:
              </p>
              <p style="margin:0 0 24px;font-size:13px;color:#58a6ff;word-break:break-all;">
                ${opts.inviteUrl}
              </p>
              <p style="margin:0;font-size:13px;color:#6e7681;">
                This invite expires in ${expiresDays}. If you weren't expecting this, you can safely ignore it.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:20px 40px;border-top:1px solid #21262d;">
              <p style="margin:0;font-size:12px;color:#6e7681;">
                Shireguard · Zero-config WireGuard networking
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}
