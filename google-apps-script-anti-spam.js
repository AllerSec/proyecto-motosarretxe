/**
 * Google Apps Script anti-spam para el formulario de contacto de motosarretxe.com
 *
 * INSTRUCCIONES:
 * 1. Abre https://script.google.com y entra en tu proyecto actual.
 * 2. Borra TODO el código existente.
 * 3. Pega este código completo.
 * 4. Guarda (Ctrl+S).
 * 5. Despliega: Implementar > Gestionar implementaciones > Editar (lápiz) > Nueva versión > Implementar.
 *    (Mantén la misma URL de implementación, NO crees una nueva — así no hay que cambiar el HTML.)
 *
 * Filtros server-side: honeypot, tiempo mínimo, keywords spam, alfabetos no-latinos,
 * dominios desechables, escape HTML para evitar inyección en el email.
 */

const SPAM_KEYWORDS = /\b(seo|ranking|backlink|campaign|crypto|bitcoin|investment|loan|viagra|casino|porn|escort|guaranteed?\s+(traffic|leads|sales|results)|first\s+page\s+of\s+google|24\s*hours?|targeted\s+visitors|grow\s+your\s+business|increase\s+your\s+sales)\b/i;

const NON_LATIN = /[Ѐ-ӿ֐-׿؀-ۿ一-鿿]/; // cirílico, hebreo, árabe, CJK

const DISPOSABLE_DOMAINS = [
  'jmailservice.com', 'mailinator.com', 'tempmail.com', 'guerrillamail.com',
  '10minutemail.com', 'throwaway.email', 'yopmail.com', 'sharklasers.com',
  'maildrop.cc', 'dispostable.com', 'trashmail.com', 'getairmail.com'
];

function escapeHtml(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function isSpam(data) {
  // 1. Honeypots rellenos = bot
  if (data.website && String(data.website).trim()) return 'honeypot:website';
  if (data.company && String(data.company).trim()) return 'honeypot:company';

  // 2. Falta el hp_check (el bot no envía el form completo)
  if (data.hp_check !== 'ok') return 'missing:hp_check';

  // 3. Tiempo mínimo (formulario enviado en <3s = bot)
  const ts = parseInt(data.ts, 10) || 0;
  if (ts > 0) {
    const elapsed = Date.now() - ts;
    if (elapsed < 3000) return 'too_fast:' + elapsed + 'ms';
    if (elapsed > 24 * 60 * 60 * 1000) return 'too_old'; // form de hace +1 día
  }

  // 4. Email válido y no desechable
  const email = String(data.email || '').toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'invalid_email';
  const domain = email.split('@')[1] || '';
  if (DISPOSABLE_DOMAINS.indexOf(domain) !== -1) return 'disposable_email';

  // 5. Mensaje + nombre: keywords spam o alfabetos no-latinos
  const blob = (data.mensaje || '') + ' ' + (data.nombre || '');
  if (SPAM_KEYWORDS.test(blob)) return 'spam_keyword';
  if (NON_LATIN.test(blob)) return 'non_latin_chars';

  // 6. URLs en el mensaje (señal típica de spam SEO)
  const msg = String(data.mensaje || '');
  const urlMatches = msg.match(/https?:\/\//gi) || [];
  if (urlMatches.length >= 2) return 'too_many_urls';

  // 7. Mensaje demasiado corto o demasiado largo
  if (msg.trim().length < 10) return 'message_too_short';
  if (msg.length > 5000) return 'message_too_long';

  // 8. Teléfono USA/internacional cuando el form es local (ES/FR)
  const phone = String(data.telefono || '');
  if (/^\+?1[\s\-]?\(?[2-9]\d{2}/.test(phone)) return 'us_phone';

  return null; // no es spam
}

function doPost(e) {
  try {
    const data = JSON.parse(e.postData.contents);

    // Filtro anti-spam
    const spamReason = isSpam(data);
    if (spamReason) {
      // Devolvemos "success" para no dar pistas al bot, pero NO enviamos email.
      // Opcional: log en una hoja de cálculo para auditoría.
      console.log('SPAM bloqueado: ' + spamReason + ' | email=' + (data.email || '?'));
      return ContentService
        .createTextOutput(JSON.stringify({ success: true, filtered: true }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Email legítimo: enviar con escape HTML
    MailApp.sendEmail({
      to: 'motosarretxe@gmail.com',
      subject: 'Nuevo mensaje WEB - Arretxe Motos',
      htmlBody: `
        <h2>Nuevo mensaje desde la web</h2>
        <p><b>Nombre:</b> ${escapeHtml(data.nombre)} ${escapeHtml(data.apellidos)}</p>
        <p><b>Email:</b> ${escapeHtml(data.email)}</p>
        <p><b>Teléfono:</b> ${escapeHtml(data.telefono || 'No indicado')}</p>
        <p><b>Mensaje:</b><br>${escapeHtml(data.mensaje || 'Sin mensaje').replace(/\n/g, '<br>')}</p>
      `
    });

    return ContentService
      .createTextOutput(JSON.stringify({ success: true }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    console.error('Error procesando POST: ' + err);
    return ContentService
      .createTextOutput(JSON.stringify({ success: false, error: String(err) }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}
