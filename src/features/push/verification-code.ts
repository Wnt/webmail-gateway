import { htmlToTextRead, type EmailBody } from "./summary-text.js";

/**
 * Finds the one-time code in a sign-in or confirmation mail ("Your
 * verification code is 177945", "HUK6QR ist Ihr Bestätigungscode"), so the
 * native app's notification can offer it for copying
 * (design/ios-native-app.md, "The code").
 *
 * A port of Bulwark's `lib/verification-code.ts` (bulwarkmail/webmail fork,
 * AGPL-3.0): the rules below are the same, character for character, so the
 * webmail's list chip and the phone's notification agree. The shared
 * synthetic cases are `test/fixtures/verification-code-cases.json`. Only the
 * Bulwark-typed `Email` helpers are left out; `verificationCodeBodyTexts`
 * is the gateway's own body reader.
 *
 * A token only counts when it looks like a code and sits near a word that
 * names one (code, Bestätigungscode, Passcode, PIN, OTP, ...). Mail is full
 * of numbers — dates, prices, postcodes, order and phone numbers — and a
 * wrong chip is worse than none, so anything doubtful is left out.
 */

// A code this far after its keyword ("Der Bestätigungscode ist unten
// aufgeführt. Bitte geben Sie ihn ... ein. 37CCHC") still counts, one this far
// before it ("548980 ist Ihr Bestätigungscode") too.
const MAX_AFTER = 120;
const MAX_BEFORE = 60;

// Words that end in a code keyword but name something else: "Gutscheincode",
// "Postcode", "Barcode", and the word before a bare "code" ("promo code",
// "Claude Code", "VS Code").
const NOT_A_CODE_PREFIXES = new Set([
  'en', 'de', 'uni', 'x', 'vs', 'op', 'byte', 'bar', 'post', 'zip', 'qr', 'geo', 'short', 'pseudo',
  'hash', 'leet', 'trans', 're', 'source', 'quell', 'programm', 'program', 'status', 'error',
  'fehler', 'dress', 'color', 'colour', 'farb', 'html', 'css', 'embed', 'tracking', 'sendungs',
  'referral', 'empfehlungs', 'sort', 'swift', 'tax', 'ean', 'produkt', 'product', 'artikel',
  'promo', 'coupon', 'discount', 'voucher', 'gift', 'gutschein', 'rabatt', 'aktions', 'geschenk',
  'bonus', 'vorteils', 'area', 'country', 'länder', 'laender', 'landes', 'claude', 'studio',
]);

// Word endings that name a code, across the languages the app ships.
// "bestätigungscode", "verificatiecode", "engangskode", "vahvistuskoodi(si)",
// "verifieringskod", "ellenőrzőkód", "код", ...
const CODE_WORD_ENDINGS = [
  'code', 'codes', 'codice', 'codici', 'código', 'códigos', 'codigo', 'codigos', 'cod', 'kod',
  'kodu', 'kodem', 'kodunuz', 'kód', 'kódot', 'kódu', 'kode', 'koden', 'koodi', 'koodia', 'koodisi', 'koodiasi', 'koodinne', 'koodianne', 'kood',
  'kods', 'kodas', 'код', 'кода', 'коду', 'кодом', 'κωδικός', 'κωδικό', 'קוד', 'رمز', 'کد',
];

const CODE_WORDS_EXACT = new Set(['passcode', 'einmalkennwort', 'einmalpasswort']);

// Only ever written in capitals when they mean a code; "pin" and "tan" are
// ordinary words too.
const UPPERCASE_CODE_WORDS = /^(?:PIN|OTP|(?:m|sms|push|chip|photo|i|e)?TAN)$/;

// Scripts without spaces between words, matched as substrings.
const CJK_CODE_WORDS = /コード|認証番号|確認番号|验证码|驗證碼|校验码|动态码|인증\s?번호|인증\s?코드|코드/g;

const ONE_TIME_PASSWORD = /\b(?:one[- ]time|single[- ]use|temporary) pass(?:word|code)\b/gi;

const WORD = /[\p{L}\p{M}]+(?:-[\p{L}\p{M}]+)*/gu;

// "with code 250 (2.1.5)" in a delivery report: a code word followed by a
// number too short to be a one-time code names a status or error code.
const LABELS_SHORT_NUMBER = /^\s*[:=]?\s*\d{1,3}(?![\p{L}\p{N}]|[.,]\d|[ -]\d)/u;

function isCodeWordPart(part: string, previous: string | undefined): boolean {
  if (UPPERCASE_CODE_WORDS.test(part)) return true;
  const lower = part.toLowerCase();
  if (CODE_WORDS_EXACT.has(lower)) return true;
  for (const ending of CODE_WORD_ENDINGS) {
    if (!lower.endsWith(ending)) continue;
    const prefix = lower.slice(0, lower.length - ending.length);
    // A bare "code" takes its meaning from the word before it.
    const qualifier = prefix || previous?.toLowerCase();
    return !qualifier || !NOT_A_CODE_PREFIXES.has(qualifier);
  }
  return false;
}

interface Span { start: number; end: number }

/** The code words of `text`, as three lists (words, CJK words, "one-time
 *  password" phrases). Within a list the spans are disjoint and in order, so
 *  a candidate looks up only the ones near it (`nearbyKeywords`). */
function findCodeWords(text: string): Span[][] {
  const words: Span[] = [];
  let previousWord: string | undefined;
  for (const match of text.matchAll(WORD)) {
    const start = match.index!;
    const end = start + match[0].length;
    const parts = match[0].split('-');
    const hit = parts.some((part, i) => isCodeWordPart(part, i > 0 ? parts[i - 1] : previousWord));
    const next = text.slice(end, end + 12);
    // "Code of Conduct", "code of practice"
    if (hit && !/^\s+of\s/i.test(next) && !LABELS_SHORT_NUMBER.test(next)) words.push({ start, end });
    previousWord = parts[parts.length - 1];
  }
  const lists = [words];
  for (const re of [CJK_CODE_WORDS, ONE_TIME_PASSWORD]) {
    lists.push([...text.matchAll(re)].map((match) => ({ start: match.index!, end: match.index! + match[0].length })));
  }
  return lists;
}

/** Work counters (tests check the detector stays linear by counting, not timing). */
export const detectorWork = { keywordSteps: 0 };

/**
 * Where each keyword list's lookups start: a candidate pass (one regex over
 * the text) finds its candidates in text order, so the keywords that end too
 * far before one also end too far before every later one. Each list's
 * cursor only moves forward, so a pass skips every keyword at most once.
 */
type Cursors = number[];

/** The keywords of one list that can matter for a candidate at start..end:
 *  those ending at most MAX_AFTER before it or starting at most MAX_BEFORE
 *  after it (or overlapping it). The cursor moves past the ones ending too
 *  early for good; the ones looked at are at most a window's worth (spans in
 *  a list do not overlap). Linear in the text over a whole pass. */
function* nearbyKeywords(list: Span[], cursors: Cursors, which: number, start: number, end: number): Generator<Span> {
  let i = cursors[which]!;
  while (i < list.length && list[i]!.end < start - MAX_AFTER) {
    i++;
    detectorWork.keywordSteps++;
  }
  cursors[which] = i;
  for (; i < list.length && list[i]!.start <= end + MAX_BEFORE; i++) {
    detectorWork.keywordSteps++;
    yield list[i]!;
  }
}

// Tried in this order at each position, so "557 260" and "6ZA-BRE" are taken
// whole before their pieces are.
const CANDIDATE = new RegExp(
  [
    // 6ZA-BRE, NJF63-SW7S7, and 2025-12-12 (dropped later)
    String.raw`(?<![\p{L}\p{N}])[A-Za-z0-9]{2,8}(?:-[A-Za-z0-9]{2,8}){1,3}(?![\p{L}\p{N}])`,
    // 557 260, 123-456
    String.raw`(?<!\d)\d{3,4}[ -]\d{3,4}(?!\d)`,
    // 3 0 4 6 2 7
    String.raw`(?<![\p{L}\p{N}])\d(?: \d){3,9}(?![\p{L}\p{N}])`,
    // 37CCHC, 5aem5f5z, 177945
    String.raw`(?<![\p{L}\p{N}])[A-Za-z0-9]{4,10}(?![\p{L}\p{N}])`,
  ].join('|'),
  'gu',
);

// Digits run into the words around them, which the pass above takes as one
// token: "ein:86771674Teile", "Claude.ai177945Copy", "732888Gib".
const GLUED_DIGITS = /(?<=\p{L})\d{4,10}(?!\d)|(?<!\d)\d{4,10}(?=\p{L})/gu;

const ALNUM = /[\p{L}\p{N}]/u;
// Glued digits are part of a word; a run longer than this either way is an
// id or a hash, not a word (and the walk stays bounded).
const MAX_GLUED_WALK = 64;

/** Whether the digits at start..end have only letters around them, as in
 *  "ai177945Copy", and are not one group of an id like "4887a30a5a2si2098"
 *  or "PAXPR03MB8065". */
function gluedToWords(text: string, start: number, end: number): boolean {
  let from = start;
  let to = end;
  while (from > 0 && ALNUM.test(text.charAt(from - 1))) {
    if (start - from >= MAX_GLUED_WALK) return false;
    from--;
  }
  while (to < text.length && ALNUM.test(text.charAt(to))) {
    if (to - end >= MAX_GLUED_WALK) return false;
    to++;
  }
  return /^\p{L}*\d+\p{L}*$/u.test(text.slice(from, to));
}

const YEAR = /^(?:19|20)\d\d$/;
// 10min, 600px, 100GB
const NUMBER_WITH_UNIT = /^\d+[a-z]{1,3}$/i;
// THANKS10, HERBST25, FALL2026
const PROMO_CODE = /^[A-Z]{4,}\d{1,4}$/;
const PROMO_WORDS = /%|(?<!\p{L})(?:off|rabatt|spar\p{L}*|save|discount|coupon|gutschein\p{L}*|voucher|sale|angebot\p{L}*)(?!\p{L})/iu;
// A number labelled as something else: "Kundennummer: 5512345", "Meeting-ID:
// 845 1234 5678", "at line 1042", "card ending in 4821". Nouns that also
// label codes ("Code für dein Konto: 123456") count only without a colon.
const LABELLED_AS_OTHER = new RegExp(
  String.raw`(?:(?:\p{L}*(?:nummer|number)|(?<!\p{L})(?:nr|no|id|line|zeile|version|tel|telefon|phone|fax|mobil|plz))\.?:?` +
  String.raw`|(?<!\p{L})(?:order|bestellung|account|konto|invoice|rechnung|ticket|case|page|seite|room|zimmer|commit|issue|pr|build|run|job|step|port)` +
  String.raw`|ending in|endet auf|endend auf|ends with)[ #]*$`,
  'iu',
);
const LOWERCASE_HEX = /^[0-9a-f-]+$/;
// "The code is: 123456", "Ihr Code lautet 123456"
const LINKED_BY = /(?::|=|(?<!\p{L})(?:is|lautet|ist|est|es|è|é|är|er|jest|je))\s*$/iu;

const LETTER = /\p{L}/u;
// How far after a candidate promotion words disqualify it.
const PROMO_AFTER = 40;

/** Text around a candidate, not starting or ending inside a word, so that
 *  "off" cut from "offiziellen" does not read as a word of its own. */
function contextWindow(text: string, from: number, to: number): string {
  let start = Math.max(0, from);
  let end = Math.min(text.length, to);
  while (start > 0 && start < end && LETTER.test(text.charAt(start - 1)) && LETTER.test(text.charAt(start))) start++;
  while (end < text.length && end > start && LETTER.test(text.charAt(end)) && LETTER.test(text.charAt(end - 1))) end--;
  return text.slice(start, end);
}

interface Candidate extends Span {
  code: string;
  score: number;
  /** Presented as the code: "code is X" (or "code: X"), or on a line of its own. */
  strong: boolean;
}

function scoreCandidate(text: string, raw: string, start: number, keywords: Span[][], cursors: Cursors): Candidate | null {
  const end = start + raw.length;
  const letters = raw.replace(/[^A-Za-z]/g, '');
  const digits = raw.replace(/\D/g, '');
  const before = contextWindow(text, start - 40, start);
  const after = text.slice(end, end + 8);

  if (!digits) return null;
  if (letters && letters !== letters.toUpperCase() && letters !== letters.toLowerCase()) return null;

  let code = raw;
  if (!letters) {
    // Grouped digits are typed without the gaps: "557 260" is 557260.
    code = digits;
    if (raw.includes('-') && !/^\d{3,4}-\d{3,4}$/.test(raw)) return null; // dates, phone numbers
    if (digits.length < 4 || digits.length > 10) return null;
    // Part of a date, time, decimal or longer number: 12.12.2025, 10:49:27, 1.299,00
    if (/\d[.,:/-]$/.test(before) || /^[.,:/-]\d/.test(after)) return null;
    // Issue and ticket numbers, phone numbers, the next group of an IBAN
    if (/[#+]$/.test(before) || /(?:\d|\))[ /-]?$/.test(before) || /^[ /-]?\d/.test(after)) return null;
    // Amounts
    if (/[€$£]\s?$/.test(before) || /^\s?(?:[€$£%]|eur\b|usd\b|chf\b)/i.test(after)) return null;
  } else if (NUMBER_WITH_UNIT.test(raw) || PROMO_CODE.test(raw)) {
    return null;
  }
  if (LABELLED_AS_OTHER.test(before)) return null;
  if (PROMO_WORDS.test(contextWindow(text, start - 60, end + PROMO_AFTER))) return null;

  let best = Infinity;
  let bestAfter = Infinity;
  for (const [which, list] of keywords.entries()) {
    for (const kw of nearbyKeywords(list, cursors, which, start, end)) {
      if (kw.start < end && kw.end > start) return null; // the candidate is part of a keyword ("2FA-Code")
      if (kw.end <= start && start - kw.end <= MAX_AFTER) {
        bestAfter = Math.min(bestAfter, start - kw.end);
        best = Math.min(best, start - kw.end);
      }
      if (kw.start >= end && kw.start - end <= MAX_BEFORE) best = Math.min(best, (kw.start - end) * 1.5);
    }
  }
  if (best === Infinity) return null;

  // Lowercase letters also make up words, hashes and ids, so they have to
  // follow their keyword closely ("confirmation code is 5aem5f5z"), and a
  // lowercase hex string (a commit, a colour, a token) only counts when the
  // keyword labels it directly ("den Code e382e507-1593-47f8").
  if (letters && letters === letters.toLowerCase()) {
    if (bestAfter > 40) return null;
    if (LOWERCASE_HEX.test(raw) && bestAfter > 2) return null;
  }

  const linked = LINKED_BY.test(before);
  const ownLine = /(?:^|\n)\s*$/.test(before) && /^\s*(?:\n|$)/.test(after);
  // "KI Palooza 2026": a year is only the code when it is presented as one.
  if (!letters && YEAR.test(digits) && !linked && !ownLine) return null;

  let score = best;
  if (linked) score -= 15;
  if (ownLine) score -= 15;
  return { start, end, code, score, strong: linked || ownLine };
}

const WORD_CHAR_OR_HYPHEN = /^[\p{L}\p{N}-]$/u;
const SPACE = /\s/;

/** Without a trailing "..." or "…" and the word right before it (by hand:
 *  an unanchored regex would rescan a long word from every position). */
function withoutCutWord(text: string): string {
  let end = text.length;
  while (end > 0 && SPACE.test(text.charAt(end - 1))) end--;
  let start: number;
  if (text.endsWith('...', end)) start = end - 3;
  else if (text.endsWith('…', end)) start = end - 1;
  else return text;
  while (start > 0) {
    const low = text.charCodeAt(start - 1);
    const pair = low >= 0xdc00 && low <= 0xdfff && start >= 2 && text.charCodeAt(start - 2) >= 0xd800 && text.charCodeAt(start - 2) <= 0xdbff;
    const size = pair ? 2 : 1;
    if (!WORD_CHAR_OR_HYPHEN.test(text.slice(start - size, start))) break;
    start -= size;
  }
  return text.slice(0, start);
}

// A preview is cut off with "...", and the word it cut may be half a code.
function normalize(text: string): string {
  return withoutCutWord(flatten(text)).trim();
}

function flatten(text: string): string {
  return text
    // Invisible spacers senders put between characters
    .replace(/[\u00ad\u200b-\u200f\u2060\ufeff]|\u034f/g, '')
    // Links and addresses carry ids and tokens, never the code to type
    .replace(/https?:\/\/\S+|www\.\S+/gi, ' ')
    // (each whitespace-delimited token once: what /\S*@\S+/ removed, without its rescans)
    .replace(/\S+/g, (token) => (/@\S/.test(token) ? ' ' : token))
    // Keep line breaks (a code often stands on a line of its own) but not
    // the runs of blank lines and indentation between table cells.
    .replace(/[^\S\n]+/g, ' ')
    .replace(/ ?\n[\s]*/g, '\n');
}

// A text that was cut (at a cap here, or by whoever produced it) may have been
// cut through a code, or through the text after it that decides whether it is
// one. A candidate is offered only when the whole text could not have read it
// otherwise, i.e. it ends at least PROMO_AFTER (40) visible characters before
// the cut:
// - any character after the cut could be a "%" or a promotion word inside the
//   40-character window scoreCandidate reads after a candidate, so that window
//   is the bound (it cannot be narrower and stay exact);
// - it covers everything shorter: a code's possible continuation (at most 33
//   characters more: hyphen groups up to "AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD",
//   35 in all, spaced digits up to 19) and the next-group, date and amount
//   checks (8 characters after it);
// - digits glued into a word that reaches the cut never get here: the word the
//   cut went through is dropped, and with it the digits in it.
// So a code never comes back as a fragment of itself, nor as one the whole text
// would refuse.

/**
 * The text a cut input is read as, where each of its positions is in the
 * flattened input (`lead`), and where the visible text ends there (before
 * the closing ellipsis: ours, or the sender's). The text then ends with
 * " …", so nothing reads the cut as the end of a line.
 */
function readCut(rawText: string): { text: string; lead: number; visibleEnd: number } {
  const flat = flatten(rawText);
  const kept = withoutCutWord(flat);
  const lead = kept.length - kept.trimStart().length;
  const text = kept.trim();
  let visibleEnd = flat.length;
  while (visibleEnd > 0 && SPACE.test(flat.charAt(visibleEnd - 1))) visibleEnd--;
  if (flat.endsWith('...', visibleEnd)) visibleEnd -= 3;
  else if (flat.endsWith('…', visibleEnd)) visibleEnd -= 1;
  return { text: text ? `${text} …` : '', lead, visibleEnd };
}

// In a body, two different codes about as plausible as each other (scores
// within this; a score is roughly the distance to the code word, minus 15 for
// "is:" and 15 for a line of its own) give no code: a wrong one is worse.
const DISAGREE_MARGIN = 10;

function bestCandidate(rawText: string, cut = false, unique = false): Candidate | null {
  const read = cut ? readCut(rawText) : { text: normalize(rawText), lead: 0, visibleEnd: Infinity };
  const text = read.text;
  if (!text) return null;
  const keywords = findCodeWords(text);
  if (!keywords.some((list) => list.length)) return null;

  let best: Candidate | null = null;
  const byCode = new Map<string, number>();
  for (const re of [CANDIDATE, GLUED_DIGITS]) {
    const cursors: Cursors = keywords.map(() => 0); // each pass finds its candidates in text order
    for (const match of text.matchAll(re)) {
      if (read.visibleEnd - (match.index! + match[0].length + read.lead) < PROMO_AFTER) continue;
      if (re === GLUED_DIGITS && !gluedToWords(text, match.index!, match.index! + match[0].length)) continue;
      const candidate = scoreCandidate(text, match[0], match.index!, keywords, cursors);
      if (!candidate) continue;
      byCode.set(candidate.code, Math.min(byCode.get(candidate.code) ?? Infinity, candidate.score));
      if (!best || candidate.score < best.score) best = candidate;
    }
  }
  if (best && unique) {
    for (const [code, score] of byCode) if (code !== best.code && score <= best.score + DISAGREE_MARGIN) return null;
  }
  return best;
}

// A code sits near the top: longer input is cut, which also bounds the work
// on hostile mail. A cut text loses the word the cut went through (as a
// preview cut off with "..." does) and offers no code near the cut.
export const MAX_SUBJECT_CHARS = 1_000;
export const MAX_PREVIEW_CHARS = 1_000;
export const MAX_BODY_CHARS = 20_000;

/**
 * The end of a text that was cut before it reached the detector (a body
 * reader's cap, a server's truncated body value): `findVerificationCode`
 * treats such a text as cut. U+FFFF is a noncharacter, never part of mail.
 */
export const CUT_MARK = '\u2026\uffff';

/** `text` marked as cut when `cut`. */
export function markCut(text: string, cut: boolean): string {
  return cut ? text + CUT_MARK : text;
}

// A preview may end where the server that made it stopped reading, with no
// mark at all, whatever its length: JMAP's preview is "up to 256
// characters", legacy-proxy cuts there, and before that reads only the first
// 8,192 bytes of a part, whose whitespace and markup can collapse to a few
// characters ("Your code is 1234"). JMAP has no property saying a preview is
// complete, so every preview is read as possibly cut at its end.

/** Whether `text` ends with "..." or "…" (and whitespace): cut, by its own say. */
function endsWithEllipsis(text: string): boolean {
  let end = text.length;
  while (end > 0 && SPACE.test(text.charAt(end - 1))) end--;
  return text.endsWith('...', end) || text.endsWith('…', end);
}

function capped(text: string | null | undefined, max: number, mayBeCut = false): { text: string; cut: boolean } {
  let t = text ?? '';
  let cut = mayBeCut;
  if (t.endsWith(CUT_MARK)) {
    t = t.slice(0, -CUT_MARK.length);
    cut = true;
  }
  if (t.length > max) {
    t = t.slice(0, max);
    cut = true;
  }
  if (endsWithEllipsis(t)) return { text: t, cut: true };
  return { text: cut ? `${t}…` : t, cut };
}

function cappedCandidate(text: string | null | undefined, max: number, mayBeCut = false, unique = false): Candidate | null {
  const c = capped(text, max, mayBeCut);
  return bestCandidate(c.text, c.cut, unique);
}

// ---- What a reader of the body sees: both body readers (Bulwark's and
// ---- webmail-gateway's) leave out the same hidden and quoted parts.

const ZERO_LENGTH = /^[+-]?(?:0+(?:\.0*)?|\.0+)(?:[a-z]{1,4}|%)?$/;
const ZERO_SIZE_PROPS = new Set(['font-size', 'width', 'height', 'max-width', 'max-height']);

/** An inline style that hides its element: display:none, visibility:hidden, mso-hide:all, no size, no opacity. */
export function hiddenByStyle(style: string): boolean {
  for (const declaration of style.toLowerCase().split(';')) {
    const colon = declaration.indexOf(':');
    if (colon < 0) continue;
    const prop = declaration.slice(0, colon).trim();
    const value = declaration.slice(colon + 1).replace('!important', '').trim();
    if (prop === 'display' && value === 'none') return true;
    if (prop === 'visibility' && (value === 'hidden' || value === 'collapse')) return true;
    if (prop === 'mso-hide' && value === 'all') return true;
    if (prop === 'opacity' && /^0*(?:\.0*)?$/.test(value) && value !== '') return true;
    if (ZERO_SIZE_PROPS.has(prop) && ZERO_LENGTH.test(value)) return true;
  }
  return false;
}

// Prior correspondence in HTML, as Bulwark's viewer collapses it
// (lib/quote-collapse.ts): a container wraps the quoted message (left out
// with its content; text after it is read), a separator is followed by it
// (left out with everything after it).
const QUOTE_CONTAINER_CLASSES = ['gmail_quote_container', 'gmail_quote', 'yahoo_quoted', 'protonmail_quote'];
const QUOTE_CONTAINER_IDS = new Set(['mail-editor-reference-message-container']);
const QUOTE_SEPARATOR_IDS = new Set(['divrplyfwdmsg', 'appendonsend', 'stopspelling']);
const QUOTE_SEPARATOR_CLASSES = ['moz-cite-prefix'];

/**
 * What the code reader does with an element: leave it and its content out
 * ('element': hidden, or a quote), leave out everything from it on ('rest':
 * the start of prior correspondence), or read it (null). `attr` gives an
 * attribute's value, or null when it is absent.
 */
export function excludedElement(tagName: string, attr: (name: string) => string | null): 'element' | 'rest' | null {
  const id = (attr('id') ?? '').trim().toLowerCase();
  const classes = ` ${(attr('class') ?? '').toLowerCase().replace(/\s+/g, ' ')} `;
  const hasClass = (list: string[]) => list.some((c) => classes.includes(` ${c} `));
  if (QUOTE_SEPARATOR_IDS.has(id) || hasClass(QUOTE_SEPARATOR_CLASSES)) return 'rest';
  if (QUOTE_CONTAINER_IDS.has(id) || hasClass(QUOTE_CONTAINER_CLASSES) || attr('data-quoted-html') !== null) return 'element';
  if (tagName.toLowerCase() === 'blockquote' || (attr('type') ?? '').trim().toLowerCase() === 'cite') return 'element';
  if (attr('hidden') !== null || (attr('aria-hidden') ?? '').trim().toLowerCase() === 'true') return 'element';
  const style = attr('style');
  return style && hiddenByStyle(style) ? 'element' : null;
}

/** "On <date>, <name> wrote:" and its translations (Finnish clients: "<date> <name> kirjoitti:"). */
const ATTRIBUTION =
  /^(?:(?:On|Am|Le|El|Il|Op|Den|Dne)\s.{3,300}\s(?:wrote|schrieb|a écrit|escribió|ha scritto|schreef|skrev|napsal)|.{3,300}\s(?:kirjoitti|skrev))\s*:?\s*$/i;
const QUOTE_SEPARATOR =
  /^(?:-{2,}\s*(?:Original Message|Forwarded message|Alkuperäinen viesti|Välitetty viesti|Ursprüngliche Nachricht|Weitergeleitete Nachricht|Message d'origine|Message transféré)\s*-{2,}|_{20,})\s*$/i;
const HEADER_FROM = /^\*?(?:From|Lähettäjä|Från|Von|De)\s*:\*?\s+\S/i;
const HEADER_NEXT = /^\*?(?:Sent|Date|To|Subject|Lähetetty|Päivämäärä|Vastaanottaja|Aihe|Skickat|Gesendet|Envoyé)\s*:/i;

/**
 * Plain text without prior correspondence: lines quoted with ">", and
 * everything from an "On … wrote:" line, an "-----Original Message-----" or
 * forwarded-message separator, or an Outlook "From: … / Sent: …" block on.
 * `quoteCut` says the text ended there. Line by line, each test anchored and
 * bounded, so linear in the text.
 */
export function withoutQuotedText(text: string): { text: string; quoteCut: boolean } {
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    const next = i + 1 < lines.length ? lines[i + 1]!.trim() : '';
    const startsQuote =
      QUOTE_SEPARATOR.test(line) ||
      ATTRIBUTION.test(line) ||
      // an attribution wrapped over two lines: "On Mon, 12 Oct 2026 at 10:00, Alice" / "<a@b> wrote:"
      (/^(?:On|Am|Le)\s/i.test(line) && ATTRIBUTION.test(`${line} ${next}`)) ||
      // an Outlook header block: "From: ..." followed by "Sent:/Date:/To:" within three lines
      (HEADER_FROM.test(line) && lines.slice(i + 1, i + 4).some((l) => HEADER_NEXT.test(l.trim())));
    if (startsQuote) return { text: out.join('\n'), quoteCut: true };
    if (!line.startsWith('>')) out.push(lines[i]!);
  }
  return { text: out.join('\n'), quoteCut: false };
}

/**
 * The one-time code in a mail, or null. `text` is the preview for a list
 * row (`source` 'preview') and the body for the reader. A code in the
 * subject wins, since senders that put it there ("Your code is 177945")
 * also tend to repeat it next to unrelated numbers in the body. Wherever a
 * text was, or may have been, cut (a cap, a CUT_MARK, a closing "..." or
 * "…", the end of any preview), no code is offered near the cut: the body
 * then has to show it whole. A body with two
 * different, about equally plausible codes gives none. The body readers
 * leave out hidden and quoted text (excludedElement, withoutQuotedText).
 */
export function findVerificationCode(
  subject: string | null | undefined,
  text: string | null | undefined,
  source: 'preview' | 'body' = 'body',
): string | null {
  const preview = source === 'preview';
  const fromSubject = cappedCandidate(subject, MAX_SUBJECT_CHARS);
  const fromText = cappedCandidate(text, preview ? MAX_PREVIEW_CHARS : MAX_BODY_CHARS, preview, !preview);
  if (!fromSubject) return fromText?.code ?? null;
  // A body that presents another code as the code ("code is 654321", or on a
  // line of its own) disagrees with its subject: no code, a wrong one is worse.
  if (!preview && fromText?.strong && fromText.code !== fromSubject.code) return null;
  return fromSubject.code;
}

// ---------------------------------------------------------------- gateway additions

/**
 * Whether `text` names a code at all (the keyword rules above, with no
 * candidate needed). The push pipeline reads a message's body for its code
 * only when the subject or preview says there is one, but the preview did
 * not show it (cut off, or behind a stylesheet or padding).
 */
export function mentionsVerificationCode(text: string | null | undefined): boolean {
  const t = normalize(capped(text, MAX_PREVIEW_CHARS).text);
  return t.length > 0 && findCodeWords(t).some((list) => list.length);
}

// A code sits near the top; a newsletter of megabytes need not be read whole.
const MAX_BODY_HTML = 200_000;

/**
 * The texts of a message body to look for its code in, best first: the HTML
 * part as text (stylesheets, scripts and comments dropped, table cells kept
 * apart), then the plain-text part, each as its reader sees it: hidden
 * elements and prior correspondence (quotes, forwarded or replied-to
 * messages) are left out (excludedElement, withoutQuotedText), so a hidden
 * or older code is never offered. Parts flagged with an encoding problem
 * are skipped. A text cut on the way (the server's truncated value, the
 * HTML or text cap) ends with CUT_MARK, so the cut is known to the detector
 * even when the text left is short (a large <style> before the cut); one
 * that ends where prior correspondence starts is complete.
 */
export function verificationCodeBodyTexts(body: EmailBody): string[] {
  const out: string[] = [];
  const html = body.html.find((p) => p.type === "text/html" && p.value && !p.isEncodingProblem);
  if (html) {
    const cutHtml = html.isTruncated === true || html.value.length > MAX_BODY_HTML;
    const read = htmlToTextRead(html.value.slice(0, MAX_BODY_HTML), { keepQuotes: true, exclude: excludedElement });
    const visible = withoutQuotedText(read.text);
    // Two causes, kept apart: the text cap (a quote after it does not make
    // what was cut whole), and the HTML cut, which a quote or separator
    // before it makes harmless.
    const complete = read.stopped || visible.quoteCut;
    out.push(markCut(visible.text.slice(0, MAX_BODY_CHARS), visible.text.length > MAX_BODY_CHARS || (!complete && cutHtml)));
  }
  const text = body.text.find((p) => p.type === "text/plain" && p.value && !p.isEncodingProblem);
  if (text) {
    const cut = text.isTruncated === true || text.value.length > MAX_BODY_CHARS;
    const visible = withoutQuotedText(text.value.slice(0, MAX_BODY_CHARS));
    out.push(markCut(visible.text, cut && !visible.quoteCut));
  }
  return out;
}

/**
 * The code in a message's body, read as `findVerificationCode` reads it
 * after the subject: from the HTML part as its reader shows it, else from
 * the plain-text part. When the subject has a code, the first body text
 * decides whether it stands (a body presenting another code gives none).
 */
export function findVerificationCodeInBody(subject: string | null | undefined, body: EmailBody): string | null {
  const texts = verificationCodeBodyTexts(body);
  if (texts.length === 0) return findVerificationCode(subject, "");
  const subjectHasCode = findVerificationCode(subject, "") !== null;
  for (const text of texts) {
    const code = findVerificationCode(subject, text);
    if (code || subjectHasCode) return code;
  }
  return null;
}
