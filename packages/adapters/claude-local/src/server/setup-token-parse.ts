// The Claude `setup-token` parsers. They read the interactive login output of
// Claude Code. `parseSetupTokenPrompt` returns the authorization URL and the
// browser-code prompt, or null. `parseSetupTokenCredential` returns the minted
// OAuth token from the success screen, or null.
//
// Security (shape validation): the prompt parser accepts an authorization URL
// only when it matches one of the two observed origin-and-path pairs, carries
// each required query key one time with a valid decoded value, and pins the
// `redirect_uri` value to the one observed callback. It rejects a look-alike
// host, userinfo, an explicit port, a fragment, a duplicate key, an unexpected
// added key, an invalid value, and an API-key-shaped value in the raw URL or in
// any decoded query value. Different Claude CLI versions render the URL two ways:
// a single OSC 8 hyperlink, or plain text with a hard line wrap and no
// hyperlink. The parser reassembles the wrapped plain-text URL from the physical
// lines and validates only the final reassembled string, so the login works on
// every CLI version that keeps this flow shape. It binds the browser-code prompt
// to the dedicated line after the URL block; a repeated URL line, a code-like
// value on the wrong line, or an unrelated line cannot form a prompt.
//
// The token parser binds the token to the exact success record: it requires the
// before-anchor line and the after-anchor line, in that order, exactly one time
// each, and it reads only the lines between them. It de-wraps the token across
// the physical terminal lines. It fails closed for any other input. Both parsers
// never log any input byte, and they keep every input byte out of each thrown
// error. Both parsers are pure functions.

export interface SetupTokenPrompt {
  // The validated authorization URL, exactly as the terminal emitted it.
  url: string;
  // The canonical browser-code prompt. The parser returns the constant
  // {@link SETUP_TOKEN_PROMPT}, so the output is never a caller-controlled value.
  prompt: string;
}

// The canonical browser-code prompt text. The Claude login UI prints this line
// to ask the user to paste the code from the browser. The parser returns this
// exact constant on a match.
export const SETUP_TOKEN_PROMPT = "Paste code here if prompted";

// The two accepted authorization URLs, each the exact origin plus path. The
// parser accepts an origin-and-path pair only when it equals one of these two
// strings. It does not accept the cross-product of the two hosts and the two
// paths. `claude` 2.1.19 emits the first URL; `claude` 2.1.205 and 2.1.226 emit
// the second URL.
export const SETUP_TOKEN_AUTH_URLS = [
  "https://claude.ai/oauth/authorize",
  "https://claude.com/cai/oauth/authorize",
] as const;

// The lowercase host prefix of each accepted authorization URL. The parser
// requires the raw URL candidate to start with one of these exact lowercase
// prefixes before it parses the URL. This rejects a mixed-case host spelling, a
// punycode host, and an explicit default `:443` port, because none of them start
// with the exact lowercase `https://<host>/` prefix.
const SETUP_TOKEN_AUTH_URL_PREFIXES = [
  "https://claude.ai/",
  "https://claude.com/",
] as const;

// The one accepted `redirect_uri` value. The parser parses the decoded
// `redirect_uri` value on its own and pins it to this exact callback, with no
// userinfo, no port, no query, and no fragment. The 2.1.226 live capture grounds
// this host; the contract keeps a single pin until sanitized 2.1.19 evidence
// proves another real callback.
export const SETUP_TOKEN_REDIRECT_URI = "https://platform.claude.com/oauth/code/callback";

// The required query keys of the authorization URL. The parser requires each key
// one time with a valid decoded value. It rejects a missing key, a duplicate
// key, and an invalid value.
export const SETUP_TOKEN_URL_QUERY_KEYS = [
  "client_id",
  "code",
  "code_challenge",
  "code_challenge_method",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
] as const;

// The set form of the required query keys. The parser uses it to sort a key into
// a required key or an added key.
const SETUP_TOKEN_CORE_KEY_SET = new Set<string>(SETUP_TOKEN_URL_QUERY_KEYS);

// The value validators for the required query keys. Each pattern binds the whole
// decoded value. The parser rejects a value that does not match.
const CLIENT_ID_RE = /^[A-Za-z0-9._~-]{1,128}$/;
// The `code` value of the `claude` 2.1.19 authorization request is a short
// opaque token. A real 2.1.19 capture measured a 4-character value, so the
// minimum length is one character. The character class and the 1024-character
// maximum bound the value.
const CODE_RE = /^[A-Za-z0-9._~-]{1,1024}$/;
const CODE_CHALLENGE_RE = /^[A-Za-z0-9_-]{43,128}$/;
const STATE_RE = /^[A-Za-z0-9_-]{16,256}$/;
// One `scope` token. The `scope` value is one to eight space-separated tokens.
const SCOPE_TOKEN_RE = /^[A-Za-z0-9:._-]{1,64}$/;

// The name of an added query key. An added key is any key that is not a required
// key. The parser accepts at most four added keys, each with a name that matches
// this pattern.
const ADDED_KEY_NAME_RE = /^[a-z][a-z0-9_-]{0,63}$/;

// The decoded value of an added query key. The parser accepts at most 256
// printable ASCII characters.
const ADDED_VALUE_RE = /^[\x20-\x7E]{0,256}$/;

// An API-key prefix. The Claude setup token and API key start with `sk-ant-`.
// The parser rejects the raw URL candidate and any decoded query value that
// holds this prefix, so a secret cannot ride inside the authorization URL.
const API_KEY_RE = /sk-ant-/i;

// The maximum number of added query keys. The parser accepts at most four added
// keys, so the URL holds at most twelve keys in total.
const MAX_ADDED_KEYS = 4;

// The maximum number of `scope` tokens.
const MAX_SCOPE_TOKENS = 8;

// The maximum length of the whole `scope` value.
const MAX_SCOPE_LENGTH = 512;

// The maximum length of the reassembled authorization URL. The parser rejects a
// candidate longer than this cap.
const MAX_URL_LENGTH = 2048;

// The characters that a URL can hold. A physical line that reassembles into the
// wrapped URL holds only these characters after a trim.
const URL_CHARS_ONLY_RE = /^[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/;

// An ANSI Control Sequence Introducer (CSI): the ESC control byte, a `[`, zero
// or more parameter bytes (0x30-0x3F), zero or more intermediate bytes
// (0x20-0x2F), and one final byte (0x40-0x7E). The Claude terminal wraps the
// output in CSI color sequences. The parser removes every CSI sequence first, so
// a colored prompt reads the same as a plain one.
// eslint-disable-next-line no-control-regex
const ANSI_CSI_RE = /\x1b\[[0-?]*[ -/]*[@-~]/g;

// A horizontal-move CSI sequence: Cursor Horizontal Absolute (final byte `G`)
// and Cursor Forward (final byte `C`). The Claude login UI lays out each word at
// an absolute column with one of these sequences, so it emits no literal space
// between two words. The parser replaces each horizontal-move sequence with one
// space, so a word gap reads as a space. Without this step the later CSI removal
// deletes the sequence and glues the two words, and the URL preamble line, the
// browser-code prompt line, and the success anchor lines never match. The
// vertical and color sequences carry no horizontal text gap; the CSI removal
// below drops them.
// eslint-disable-next-line no-control-regex
const CSI_HORIZONTAL_MOVE_RE = /\x1b\[[0-9;]*[GC]/g;

// An OSC 8 hyperlink. The terminal emits the URL through an OSC 8 hyperlink plus
// wrapped display text. The hyperlink carries the true, unwrapped URL in its URI
// field, while the display text may wrap across lines. The parser replaces the
// whole hyperlink (open sequence, display text, close sequence) with the URI, so
// it reads the unwrapped URL and drops the wrapped display text. The URI field
// is the first capture group. The terminator of each OSC sequence is the String
// Terminator (ESC `\`) or the BEL byte.
// eslint-disable-next-line no-control-regex
const OSC8_HYPERLINK_RE =
  /\x1b\]8;[^;\x1b\x07]*;([^\x1b\x07]*)(?:\x1b\\|\x07)[\s\S]*?\x1b\]8;[^;\x1b\x07]*;(?:\x1b\\|\x07)/g;

// Any remaining OSC sequence. A partial output chunk can hold an OSC 8 open
// sequence without its close sequence. The parser removes each leftover OSC
// sequence after it replaces the complete hyperlinks.
// eslint-disable-next-line no-control-regex
const OSC_ANY_RE = /\x1b\][^\x1b\x07]*(?:\x1b\\|\x07)/g;

// Trailing punctuation that prose commonly puts right after a URL. The parser
// strips only these characters when it compares a line to a repeated URL. It
// never strips these from the candidate before validation, because the validator
// rejects any trailing punctuation on its own.
const TRAILING_PUNCTUATION_RE = /[)\].,;:!]+$/;

// The line that introduces the URL. The Claude login UI prints this phrase right
// before the URL. The parser anchors the URL search on this phrase, so a URL far
// from the login context cannot bind.
const URL_PREAMBLE_RE = /the url below to sign in/i;

// The browser-code prompt on a dedicated line. The line starts with the exact
// prompt phrase. The line can end with the input caret `>` and masked echo `*`
// characters and spaces. The pattern rejects the phrase when other prose shares
// the line.
const PROMPT_LINE_RE = /^Paste code here if prompted\b[\s>*]*$/;

// The copy hint Claude Code prints between the URL block and the prompt.
// Linux builds say "Hold Shift". macOS builds of the same flow say "Hold Fn"
// or "Hold Option". The parser skips this hint, including a short wrap, and
// binds no value from it. Any other line still fails closed.
const COPY_HINT_LINE_RE = /^Hold\s+(?:Shift|Fn|Option|Opt)\s+while\s+selecting\s+to\s+use\s+your\s+terminal['’]s\s+native\s+copy\.?$/i;

// The most physical lines a wrapped copy hint may occupy. A narrow wrap of the
// hint fits in this budget. A longer run is not the hint.
const MAX_COPY_HINT_LINES = 4;

// The maximum number of characters between the end of the URL preamble line and
// the start of the URL. The Claude UI prints the URL right after the preamble.
// The parser accepts a URL start only inside this window, so a URL far from the
// preamble cannot bind.
const MAX_PREAMBLE_TO_URL_GAP = 512;

// The maximum number of consecutive physical lines that the parser joins to
// reassemble a wrapped plain-text URL. The `claude` 2.1.19 CLI wraps the URL at
// the terminal width with no space at the wrap, so the parser joins a bounded
// run of URL-character-only lines.
const MAX_URL_LINES = 16;

// The result of a URL search: the validated URL and the index of the physical
// line that holds the last fragment of the URL.
interface SetupTokenUrlMatch {
  url: string;
  endLine: number;
}

/**
 * Removes the terminal control sequences from `text`. Replaces each OSC 8
 * hyperlink with its true URI, so the parser reads the unwrapped URL and drops
 * the wrapped display text. Removes each leftover OSC sequence. Replaces each
 * horizontal-move CSI sequence with one space, so a word that the login UI lays
 * out at an absolute column reads as a space-separated word. Removes each
 * remaining ANSI CSI sequence. Returns plain text. The function only normalizes
 * the input; the URL and the prompt still pass the shape validation below.
 */
function stripTerminalControls(text: string): string {
  return text
    .replace(OSC8_HYPERLINK_RE, "$1")
    .replace(OSC_ANY_RE, "")
    .replace(CSI_HORIZONTAL_MOVE_RE, " ")
    .replace(ANSI_CSI_RE, "");
}

// The screen keeps enough rows and columns for one login transcript. The
// column cap stays above the authorization URL length cap. A shorter cap would
// cut a too-long URL down into a URL the validator accepts.
const SCREEN_MAX_ROWS = 400;
const SCREEN_MAX_COLS = MAX_URL_LENGTH * 2;

/**
 * Reads one CSI sequence starting at the `[` of `ESC [`. Returns null when the
 * sequence does not finish. Private-mode sequences (`ESC [ ? ...`) are marked
 * so the screen can ignore them.
 */
function readCsi(chars: string[], start: number): { end: number; params: number[]; final: string; privateMode: boolean } | null {
  let index = start + 1;
  const privateMode = index < chars.length && chars[index] === "?";
  if (privateMode) index += 1;
  const params: number[] = [];
  let current = "";
  const limit = Math.min(chars.length, start + 48);
  while (index < limit) {
    const ch = chars[index];
    if (ch >= "0" && ch <= "9") {
      current += ch;
      index += 1;
      continue;
    }
    if (ch === ";") {
      params.push(current === "" ? 0 : Number(current));
      current = "";
      index += 1;
      continue;
    }
    if (ch >= "@" && ch <= "~") {
      params.push(current === "" ? 0 : Number(current));
      return { end: index + 1, params, final: ch, privateMode };
    }
    index += 1;
  }
  return null;
}

function moveCount(params: number[], slot: number): number {
  const value = params[slot] ?? 0;
  return value === 0 ? 1 : value;
}

/**
 * Renders login output onto a terminal screen and returns the visible rows.
 * Cursor-forward over a cell that already holds a character keeps that
 * character. Cursor-forward over an empty cell becomes a space when the row
 * is read back, which preserves word gaps. OSC 8 hyperlinks contribute their
 * URI, not the wrapped display text. The function does not validate a URL or
 * a token.
 */
function renderTerminalScreen(text: string): string {
  const source = text.replace(OSC8_HYPERLINK_RE, "$1\n").replace(OSC_ANY_RE, "");
  const chars = Array.from(source);
  const rows: string[][] = [];
  let row = 0;
  let col = 0;

  const ensure = (index: number): string[] => {
    while (rows.length <= index) rows.push([]);
    return rows[index];
  };
  const writeChar = (ch: string): void => {
    if (row >= SCREEN_MAX_ROWS || col >= SCREEN_MAX_COLS) return;
    const line = ensure(row);
    while (line.length < col) line.push(" ");
    line[col] = ch;
    col += 1;
  };

  for (let index = 0; index < chars.length; index += 1) {
    const ch = chars[index];
    if (ch === "\n") {
      row = Math.min(SCREEN_MAX_ROWS - 1, row + 1);
      col = 0;
      continue;
    }
    if (ch === "\r") {
      col = 0;
      continue;
    }
    if (ch !== "\u001b") {
      if (ch >= " " || ch === "\t") writeChar(ch === "\t" ? " " : ch);
      continue;
    }
    const next = chars[index + 1];
    if (next !== "[") {
      index += next === undefined ? 0 : 1;
      continue;
    }
    const csi = readCsi(chars, index + 1);
    if (!csi) break;
    index = csi.end - 1;
    if (csi.privateMode) continue;
    if (csi.final === "A") row = Math.max(0, row - moveCount(csi.params, 0));
    else if (csi.final === "B") row = Math.min(SCREEN_MAX_ROWS - 1, row + moveCount(csi.params, 0));
    else if (csi.final === "C") col = Math.min(SCREEN_MAX_COLS - 1, col + moveCount(csi.params, 0));
    else if (csi.final === "D") col = Math.max(0, col - moveCount(csi.params, 0));
    else if (csi.final === "G") col = Math.max(0, Math.min(SCREEN_MAX_COLS - 1, (csi.params[0] || 1) - 1));
    else if (csi.final === "H" || csi.final === "f") {
      row = Math.max(0, Math.min(SCREEN_MAX_ROWS - 1, (csi.params[0] || 1) - 1));
      col = Math.max(0, Math.min(SCREEN_MAX_COLS - 1, (csi.params[1] || 1) - 1));
    } else if (csi.final === "K") {
      const line = ensure(row);
      const mode = csi.params[0] ?? 0;
      if (mode === 0) line.splice(col);
      else if (mode === 1) {
        for (let cell = 0; cell <= col && cell < line.length; cell += 1) line[cell] = " ";
      } else if (mode === 2) line.splice(0, line.length);
    }
  }
  return rows.map((line) => line.join("").replace(/[ \t]+$/u, "")).join("\n");
}

/**
 * Returns true when `value` is a valid `scope` value: one to eight
 * space-separated tokens, a total length of at most {@link MAX_SCOPE_LENGTH},
 * and each token a match of {@link SCOPE_TOKEN_RE}. A double space forms an empty
 * token, which fails the token pattern, so a malformed value fails closed.
 */
function isValidScope(value: string): boolean {
  if (value.length < 1 || value.length > MAX_SCOPE_LENGTH) return false;
  const tokens = value.split(" ");
  if (tokens.length < 1 || tokens.length > MAX_SCOPE_TOKENS) return false;
  return tokens.every((token) => SCOPE_TOKEN_RE.test(token));
}

/**
 * Returns true when `value` is the one accepted `redirect_uri`. The function
 * parses the decoded value on its own and pins it to {@link
 * SETUP_TOKEN_REDIRECT_URI}, with the `https:` protocol, no userinfo, no port,
 * no query, and no fragment. It never broadens to an arbitrary HTTPS URL.
 */
function isValidRedirectUri(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  if (parsed.username !== "" || parsed.password !== "") return false;
  if (parsed.port !== "") return false;
  if (parsed.search !== "" || parsed.hash !== "") return false;
  return `${parsed.origin}${parsed.pathname}` === SETUP_TOKEN_REDIRECT_URI;
}

/**
 * Returns true when the query of `parsed` matches the contract. It requires each
 * required key one time with a valid decoded value. It rejects a duplicate for
 * any key. It accepts at most {@link MAX_ADDED_KEYS} added keys, each with a
 * valid name, one value, and a decoded value of at most 256 printable ASCII
 * characters. It rejects an API-key prefix in any decoded value.
 */
function hasValidQuery(parsed: URL): boolean {
  // Collect the values of each key, so the parser can reject a duplicate key and
  // read the one decoded value of each key.
  const byKey = new Map<string, string[]>();
  for (const [key, value] of parsed.searchParams) {
    const values = byKey.get(key);
    if (values) values.push(value);
    else byKey.set(key, [value]);
  }

  // Reject a duplicate for any key. After this test each key holds one value.
  for (const values of byKey.values()) {
    if (values.length !== 1) return false;
  }

  // Reject an API-key prefix in any decoded key and any decoded value. The
  // `URLSearchParams` decoder turns a percent-encoded name into its literal
  // form, so a secret-shaped value can hide in a query name (for example,
  // `sk%2Dant%2Dredacted` decodes to `sk-ant-redacted`). The parser rejects the
  // prefix in the name and in the value, before it classifies an added key. The
  // raw-candidate check stays in place as defense in depth.
  for (const [key, values] of byKey) {
    if (API_KEY_RE.test(key)) return false;
    if (API_KEY_RE.test(values[0])) return false;
  }

  // Require each required key.
  for (const key of SETUP_TOKEN_URL_QUERY_KEYS) {
    if (!byKey.has(key)) return false;
  }

  // Bound the added keys and validate each one.
  const addedKeys = [...byKey.keys()].filter((key) => !SETUP_TOKEN_CORE_KEY_SET.has(key));
  if (addedKeys.length > MAX_ADDED_KEYS) return false;
  for (const key of addedKeys) {
    if (!ADDED_KEY_NAME_RE.test(key)) return false;
    if (!ADDED_VALUE_RE.test(byKey.get(key)![0])) return false;
  }

  // Validate each required value.
  if (!CLIENT_ID_RE.test(byKey.get("client_id")![0])) return false;
  if (!CODE_RE.test(byKey.get("code")![0])) return false;
  if (!CODE_CHALLENGE_RE.test(byKey.get("code_challenge")![0])) return false;
  if (byKey.get("code_challenge_method")![0] !== "S256") return false;
  if (byKey.get("response_type")![0] !== "code") return false;
  if (!STATE_RE.test(byKey.get("state")![0])) return false;
  if (!isValidScope(byKey.get("scope")![0])) return false;
  if (!isValidRedirectUri(byKey.get("redirect_uri")![0])) return false;
  return true;
}

/**
 * Returns `candidate` when it is a valid authorization URL, or null. The final
 * validator applies to every candidate, from an OSC 8 URI or from a plain-text
 * reassembly. It requires the length cap {@link MAX_URL_LENGTH}, an exact
 * lowercase host prefix, no API-key prefix in the raw candidate, the `https:`
 * protocol, empty userinfo, empty port, no fragment, one of the two accepted
 * origin-and-path pairs, and a valid query.
 */
function validateAuthUrl(candidate: string): string | null {
  if (candidate.length > MAX_URL_LENGTH) return null;
  if (!SETUP_TOKEN_AUTH_URL_PREFIXES.some((prefix) => candidate.startsWith(prefix))) return null;
  if (API_KEY_RE.test(candidate)) return null;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:") return null;
  if (parsed.username !== "" || parsed.password !== "") return null;
  if (parsed.port !== "" || parsed.hash !== "") return null;
  const pair = `${parsed.origin}${parsed.pathname}`;
  if (!SETUP_TOKEN_AUTH_URLS.includes(pair as (typeof SETUP_TOKEN_AUTH_URLS)[number])) return null;
  if (!hasValidQuery(parsed)) return null;
  return candidate;
}

/**
 * Reassembles a wrapped plain-text URL from the physical lines and validates it.
 * The parser starts at `startLine`, then joins at most {@link MAX_URL_LINES}
 * consecutive URL-character-only physical lines into at most {@link
 * MAX_URL_LENGTH} characters. It validates the joined string after each join and
 * returns the first joined string that passes {@link validateAuthUrl}. A CLI that
 * emits the whole URL on one line passes on the first join. A CLI that wraps the
 * URL passes once the parser joins the last fragment. Returns null when no bounded
 * join validates.
 */
function reassembleUrl(lines: string[], startLine: number): SetupTokenUrlMatch | null {
  let joined = "";
  for (let offset = 0; offset < MAX_URL_LINES && startLine + offset < lines.length; offset += 1) {
    const trimmed = lines[startLine + offset].trim();
    if (trimmed.length === 0 || !URL_CHARS_ONLY_RE.test(trimmed)) break;
    joined += trimmed;
    if (joined.length > MAX_URL_LENGTH) break;
    const url = validateAuthUrl(joined);
    if (url) return { url, endLine: startLine + offset };
  }
  return null;
}

/**
 * Returns the canonical browser-code prompt when `lines` holds it on a dedicated
 * line after the URL block. The parser reads the non-blank lines after the URL
 * end line. The Claude UI can emit one full URL line per wrapped display row, so
 * it repeats the same full authorization URL on a few consecutive lines. The
 * parser skips a line that repeats `url`. The `claude` 2.1.291 UI also prints a
 * copy hint before the prompt, so the parser skips a line or a short wrap that
 * matches {@link COPY_HINT_LINE_RE}. The parser then binds the prompt on the
 * first non-blank line that is not a repeat and not the copy hint. That line
 * must match the exact prompt shape. Returns null when that line is not the
 * prompt.
 */
function copyHintEnd(lines: string[], start: number): number {
  const parts: string[] = [];
  for (let index = start; index < lines.length && parts.length < MAX_COPY_HINT_LINES; index += 1) {
    const trimmed = lines[index].trim();
    if (trimmed.length === 0) break;
    parts.push(trimmed);
    if (COPY_HINT_LINE_RE.test(parts.join(" "))) return index + 1;
  }
  return -1;
}

function findBrowserCodePrompt(lines: string[], endLine: number, url: string): string | null {
  for (let i = endLine + 1; i < lines.length; i += 1) {
    const trimmed = lines[i].trim();
    if (trimmed.length === 0) continue;
    // Skip a line that repeats the full URL. Strip the trailing prose
    // punctuation first, the same way the repeated-URL comparison needs, so a
    // repeated URL with a trailing punctuation mark still matches.
    if (trimmed.replace(TRAILING_PUNCTUATION_RE, "") === url) continue;
    const hintEnd = copyHintEnd(lines, i);
    if (hintEnd !== -1) {
      i = hintEnd - 1;
      continue;
    }
    return PROMPT_LINE_RE.test(trimmed) ? SETUP_TOKEN_PROMPT : null;
  }
  return null;
}

/**
 * Parses Claude `setup-token` login output. Removes the terminal control
 * sequences first, so colored and hyperlinked output reads the same as plain
 * output. The parser finds the URL preamble, then a physical line that starts the
 * authorization URL within {@link MAX_PREAMBLE_TO_URL_GAP} characters of the
 * preamble, then reassembles the wrapped URL and validates the final string, then
 * binds the browser-code prompt on the dedicated line after the URL block. So the
 * URL binds to the login context and the prompt binds to the URL. Returns the
 * authorization URL and the browser-code prompt when both are present and valid.
 * Returns null for any other input, including a non-string input, an absent
 * preamble, a URL with a wrong host, path, query, or fragment, an API-key-shaped
 * URL, and a missing or misplaced prompt. Never throws on input, and never puts
 * any input byte into a log or an error. This phase returns no token.
 */
function promptFromPlain(clean: string): SetupTokenPrompt | null {
  const preamble = URL_PREAMBLE_RE.exec(clean);
  if (!preamble) return null;
  const afterPreamble = preamble.index + preamble[0].length;
  // The region after the preamble. The URL must start inside the start window.
  const region = clean.slice(afterPreamble);
  const lines = region.split("\n");

  // Walk the physical lines and track the character offset of each line start.
  // The URL must start within MAX_PREAMBLE_TO_URL_GAP characters of the preamble.
  let offset = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const lineStart = offset;
    offset += lines[i].length + 1;
    if (lineStart > MAX_PREAMBLE_TO_URL_GAP) break;
    const trimmed = lines[i].trim();
    if (!SETUP_TOKEN_AUTH_URL_PREFIXES.some((prefix) => trimmed.startsWith(prefix))) continue;
    const match = reassembleUrl(lines, i);
    if (!match) continue;
    const prompt = findBrowserCodePrompt(lines, match.endLine, match.url);
    if (prompt) return { url: match.url, prompt };
  }
  return null;
}

function plainLoginText(text: string): string[] {
  return [renderTerminalScreen(text), stripTerminalControls(text).replace(/\r\n|\r/g, "\n")];
}

export function parseSetupTokenPrompt(text: string): SetupTokenPrompt | null {
  if (typeof text !== "string" || text.length === 0) return null;
  for (const clean of plainLoginText(text)) {
    const prompt = promptFromPlain(clean);
    if (prompt) return prompt;
  }
  return null;
}

// A fresh Claude home can stop on one of these screens before it prints a URL.
// The classifier returns a fixed kind. It never returns the screen text.
export type SetupTokenBlocker = "workspace_trust" | "first_run_onboarding";

const WORKSPACE_TRUST_RE = /Quick safety check|Is this a project you created or one you trust/i;
const FIRST_RUN_ONBOARDING_RE = /Choose the text style that looks best/i;

/**
 * Classifies a login transcript that has not produced a sign-in URL. Returns
 * null when the transcript holds a valid prompt, or when it does not match a
 * known blocking screen. Never returns transcript text.
 */
export function classifySetupTokenBlocker(text: string): SetupTokenBlocker | null {
  if (typeof text !== "string" || text.length === 0) return null;
  if (parseSetupTokenPrompt(text)) return null;
  const plain = plainLoginText(text).join("\n");
  if (WORKSPACE_TRUST_RE.test(plain)) return "workspace_trust";
  if (FIRST_RUN_ONBOARDING_RE.test(plain)) return "first_run_onboarding";
  return null;
}

// --- The success token parser ------------------------------------------------

// The literal prefix of the Claude setup-token OAuth token. The success screen
// prints a token that starts with this exact prefix. The opaque tail follows.
export const SETUP_TOKEN_PREFIX = "sk-ant-oat01-";

// The line that introduces the token. The success screen prints this exact line
// right before the token block. The token parser binds the token to this anchor.
export const SETUP_TOKEN_BEFORE_ANCHOR = "Your OAuth token (valid for 1 year):";

// The line that follows the token. The success screen prints this exact line
// right after the token block. The token parser binds the token to this anchor.
export const SETUP_TOKEN_AFTER_ANCHOR =
  "Store this token securely. You won't be able to see it again.";

// One physical line of the token. The terminal wraps the token at the
// pseudo-terminal width, so one physical line holds one fragment of the token
// character class. The token character class is `[A-Za-z0-9_-]`; the opaque tail
// can contain `-`, so a line fragment can contain `-`.
const TOKEN_FRAGMENT_RE = /^[A-Za-z0-9_-]+$/;

// The full token shape after the parser joins the wrapped fragments. The token
// starts with the exact prefix and continues over the token character class. The
// minimum tail length rejects a bare prefix and a short, noisy candidate. A real
// opaque tail is far longer than this floor.
const FULL_TOKEN_RE = /^sk-ant-oat01-[A-Za-z0-9_-]{20,}$/;

// Differential redraws omit one or two characters that are already on screen.
// After a cursor-forward is removed, the visible anchor can differ from the
// canonical line by that many edits. A longer difference is not the anchor.
const ANCHOR_MAX_EDITS = 2;

const ANCHOR_PREFIX = new Map<string, string>([
  [SETUP_TOKEN_BEFORE_ANCHOR, "Your OAu"],
  [SETUP_TOKEN_AFTER_ANCHOR, "Store this token securely."],
]);

function withinEdits(left: string, right: string, maxEdits: number): boolean {
  if (Math.abs(left.length - right.length) > maxEdits) return false;
  let previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i += 1) {
    const current = [i];
    let rowMin = i;
    for (let j = 1; j <= right.length; j += 1) {
      const cost = left[i - 1] === right[j - 1] ? 0 : 1;
      const value = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost);
      current[j] = value;
      if (value < rowMin) rowMin = value;
    }
    if (rowMin > maxEdits) return false;
    previous = current;
  }
  return previous[right.length] <= maxEdits;
}

function matchesAnchor(line: string, anchor: string): boolean {
  if (line === anchor) return true;
  const prefix = ANCHOR_PREFIX.get(anchor);
  if (!prefix || !line.startsWith(prefix)) return false;
  return withinEdits(line, anchor, ANCHOR_MAX_EDITS);
}

/**
 * Returns the index of the one line that matches `anchor` after a trim. An
 * exact line matches. A line also matches when it keeps the anchor prefix and
 * is within {@link ANCHOR_MAX_EDITS} single-character edits, which is the
 * damage a differential redraw leaves. Returns null when no line matches.
 * Returns null when more than one line matches, so a duplicate success block
 * fails closed.
 */
function singleAnchorIndex(lines: string[], anchor: string): number | null {
  let found: number | null = null;
  for (let i = 0; i < lines.length; i += 1) {
    if (!matchesAnchor(lines[i].trim(), anchor)) continue;
    if (found !== null) return null;
    found = i;
  }
  return found;
}

/**
 * Parses the Claude `setup-token` success screen and returns the minted OAuth
 * token, or null. The parser removes the terminal control sequences first, then
 * binds the token to the exact success record. It requires the before-anchor
 * line {@link SETUP_TOKEN_BEFORE_ANCHOR} and the after-anchor line
 * {@link SETUP_TOKEN_AFTER_ANCHOR}, in that order, exactly one time each. It
 * reads only the lines between the two anchors. It de-wraps the token: it joins
 * the fragment lines with no separator, the same way the terminal split one
 * token across the physical lines. It validates the joined value against the
 * token shape.
 *
 * The parser fails closed for any other input. It returns null for a
 * token-shaped value outside the two anchors (before submit, in retry or error
 * text, or after a cancellation), a duplicate success block, an anchor out of
 * order, a missing anchor, extra text on a token line, a stray prose line
 * between the anchors, a wrong prefix, and a value that does not match the token
 * shape. It never logs any input byte and never puts any input byte into a
 * thrown error. The parser is a pure function.
 */
function credentialFromPlain(clean: string): string | null {
  const lines = clean.split("\n");

  const beforeIndex = singleAnchorIndex(lines, SETUP_TOKEN_BEFORE_ANCHOR);
  const afterIndex = singleAnchorIndex(lines, SETUP_TOKEN_AFTER_ANCHOR);
  if (beforeIndex === null || afterIndex === null) return null;
  if (afterIndex <= beforeIndex) return null;

  // Read only the non-blank lines strictly between the two anchors. Each line
  // must be one token fragment. A stray prose line, or extra text on a token
  // line, fails the fragment test and the parser returns null.
  const fragments: string[] = [];
  for (let i = beforeIndex + 1; i < afterIndex; i += 1) {
    const trimmed = lines[i].trim();
    if (trimmed.length === 0) continue;
    if (!TOKEN_FRAGMENT_RE.test(trimmed)) return null;
    fragments.push(trimmed);
  }
  if (fragments.length === 0) return null;

  const token = fragments.join("");
  if (!FULL_TOKEN_RE.test(token)) return null;
  return token;
}

export function parseSetupTokenCredential(text: string): string | null {
  if (typeof text !== "string" || text.length === 0) return null;
  // Try the rendered screen first. Fall back to the linear control strip, and
  // map a bare carriage return to a line feed, because some success records use
  // that byte as the line delimiter. Neither path can add a token byte.
  for (const clean of plainLoginText(text)) {
    const token = credentialFromPlain(clean);
    if (token) return token;
  }
  return null;
}
