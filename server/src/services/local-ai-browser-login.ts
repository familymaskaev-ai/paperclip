import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { open } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { runSetupTokenLogin } from "@paperclipai/adapter-claude-local/server";
import { runDeviceLogin } from "@paperclipai/adapter-codex-local/server";
import { ensureCommandResolvable, resolveCommandForLogs } from "@paperclipai/adapter-utils/server-utils";
import { resolveCodexCommand, startAntigravityBrowserLogin } from "../vendor/paperclip-runner/index.js";

export type LocalBrowserLoginState = {
  authorizationUrl?: string;
  code?: string;
  outcome?: "success" | "failure";
  error?: string;
  submitCode?: (code: string) => void;
  abort: () => void;
};

// Node has no built-in PTY API. Python's standard-library pty module supplies
// the terminal required by both CLIs. The Docker image already includes
// python3. This bridge forwards only bytes; provider output is never logged.
//
// The slave starts at 0 rows by 0 columns unless a size is set before exec.
// A later resize does not rebuild a frame the process already measured at
// startup, and it does not answer a terminal-query wait. Set the size on the
// slave before exec, and again on the master so the size survives platforms
// that apply it on only one side.
const LOGIN_PTY_ROWS = 40;
const LOGIN_PTY_COLS = 120;
const PYTHON_PTY_BRIDGE = String.raw`
import errno, fcntl, os, pty, select, signal, struct, sys, termios
pid, master = pty.fork()
if pid == 0:
    try:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", ${LOGIN_PTY_ROWS}, ${LOGIN_PTY_COLS}, 0, 0))
    except OSError:
        pass
    os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
try:
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", ${LOGIN_PTY_ROWS}, ${LOGIN_PTY_COLS}, 0, 0))
except OSError:
    pass
def stop(_signal, _frame):
    try: os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError: pass
    sys.exit(1)
signal.signal(signal.SIGTERM, stop)
while True:
    readable, _, _ = select.select([master, 0], [], [])
    if 0 in readable:
        data = os.read(0, 4096)
        if data: os.write(master, data)
        else: stop(None, None)
    if master in readable:
        try: data = os.read(master, 4096)
        except OSError as error:
            if error.errno == errno.EIO: break
            raise
        if not data: break
        os.write(1, data)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
`;

async function seedIsolatedOnboarding(home: string): Promise<void> {
  let file;
  try {
    file = await open(path.join(home, ".claude.json"), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  } catch {
    return;
  }
  try {
    await file.writeFile(`${JSON.stringify({ hasCompletedOnboarding: true })}\n`);
  } finally {
    await file.close();
  }
}

/** Run the same browser-code login used by sandbox connections on the local host. */
export function startLocalBrowserLogin(provider: "anthropic" | "openai" | "google", home: string): LocalBrowserLoginState {
  if (provider === "google") return startAntigravityBrowserLogin(home);
  const controller = new AbortController();
  const state: LocalBrowserLoginState = { abort: () => controller.abort() };
  const args = provider === "anthropic" ? ["setup-token"] : ["login", "--device-auth"];
  let child: ChildProcessWithoutNullStreams | null = null;
  const driver = {
    async start(_command: string, onData: (chunk: string) => void): Promise<{ exitCode: number | null }> {
      let executable = "claude";
      if (provider === "openai") {
        const legacyPlatform = !((process.platform === "linux" || process.platform === "darwin")
          && (process.arch === "x64" || process.arch === "arm64"));
        try {
          if (legacyPlatform) {
            await ensureCommandResolvable("codex", home, process.env);
            executable = path.resolve(home, await resolveCommandForLogs("codex", home, process.env));
          } else {
            executable = resolveCodexCommand();
          }
        } catch {
          state.error = legacyPlatform
            ? "Codex browser sign-in requires the Codex CLI on this platform. Install Codex on this execution host and ensure codex is on Paperclip's PATH, then start sign-in again."
            : "Codex browser sign-in requires an installed Codex CLI. Install Codex on this execution host or restore Paperclip's runtime dependencies, then start sign-in again.";
          throw new Error("Browser login runtime unavailable");
        }
      }
      if (controller.signal.aborted) throw new Error("Local sign-in cancelled before launch");
      // The theme screen is not the folder-trust check. Record only that the
      // isolated attempt home has finished onboarding. Never write a project
      // trust decision, a tool allow-list, or a permission bypass.
      if (provider === "anthropic") await seedIsolatedOnboarding(home);
      const env: NodeJS.ProcessEnv = { ...process.env,
        ANTHROPIC_API_KEY: "", ANTHROPIC_AUTH_TOKEN: "", CLAUDE_CODE_OAUTH_TOKEN: "",
        OPENAI_API_KEY: "", CODEX_API_KEY: "",
        CLAUDE_CONFIG_DIR: provider === "anthropic" ? home : process.env.CLAUDE_CONFIG_DIR,
        CODEX_HOME: provider === "openai" ? home : process.env.CODEX_HOME,
        BROWSER: "true",
      };
      // Claude waits for replies to terminal queries when TERM is set, and the
      // bridge never answers those queries. Leave TERM unset for this child.
      // The mouse hint is not a security prompt. Disabling mouse tracking stops
      // the builds that honor this variable from printing it. The parser still
      // accepts the hint when a build prints it anyway.
      if (provider === "anthropic") {
        delete env.TERM;
        delete env.COLORTERM;
        delete env.TMUX;
        delete env.TMUX_PANE;
        env.CLAUDE_CODE_DISABLE_MOUSE = "1";
      }
      return new Promise((resolve, reject) => {
        child = spawn("python3", ["-u", "-c", PYTHON_PTY_BRIDGE, executable, ...args], { env, stdio: ["pipe", "pipe", "pipe"] });
        child.stdout.on("data", (bytes: Buffer) => onData(bytes.toString("utf8")));
        // Provider output may contain secrets. Never log or retain stderr.
        child.stderr.resume();
        child.once("error", () => {
          state.error = "Browser sign-in requires Python 3 and a working local terminal. Install Python 3 on this execution host, then start sign-in again.";
          reject(new Error("Browser login terminal unavailable"));
        });
        child.once("close", (exitCode) => resolve({ exitCode }));
      });
    },
    write(input: string) { child?.stdin.write(input); },
    stop() { child?.kill("SIGTERM"); },
    async dispose() { child?.kill("SIGTERM"); },
    async readFile(file: string) { const { readLocalAiCredentialFile } = await import("./local-ai-credential-file.js"); return Buffer.from(await readLocalAiCredentialFile(file)); },
  };
  if (provider === "anthropic") {
    let deliverCode: ((code: string) => void) | undefined;
    const codeReady = new Promise<string>((resolve) => { deliverCode = resolve; });
    state.submitCode = (code) => { deliverCode?.(code); deliverCode = undefined; };
    void runSetupTokenLogin(driver, {
      timeoutMs: 300_000, signal: controller.signal,
      onPrompt: (prompt) => { state.authorizationUrl = prompt.url; },
      onBlocked: (blocker) => {
        state.error = blocker === "workspace_trust"
          ? "Claude Code is waiting on its folder trust check. Paperclip does not accept that check for you."
          : "Claude Code is waiting on its first-run setup screen. Paperclip does not answer that screen for you.";
        controller.abort();
      },
      provideCode: (signal) => new Promise<string>((resolve, reject) => {
        const abort = () => reject(new Error("Local sign-in cancelled"));
        if (signal.aborted) { abort(); return; }
        signal.addEventListener("abort", abort, { once: true });
        codeReady.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
      }),
      onCredential: async (bytes) => {
        const file = await open(path.join(home, ".credentials.json"),
          constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
        try {
          await file.writeFile(JSON.stringify({ claudeAiOauth: { accessToken: bytes.toString("utf8") } }));
        } finally {
          await file.close();
        }
      },
    }).then((result) => { state.outcome = result.outcome === "success" ? "success" : "failure"; })
      .catch(() => { state.outcome = "failure"; });
  } else {
    void runDeviceLogin(driver, {
      timeoutMs: 300_000, signal: controller.signal,
      onPrompt: (prompt) => { state.authorizationUrl = prompt.url; state.code = prompt.code; },
    }).then((result) => { state.outcome = result.outcome === "success" ? "success" : "failure"; })
      .catch(() => { state.outcome = "failure"; });
  }
  return state;
}
