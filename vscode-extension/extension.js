const vscode = require("vscode");
const fs = require("fs");
const path = require("path");
const os = require("os");

const MUXER_HOME = path.join(os.homedir(), ".dotnet-muxer");
const DOTNET_DIR = path.join(MUXER_HOME, "dotnet");
const WORKSPACES_DIR = path.join(MUXER_HOME, "workspaces");
const PID_FILE = path.join(WORKSPACES_DIR, process.pid.toString());

function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err && err.code === "EPERM";
  }
}

function pruneOrphanWorkspaceFiles() {
  let removed = 0;
  let entries = [];
  try {
    entries = fs.readdirSync(WORKSPACES_DIR, { withFileTypes: true });
  } catch {
    return removed;
  }

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const pid = Number.parseInt(entry.name, 10);
    if (!Number.isInteger(pid)) continue;
    if (pid === process.pid) continue;
    if (isPidAlive(pid)) continue;

    try {
      fs.unlinkSync(path.join(WORKSPACES_DIR, entry.name));
      removed += 1;
    } catch {}
  }

  return removed;
}

function getWorkspacePath() {
  const folders = vscode.workspace.workspaceFolders;
  return folders && folders.length > 0 ? folders[0].uri.fsPath : null;
}

function registerWorkspace() {
  const ws = getWorkspacePath();
  if (!ws) return;
  if (!fs.existsSync(path.join(ws, ".dotnet", "dotnet"))) return;
  fs.mkdirSync(WORKSPACES_DIR, { recursive: true });
  fs.writeFileSync(PID_FILE, ws);
}

function installMuxerBinary() {
  fs.mkdirSync(DOTNET_DIR, { recursive: true });

  const platform = os.platform();
  const arch = os.arch();
  let binaryName;
  if (platform === "win32") {
    binaryName = `dotnet-${arch}-windows.exe`;
  } else if (platform === "darwin") {
    binaryName = `dotnet-${arch}-darwin`;
  } else {
    binaryName = `dotnet-${arch}-linux`;
  }

  const src = path.join(__dirname, "bin", binaryName);
  const dest = path.join(DOTNET_DIR, platform === "win32" ? "dotnet.exe" : "dotnet");

  if (!fs.existsSync(src)) {
    vscode.window.showWarningMessage(
      `dotnet-muxer: No pre-built binary for ${platform}-${arch}. Build manually and place in ${DOTNET_DIR}.`
    );
    return;
  }

  fs.copyFileSync(src, dest);
  fs.chmodSync(dest, 0o755);
}

function ensurePath() {
  if (os.platform() === "win32") return; // TODO: Windows PATH handling

  const marker = "# dotnet-muxer";
  const exportLine = `export PATH="${DOTNET_DIR}:$PATH" ${marker}`;

  const shell = process.env.SHELL || "/bin/bash";
  const rcFile = shell.includes("zsh")
    ? path.join(os.homedir(), ".zshrc")
    : path.join(os.homedir(), ".bashrc");

  let content = "";
  try { content = fs.readFileSync(rcFile, "utf8"); } catch {}

  if (content.includes(marker)) return;

  fs.appendFileSync(rcFile, `\n${exportLine}\n`);
  vscode.window.showInformationMessage(
    `dotnet-muxer: Added ${DOTNET_DIR} to PATH in ${path.basename(rcFile)}. Restart your terminal for it to take effect.`
  );
}

function activate(context) {
  pruneOrphanWorkspaceFiles();

  const pruneCommand = vscode.commands.registerCommand(
    "dotnet-muxer.pruneWorkspaceFiles",
    () => {
      const removed = pruneOrphanWorkspaceFiles();
      vscode.window.showInformationMessage(
        `dotnet-muxer: Pruned ${removed} orphaned workspace file(s).`
      );
    }
  );
  context.subscriptions.push(pruneCommand);

  const installed = context.globalState.get("installed", false);
  if (!installed) {
    installMuxerBinary();
    ensurePath();
    context.globalState.update("installed", true);
  }

  registerWorkspace();
  const workspaceChange = vscode.workspace.onDidChangeWorkspaceFolders(() => registerWorkspace());
  context.subscriptions.push(workspaceChange);
}

function deactivate() {
  try { fs.unlinkSync(PID_FILE); } catch {}
  pruneOrphanWorkspaceFiles();
}

module.exports = { activate, deactivate };
