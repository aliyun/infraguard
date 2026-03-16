"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const vscode = __importStar(require("vscode"));
const node_1 = require("vscode-languageclient/node");
let client;
const OUTPUT_CHANNEL_NAME = 'InfraGuard';
const PLATFORM_MAP = {
    'linux-x64': 'linux-x64',
    'darwin-x64': 'darwin-x64',
    'darwin-arm64': 'darwin-arm64',
    'win32-x64': 'win32-x64',
};
function resolveLspBinary(context) {
    const ext = process.platform === 'win32' ? '.exe' : '';
    const singleBinary = context.asAbsolutePath(path.join('bin', `infraguard${ext}`));
    if (fs.existsSync(singleBinary)) {
        return singleBinary;
    }
    const platformKey = `${process.platform}-${process.arch === 'arm64' ? 'arm64' : 'x64'}`;
    const mapped = PLATFORM_MAP[platformKey];
    if (mapped) {
        const platformBinary = context.asAbsolutePath(path.join('bin', `infraguard-${mapped}${ext}`));
        if (fs.existsSync(platformBinary)) {
            return platformBinary;
        }
    }
    return undefined;
}
function activate(context) {
    const outputChannel = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
    outputChannel.appendLine('[InfraGuard] Extension activating...');
    const serverCommand = resolveLspBinary(context) ?? 'infraguard';
    outputChannel.appendLine(`[InfraGuard] Using LSP command: ${serverCommand}`);
    const serverOptions = {
        command: serverCommand,
        args: ['lsp'],
        transport: node_1.TransportKind.stdio,
    };
    const clientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'ros-template-yaml' },
            { scheme: 'file', language: 'ros-template-json' },
            { scheme: 'file', language: 'yaml' },
            { scheme: 'file', language: 'json' },
        ],
        initializationOptions: {
            locale: vscode.env.language,
        },
        outputChannel,
    };
    client = new node_1.LanguageClient('infraguard', OUTPUT_CHANNEL_NAME, serverOptions, clientOptions);
    client.start().then(() => outputChannel.appendLine('[InfraGuard] LSP client started.'), (err) => {
        outputChannel.appendLine(`[InfraGuard] LSP failed to start: ${err?.message ?? err}`);
        outputChannel.show(true);
    });
    const schemaUpdateCommand = vscode.commands.registerCommand('infraguard.schemaUpdate', async () => {
        const terminal = vscode.window.createTerminal('InfraGuard Schema Update');
        terminal.sendText(`"${serverCommand}" schema update`);
        terminal.show();
    });
    context.subscriptions.push(schemaUpdateCommand);
}
function deactivate() {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
//# sourceMappingURL=extension.js.map