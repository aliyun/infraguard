import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import {
	LanguageClient,
	LanguageClientOptions,
	ServerOptions,
	TransportKind,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;

const OUTPUT_CHANNEL_NAME = 'InfraGuard';

const PLATFORM_MAP: Record<string, string> = {
	'linux-x64': 'linux-x64',
	'darwin-x64': 'darwin-x64',
	'darwin-arm64': 'darwin-arm64',
	'win32-x64': 'win32-x64',
};

function resolveLspBinary(context: vscode.ExtensionContext): string | undefined {
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

export function activate(context: vscode.ExtensionContext) {
	const outputChannel = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
	outputChannel.appendLine('[InfraGuard] Extension activating...');

	const serverCommand = resolveLspBinary(context) ?? 'infraguard';
	outputChannel.appendLine(`[InfraGuard] Using LSP command: ${serverCommand}`);

	const serverOptions: ServerOptions = {
		command: serverCommand,
		args: ['lsp'],
		transport: TransportKind.stdio,
	};

	const clientOptions: LanguageClientOptions = {
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

	client = new LanguageClient(
		'infraguard',
		OUTPUT_CHANNEL_NAME,
		serverOptions,
		clientOptions
	);

	client.start().then(
		() => outputChannel.appendLine('[InfraGuard] LSP client started.'),
		(err) => {
			outputChannel.appendLine(`[InfraGuard] LSP failed to start: ${err?.message ?? err}`);
			outputChannel.show(true);
		}
	);

	const schemaUpdateCommand = vscode.commands.registerCommand(
		'infraguard.schemaUpdate',
		async () => {
			const terminal = vscode.window.createTerminal('InfraGuard Schema Update');
			terminal.sendText(`"${serverCommand}" schema update`);
			terminal.show();
		}
	);

	context.subscriptions.push(schemaUpdateCommand);
}

export function deactivate(): Thenable<void> | undefined {
	if (!client) {
		return undefined;
	}
	return client.stop();
}
