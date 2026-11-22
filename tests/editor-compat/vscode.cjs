'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { createRequire } = require('node:module');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { position, withProject } = require('./support.cjs');

const version = '1.90.2';

async function launch() {
  assert(process.env.SRX_BIN, 'SRX_BIN must point to the candidate');
  const checkout = process.cwd();
  const requireClient = createRequire(path.join(checkout, 'package.json'));
  const { runTests } = requireClient('@vscode/test-electron');
  await withProject('srx-vscode-compat-', async (project, cases, temp) => {
    await fs.mkdir(path.join(project, '.vscode'));
    await fs.writeFile(path.join(project, '.vscode/settings.json'), JSON.stringify({
      'syrox.serverPath': process.env.SRX_BIN,
    }));
    await runTests({
      version,
      vscodeExecutablePath: process.env.VSCODE_TEST_EXECUTABLE,
      extensionDevelopmentPath: checkout,
      extensionTestsPath: __filename,
      extensionTestsEnv: { SRX_LSP_CASE: JSON.stringify(cases) },
      launchArgs: [project, '--disable-gpu',
        '--user-data-dir', path.join(temp, 'user'), '--extensions-dir', path.join(temp, 'extensions')],
    });
  });
}

async function waitFor(probe, description) {
  const deadline = Date.now() + 15000;
  do {
    const result = await probe();
    if (result) return result;
    await delay(100);
  } while (Date.now() < deadline);
  assert.fail(description);
}

async function run() {
  const vscode = require('vscode');
  assert.equal(vscode.version, version, 'unexpected Extension Host version');
  const cases = JSON.parse(process.env.SRX_LSP_CASE);
  const workspace = vscode.workspace.workspaceFolders[0].uri;
  const uri = vscode.Uri.joinPath(workspace, 'main.srx');
  const document = await vscode.workspace.openTextDocument(uri);
  assert.equal(document.languageId, 'syrox');
  const editor = await vscode.window.showTextDocument(document);
  await vscode.extensions.getExtension('ryro-hq.syrox').activate();
  const text = document.getText();
  const at = marker => {
    const { line, character } = position(text, marker);
    return new vscode.Position(line, character);
  };
  const query = (command, marker) => vscode.commands.executeCommand(command, uri, at(marker));
  await waitFor(async () => {
    const result = await query('vscode.executeCompletionItemProvider', cases.completion);
    return cases.completion.labels.every(label => result?.items.some(item => (item.label.label ?? item.label) === label));
  }, 'missing typed YAML field completions');

  const definition = async marker => {
    const [result] = await query('vscode.executeDefinitionProvider', marker);
    assert(result, `missing definition: ${marker.needle}`);
    return result.targetUri ?? result.uri;
  };
  assert.equal((await definition(cases.definition)).toString(), vscode.Uri.joinPath(workspace, cases.definition.file).toString());
  const virtual = await definition(cases.virtualSource);
  assert.equal(virtual.scheme, 'syrox-source');
  assert((await vscode.workspace.openTextDocument(virtual)).getText().includes(cases.virtualSource.text));

  const diagnostics = () => vscode.languages.getDiagnostics(uri).filter(item => item.source === 'syrox');
  assert.deepEqual(diagnostics(), []);
  const start = at({ needle: cases.diagnostic.before, offset: 0 });
  const range = new vscode.Range(start, start.translate(0, cases.diagnostic.before.length));
  assert(await editor.edit(edit => edit.replace(range, cases.diagnostic.after)));
  await waitFor(() => diagnostics().some(item => item.code === 'srx.type-check' && item.message.includes(cases.diagnostic.text)),
    'missing semantic diagnostic');
  assert(await editor.edit(edit => edit.replace(new vscode.Range(start, start.translate(0, cases.diagnostic.after.length)), cases.diagnostic.before)));
  await waitFor(() => diagnostics().length === 0, 'stale diagnostic');

  const format = () => vscode.commands.executeCommand('vscode.executeFormatDocumentProvider', uri, { tabSize: 4, insertSpaces: true });
  const edits = await format();
  assert(edits?.length, 'missing document formatting edit');
  assert(await editor.edit(edit => edits.forEach(change => edit.replace(change.range, change.newText))));
  assert(document.getText().split('\n').includes(cases.formattedLine));
  assert.equal((await format())?.length ?? 0, 0, 'formatting must be idempotent');
  console.log('VS Code Extension Host: diagnostics, completion, navigation, formatting and virtual std passed');
}

module.exports = { run };
if (require.main === module) launch().catch(error => { console.error(error); process.exitCode = 1; });
