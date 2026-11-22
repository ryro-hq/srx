'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');

async function prepare(root) {
  const fixture = process.env.SRX_LSP_FIXTURE;
  assert(fixture, 'SRX_LSP_FIXTURE must point to the shared editor fixture');
  await fs.cp(path.join(fixture, 'project'), root, { recursive: true });
  return JSON.parse(await fs.readFile(path.join(fixture, 'case.json'), 'utf8'));
}

async function withProject(prefix, run) {
  const temp = await fs.mkdtemp(path.join(tmpdir(), prefix));
  try {
    const project = path.join(temp, 'project');
    const cases = await prepare(project);
    await run(project, cases, temp);
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
}

function position(text, { needle, offset }) {
  const start = text.indexOf(needle);
  assert.notEqual(start, -1, `missing fixture marker: ${needle}`);
  const before = text.slice(0, start + offset).split('\n');
  return { line: before.length - 1, character: before.at(-1).length };
}

module.exports = { position, withProject };
