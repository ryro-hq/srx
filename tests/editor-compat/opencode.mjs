import { strict as assert } from 'node:assert'
import { readFile, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { position, withProject } from './support.cjs'

// Exercise the plugin's public tools with a real srx subprocess; the client
// repository's test:host separately checks registration in the packaged host.
const { default: plugin } = await import(pathToFileURL(resolve('index.ts')).href)
assert(process.env.SRX_BIN, 'SRX_BIN must point to the candidate')
process.env.SYROX_LSP_BIN = process.env.SRX_BIN

await withProject('srx-opencode-compat-', async (root, cases) => {
  const tools = new Map()
  const close = await plugin.setup({
    location: { directory: root },
    tool: { transform: callback => callback({
      namespace() {},
      add(tool) { tools.set(tool.name, tool) },
      get() {},
    }) },
  })
  const context = { signal: AbortSignal.timeout(30_000) }
  const path = 'main.srx'
  const file = join(root, path)
  const text = await readFile(file, 'utf8')
  const call = async (name, input) => JSON.parse((await tools.get(name).execute(input, context)).content)
  const at = marker => {
    const { line, character } = position(text, marker)
    return { path, line: line + 1, character: character + 1 }
  }
  try {
    assert.deepEqual(await call('diagnostics', { path }), [])
    const completion = await call('completion', at(cases.completion))
    for (const label of cases.completion.labels) {
      assert(completion.items.some(item => item.label === label), `missing completion: ${label}`)
    }
    const definition = await call('definition', at(cases.definition))
    assert.equal(definition.uri, pathToFileURL(join(root, cases.definition.file)).href)
    const virtual = await call('definition', at(cases.virtualSource))
    assert.match(virtual.uri, /^syrox-source:/)
    assert((await call('source', { uri: virtual.uri })).text.includes(cases.virtualSource.text))

    await writeFile(file, text.replace(cases.diagnostic.before, cases.diagnostic.after))
    const diagnostics = await call('diagnostics', { path })
    assert(diagnostics.some(item => item.code === 'srx.type-check' && item.message.includes(cases.diagnostic.text)))
    await writeFile(file, text)
    assert.deepEqual(await call('diagnostics', { path }), [])
  } finally {
    close()
  }
})
console.log('OpenCode tools: diagnostics, completion, navigation and virtual std passed')
