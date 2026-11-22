local fixture = assert(vim.env.SRX_LSP_FIXTURE, "set SRX_LSP_FIXTURE")
local cases = vim.json.decode(table.concat(vim.fn.readfile(fixture .. "/case.json"), "\n"))
local root = vim.fn.tempname()

local function run()
  local project = fixture .. "/project"
  for _, input in ipairs(vim.fn.globpath(project, "**/*.srx", false, true)) do
    local output = root .. input:sub(#project + 1)
    vim.fn.mkdir(vim.fs.dirname(output), "p")
    assert(vim.uv.fs_copyfile(input, output))
  end

  vim.opt.runtimepath:prepend(vim.fn.getcwd())
  require("syrox").setup({ cmd = { assert(vim.env.SRX_BIN), "lsp" } })
  vim.cmd.edit(vim.fn.fnameescape(root .. "/main.srx"))
  local buffer = vim.api.nvim_get_current_buf()
  assert(vim.bo[buffer].filetype == "syrox")

  local client
  assert(vim.wait(10000, function()
    client = vim.lsp.get_clients({ bufnr = buffer, name = "syrox" })[1]
    return client and client.initialized
  end), "Syrox LSP did not attach")
  local uri = vim.uri_from_bufnr(buffer)
  local lines = vim.api.nvim_buf_get_lines(buffer, 0, -1, false)
  -- Fixture markers are ASCII, so byte and UTF-16 columns agree.
  local function find(needle)
    for index, line in ipairs(lines) do
      local column = line:find(needle, 1, true)
      if column then return index - 1, column - 1 end
    end
    error("missing fixture marker: " .. needle)
  end
  local function request(method, marker)
    local line, character = find(marker.needle)
    local reply, err = client:request_sync("textDocument/" .. method, {
      textDocument = { uri = uri },
      position = { line = line, character = character + marker.offset },
    }, 5000, buffer)
    assert(reply, vim.inspect(err))
    assert(not reply.err, vim.inspect(reply.err))
    return reply.result
  end

  local completion = request("completion", cases.completion)
  for _, label in ipairs(cases.completion.labels) do
    assert(vim.iter(completion.items):any(function(item) return item.label == label end), label)
  end
  local definition = request("definition", cases.definition)
  assert(definition.uri == vim.uri_from_fname(root .. "/" .. cases.definition.file), vim.inspect(definition))
  local virtual = request("definition", cases.virtualSource)
  assert(virtual.uri:match("^syrox%-source:"))
  assert(vim.lsp.util.show_document(virtual, client.offset_encoding, { focus = true }), "open virtual std")
  assert(vim.bo.readonly and not vim.bo.modifiable, "virtual std must be read-only")
  assert(table.concat(vim.api.nvim_buf_get_lines(0, 0, -1, false), "\n"):find(cases.virtualSource.text, 1, true))

  vim.api.nvim_set_current_buf(buffer)
  local row, column = find(cases.diagnostic.before)
  vim.api.nvim_buf_set_text(buffer, row, column, row, column + #cases.diagnostic.before, { cases.diagnostic.after })
  assert(vim.wait(10000, function()
    return vim.iter(vim.diagnostic.get(buffer)):any(function(item)
      return item.code == "srx.type-check" and item.message:find(cases.diagnostic.text, 1, true)
    end)
  end), "missing semantic diagnostic")
  vim.api.nvim_buf_set_lines(buffer, 0, -1, false, lines)
  assert(vim.wait(10000, function() return #vim.diagnostic.get(buffer) == 0 end), "stale diagnostic")

  assert(client:supports_method("textDocument/formatting"))
  vim.lsp.buf.format({ bufnr = buffer, id = client.id, timeout_ms = 5000 })
  assert(vim.tbl_contains(vim.api.nvim_buf_get_lines(buffer, 0, -1, false), cases.formattedLine), "document was not formatted")
  print("Neovim: diagnostics, completion, navigation, formatting and virtual std passed")
end

local ok, err = xpcall(run, debug.traceback)
for _, client in ipairs(vim.lsp.get_clients({ name = "syrox" })) do client:stop(true) end
vim.fn.delete(root, "rf")
if not ok then vim.api.nvim_err_writeln(err); vim.cmd("cquit 1") else vim.cmd("qa!") end
