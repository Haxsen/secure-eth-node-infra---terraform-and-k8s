-- ---------------------------------------------------------------------------
-- rpc_guard: authentication + JSON-RPC firewall for the public Ethereum RPC.
--
--  * API keys are stored only as SHA-256 hashes (Secrets Manager -> CSI file),
--    hot-reloaded every 30s so revocation needs no restart.
--  * Default-deny method allowlist: no admin_/debug_/personal_/miner_/txpool_/
--    engine_ namespaces, no account-signing methods.
--  * Batch size cap, JSON nesting-depth cap, eth_getLogs block-range cap.
--  * Fails closed: if keys cannot be loaded, every request is rejected and
--    /healthz reports 503 so the ALB stops routing to this pod.
--
-- Phase split matters: nginx runs rewrite -> preaccess (limit_req) -> access.
-- identify() runs in rewrite and only *labels* the request with its key name
-- so the per-key limit can use it; enforce() rejects in access, i.e. AFTER the
-- per-IP limit, so failed-auth floods (key brute force) are rate limited too.
-- ---------------------------------------------------------------------------
local cjson = require("cjson.safe")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

local _M = {}

local API_KEYS_FILE = "/secrets/api-keys.json"
local RELOAD_INTERVAL_S = 30
local MAX_BATCH = 20
local MAX_LOG_BLOCK_RANGE = 5000
local MAX_API_KEY_LEN = 128
local MAX_JSON_DEPTH = 16

local ALLOWED_METHODS = {
  eth_blobBaseFee = true,
  eth_blockNumber = true,
  eth_call = true,
  eth_chainId = true,
  eth_estimateGas = true,
  eth_feeHistory = true,
  eth_gasPrice = true,
  eth_getBalance = true,
  eth_getBlockByHash = true,
  eth_getBlockByNumber = true,
  eth_getBlockReceipts = true,
  eth_getBlockTransactionCountByHash = true,
  eth_getBlockTransactionCountByNumber = true,
  eth_getCode = true,
  eth_getLogs = true,
  eth_getProof = true,
  eth_getStorageAt = true,
  eth_getTransactionByBlockHashAndIndex = true,
  eth_getTransactionByBlockNumberAndIndex = true,
  eth_getTransactionByHash = true,
  eth_getTransactionCount = true,
  eth_getTransactionReceipt = true,
  eth_maxPriorityFeePerGas = true,
  eth_sendRawTransaction = true,
  eth_syncing = true,
  net_listening = true,
  net_version = true,
  web3_clientVersion = true,
  web3_sha3 = true,
}

-- Per-worker state; each worker reloads independently (the file is tiny).
local api_keys = {}
local api_keys_loaded = false
local api_keys_digest = nil

-- ---------------------------------------------------------------------------
-- helpers
-- ---------------------------------------------------------------------------

local function sha256_hex(s)
  local h = resty_sha256:new()
  h:update(s)
  return resty_string.to_hex(h:final())
end

-- Terminate the request with a JSON-RPC 2.0 error body.
local function reject(status, code, message, id)
  ngx.status = status
  ngx.header["Content-Type"] = "application/json"
  ngx.say(cjson.encode({
    jsonrpc = "2.0",
    id = id == nil and cjson.null or id,
    error = { code = code, message = message },
  }))
  return ngx.exit(ngx.HTTP_OK)
end

local function load_api_keys()
  local f, err = io.open(API_KEYS_FILE, "r")
  if not f then
    ngx.log(ngx.ERR, "rpc_guard: cannot open API key file: ", err)
    return
  end
  local raw = f:read("*a")
  f:close()

  local digest = sha256_hex(raw)
  if digest == api_keys_digest then
    return
  end

  local decoded = cjson.decode(raw)
  if type(decoded) ~= "table" or getmetatable(decoded) == cjson.array_mt then
    ngx.log(ngx.ERR, "rpc_guard: API key file is not a JSON object; keeping previous keys")
    return
  end

  local fresh, n = {}, 0
  for hash, name in pairs(decoded) do
    if type(hash) == "string" and #hash == 64 and hash:match("^%x+$") and type(name) == "string" then
      fresh[hash:lower()] = name:sub(1, 64)
      n = n + 1
    else
      ngx.log(ngx.WARN, "rpc_guard: ignoring malformed API key entry")
    end
  end

  api_keys = fresh
  api_keys_loaded = true
  api_keys_digest = digest
  ngx.log(ngx.NOTICE, "rpc_guard: loaded ", n, " API key hash(es)")
end

local function parse_block_number(tag)
  if type(tag) ~= "string" then
    return nil
  end
  if #tag > 2 and #tag <= 18 and tag:match("^0x%x+$") then
    return tonumber(tag:sub(3), 16)
  end
  return nil
end

-- eth_getLogs over huge ranges is the classic way to pin a node's CPU/IO.
local function check_get_logs(params)
  if type(params) ~= "table" then
    return true
  end
  local filter = params[1]
  if type(filter) ~= "table" or filter.blockHash ~= nil then
    return true
  end
  if filter.fromBlock == "earliest" then
    return false, "eth_getLogs from 'earliest' is not allowed; use a bounded block range"
  end
  local from_n, to_n = parse_block_number(filter.fromBlock), parse_block_number(filter.toBlock)
  if from_n and to_n then
    if to_n < from_n then
      return false, "eth_getLogs toBlock is before fromBlock"
    end
    if to_n - from_n > MAX_LOG_BLOCK_RANGE then
      return false, "eth_getLogs block range exceeds " .. MAX_LOG_BLOCK_RANGE .. " blocks"
    end
  end
  -- Tag-relative ranges ("latest", "safe", ...) are bounded by geth --rpc.rangelimit.
  return true
end

-- Returns ok, http_status, jsonrpc_code, message
local function validate_call(call)
  if type(call) ~= "table" or getmetatable(call) == cjson.array_mt then
    return false, 400, -32600, "invalid request"
  end
  if call.jsonrpc ~= "2.0" or type(call.method) ~= "string" then
    return false, 400, -32600, "invalid request: jsonrpc must be \"2.0\" and method a string"
  end
  if not ALLOWED_METHODS[call.method] then
    return false, 403, -32601, "method not allowed: " .. call.method:sub(1, 64)
  end
  if call.method == "eth_getLogs" then
    local ok, why = check_get_logs(call.params)
    if not ok then
      return false, 400, -32005, why
    end
  end
  return true
end

-- ---------------------------------------------------------------------------
-- phase handlers
-- ---------------------------------------------------------------------------

function _M.init()
  cjson.decode_max_depth(MAX_JSON_DEPTH)
  cjson.decode_array_with_array_mt(true)
end

function _M.init_worker()
  load_api_keys()
  local ok, err = ngx.timer.every(RELOAD_INTERVAL_S, function(premature)
    if not premature then
      load_api_keys()
    end
  end)
  if not ok then
    ngx.log(ngx.ERR, "rpc_guard: failed to schedule API key reload: ", err)
  end
end

function _M.healthz()
  if api_keys_loaded then
    ngx.say('{"status":"ok"}')
  else
    ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
    ngx.say('{"status":"api keys not loaded"}')
  end
end

-- rewrite phase: label the request with the tenant name; never reject here.
function _M.identify()
  local key = ngx.var.http_x_api_key
  if type(key) ~= "string" or key == "" or #key > MAX_API_KEY_LEN then
    return
  end
  local name = api_keys[sha256_hex(key)]
  if name then
    ngx.var.api_key_name = name
  end
end

-- access phase (after per-IP and per-key limit_req): authn + JSON-RPC firewall.
function _M.enforce()
  if not api_keys_loaded then
    return reject(503, -32603, "gateway not ready")
  end
  if ngx.var.api_key_name == "" then
    if not ngx.var.http_x_api_key then
      return reject(401, -32001, "missing X-Api-Key header")
    end
    return reject(401, -32001, "invalid API key")
  end

  if ngx.req.get_method() ~= "POST" then
    ngx.header["Allow"] = "POST"
    return reject(405, -32600, "only POST is supported")
  end

  local ctype = ngx.var.content_type
  if not ctype or not ctype:lower():find("application/json", 1, true) then
    return reject(415, -32600, "Content-Type must be application/json")
  end

  ngx.req.read_body()
  local body = ngx.req.get_body_data()
  if not body then
    -- Empty, or larger than client_body_buffer_size and spooled to disk.
    return reject(400, -32600, "empty or oversized request body")
  end

  local payload = cjson.decode(body)
  if type(payload) ~= "table" then
    return reject(400, -32700, "parse error")
  end

  local calls
  if getmetatable(payload) == cjson.array_mt then
    if #payload == 0 then
      return reject(400, -32600, "empty batch")
    end
    if #payload > MAX_BATCH then
      return reject(400, -32600, "batch exceeds " .. MAX_BATCH .. " calls")
    end
    calls = payload
  else
    calls = { payload }
  end

  local methods = {}
  for i, call in ipairs(calls) do
    local ok, status, code, msg = validate_call(call)
    if not ok then
      local id = (#calls == 1 and type(call) == "table") and call.id or nil
      return reject(status, code, msg, id)
    end
    methods[i] = call.method
  end

  ngx.var.rpc_methods = table.concat(methods, ","):sub(1, 256)
end

return _M
