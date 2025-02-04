local http         = require("resty.http")
local ssl          = require("ngx.ssl")
local ocsp         = require("ngx.ocsp")
local ngx          = ngx
local string       = string
local tostring     = tostring
local re_sub       = ngx.re.sub
local unpack       = unpack
local dns_lookup   = require("util.dns").lookup
local openssl_asn1 = require("resty.openssl.asn1")
local os           = os

local _M = {
  is_ocsp_stapling_enabled = false
}

local DEFAULT_CERT_HOSTNAME = "_"

local certificate_data    = ngx.shared.certificate_data
local certificate_servers = ngx.shared.certificate_servers
local ocsp_response_cache = ngx.shared.ocsp_response_cache

--------------------------------------------------------------------------------
-- Convert PEM certificate (and private key) to DER format.
--------------------------------------------------------------------------------
local function get_der_cert_and_priv_key(pem_cert_key)
  local der_cert, der_cert_err = ssl.cert_pem_to_der(pem_cert_key)
  if not der_cert then
    return nil, nil, "failed to convert certificate chain from PEM to DER: " .. der_cert_err
  end

  local der_priv_key, der_priv_key_err = ssl.priv_key_pem_to_der(pem_cert_key)
  if not der_priv_key then
    return nil, nil, "failed to convert private key from PEM to DER: " .. der_priv_key_err
  end

  return der_cert, der_priv_key, nil
end

--------------------------------------------------------------------------------
-- Set the certificate and key on the current connection.
--------------------------------------------------------------------------------
local function set_der_cert_and_key(der_cert, der_priv_key)
  local set_cert_ok, set_cert_err = ssl.set_der_cert(der_cert)
  if not set_cert_ok then
    return "failed to set DER cert: " .. set_cert_err
  end

  local set_priv_key_ok, set_priv_key_err = ssl.set_der_priv_key(der_priv_key)
  if not set_priv_key_ok then
    return "failed to set DER private key: " .. set_priv_key_err
  end
end

--------------------------------------------------------------------------------
-- Lookup the certificate UID for a given hostname (normalized to lowercase).
--------------------------------------------------------------------------------
local function get_pem_cert_uid(raw_hostname)
  local hostname = re_sub(raw_hostname, "\\.$", "", "jo"):gsub("[A-Z]", function(c)
    return c:lower()
  end)

  local uid = certificate_servers:get(hostname)
  if uid then
    return uid
  end

  local wildcard_hostname, _, err = re_sub(hostname, "^[^\\.]+\\.", "*.", "jo")
  if err then
    ngx.log(ngx.ERR, "error: ", err)
    return uid
  end

  if wildcard_hostname then
    uid = certificate_servers:get(wildcard_hostname)
  end

  return uid
end

--------------------------------------------------------------------------------
-- For now, return the global setting for OCSP stapling.
--------------------------------------------------------------------------------
local function is_ocsp_stapling_enabled_for(_)
  return _M.is_ocsp_stapling_enabled
end

--------------------------------------------------------------------------------
-- Resolve a URL using DNS lookup.
--------------------------------------------------------------------------------
local function get_resolved_url(parsed_url)
  local scheme, host, port, path = unpack(parsed_url)
  local ip = dns_lookup(host)[1]
  return string.format("%s://%s:%s%s", scheme, ip, port, path)
end

--------------------------------------------------------------------------------
-- Issue an OCSP request via HTTP.
--------------------------------------------------------------------------------
local function do_ocsp_request(url, ocsp_request)
  local httpc = http.new()
  httpc:set_timeout(1000, 1000, 2000)

  local parsed_url, err = httpc:parse_uri(url)
  if not parsed_url then
    return nil, err
  end

  local resolved_url = get_resolved_url(parsed_url)

  local http_response, req_err = httpc:request_uri(resolved_url, {
    method = "POST",
    headers = {
      ["Content-Type"] = "application/ocsp-request",
      ["Host"] = parsed_url[2],
    },
    body = ocsp_request,
    ssl_server_name = parsed_url[2],
  })
  if not http_response then
    return nil, req_err
  end
  if http_response.status ~= 200 then
    return nil, "unexpected OCSP responder status code: " .. tostring(http_response.status)
  end

  return http_response.body, nil
end

--------------------------------------------------------------------------------
--[[
  New helper functions using luaossl for OCSP response parsing.
  
  The OCSP response may be wrapped in a TLS CertificateStatus message:
    - 1 byte: CertificateStatusType (1 for OCSP, 2 for OCSP multi)
    - 3 bytes: 24-bit length (big-endian)
    - N bytes: DER-encoded OCSP response
  
  If not wrapped, the data is assumed to be a raw DER-encoded OCSP response.
]]--------------------------------------------------------------------------------

local function extract_ocsp_response(data)
  if #data < 4 then
    return data  -- too short; assume raw DER.
  end

  local status_type = data:byte(1)
  if status_type ~= 1 and status_type ~= 2 then
    return data  -- not wrapped as CertificateStatus.
  end

  local len = (data:byte(2) * 65536) + (data:byte(3) * 256) + data:byte(4)
  if #data ~= 4 + len then
    return data  -- length mismatch; assume raw DER.
  end

  if status_type ~= 1 then
    return nil, "unsupported CertificateStatusType: " .. status_type
  end

  return data:sub(5)
end

--------------------------------------------------------------------------------
-- Parse a time string into a Unix timestamp.
--
-- Supports both UTCTime (YYMMDDhhmmssZ, 13 characters) and
-- GeneralizedTime (YYYYMMDDhhmmssZ, 15 characters).
--------------------------------------------------------------------------------
local function parse_time_string(s)
  if #s == 13 then
    -- UTCTime format: YYMMDDhhmmssZ
    local year = tonumber(s:sub(1,2))
    local month = tonumber(s:sub(3,4))
    local day = tonumber(s:sub(5,6))
    local hour = tonumber(s:sub(7,8))
    local min = tonumber(s:sub(9,10))
    local sec = tonumber(s:sub(11,12))
    if not (year and month and day and hour and min and sec) then
      return nil, "failed to parse UTCTime string: " .. s
    end
    -- Per RFC5280: if year < 50 then year = 2000+year, else 1900+year.
    if year < 50 then
      year = year + 2000
    else
      year = year + 1900
    end
    local t = os.time({year = year, month = month, day = day, hour = hour, min = min, sec = sec})
    local utc_offset = os.difftime(os.time(), os.time(os.date("!*t")))
    return t - utc_offset
  elseif #s == 15 then
    -- GeneralizedTime format: YYYYMMDDhhmmssZ
    local year = tonumber(s:sub(1,4))
    local month = tonumber(s:sub(5,6))
    local day = tonumber(s:sub(7,8))
    local hour = tonumber(s:sub(9,10))
    local min = tonumber(s:sub(11,12))
    local sec = tonumber(s:sub(13,14))
    if not (year and month and day and hour and min and sec) then
      return nil, "failed to parse GeneralizedTime string: " .. s
    end
    local t = os.time({year = year, month = month, day = day, hour = hour, min = min, sec = sec})
    local utc_offset = os.difftime(os.time(), os.time(os.date("!*t")))
    return t - utc_offset
  else
    return nil, "unexpected time string format: " .. s
  end
end

--------------------------------------------------------------------------------
-- Use luaossl to decode the OCSP response and extract the nextUpdate timestamp.
--
-- Returns the Unix timestamp of nextUpdate or nil plus an error message.
--------------------------------------------------------------------------------
local function get_ocsp_next_update(ocsp_response)
  local ocsp_der, err = extract_ocsp_response(ocsp_response)
  if not ocsp_der then
    return nil, err
  end

  local ocsp_resp, decode_err = openssl_asn1.decode(ocsp_der)
  if not ocsp_resp then
    return nil, "failed to decode OCSP response: " .. (decode_err or "unknown error")
  end

  -- According to RFC2560, the OCSPResponse structure is:
  --   SEQUENCE {
  --     responseStatus         ENUMERATED,
  --     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
  --
  -- Extract the OCTET STRING that holds the DER-encoded BasicOCSPResponse.
  local basic_der = nil
  if ocsp_resp.value[2] and ocsp_resp.value[2].tag == "CONTEXT_SPECIFIC" then
    local rb = ocsp_resp.value[2]
    if rb.value and rb.value[1] and rb.value[1].tag == "SEQUENCE" and rb.value[1].value then
      if rb.value[1].value[2] then
        basic_der = rb.value[1].value[2].value
      end
    end
  end

  if not basic_der then
    return nil, "failed to extract BasicOCSPResponse DER data"
  end

  local basic_ocsp, basic_err = openssl_asn1.decode(basic_der)
  if not basic_ocsp then
    return nil, "failed to decode BasicOCSPResponse: " .. (basic_err or "unknown error")
  end

  -- Navigate the BasicOCSPResponse structure.
  -- BasicOCSPResponse ::= SEQUENCE {
  --    tbsResponseData,
  --    signatureAlgorithm,
  --    signature,
  --    [0] EXPLICIT certs OPTIONAL }
  local tbs = basic_ocsp.value[1]
  if not tbs or tbs.tag ~= "SEQUENCE" or not tbs.value then
    return nil, "tbsResponseData not found in BasicOCSPResponse"
  end

  -- tbsResponseData (ResponseData) structure (simplified):
  --   SEQUENCE {
  --     [0] EXPLICIT version OPTIONAL,
  --     responderID,
  --     producedAt,
  --     responses,  -- SEQUENCE OF SingleResponse
  --     [1] EXPLICIT responseExtensions OPTIONAL
  --   }
  --
  -- Determine the index of the responses element.
  local responses_node = nil
  if tbs.value[1] and tbs.value[1].tag == "CONTEXT_SPECIFIC" then
    responses_node = tbs.value[4]
  else
    responses_node = tbs.value[3]
  end

  if not responses_node or responses_node.tag ~= "SEQUENCE" or not responses_node.value then
    return nil, "responses field not found in tbsResponseData"
  end

  -- Get the first SingleResponse.
  local single_response = responses_node.value[1]
  if not single_response or single_response.tag ~= "SEQUENCE" or not single_response.value then
    return nil, "no SingleResponse found"
  end

  -- SingleResponse structure (simplified):
  --   SEQUENCE {
  --     certID,
  --     certStatus,
  --     thisUpdate,  -- GeneralizedTime or UTCTime
  --     nextUpdate    [0] EXPLICIT GeneralizedTime or UTCTime OPTIONAL,
  --     singleExtensions [1] EXPLICIT Extensions OPTIONAL
  --   }
  local next_update_node = single_response.value[4]
  if not next_update_node then
    return nil, "nextUpdate field not present in the SingleResponse"
  end

  -- If the nextUpdate field is wrapped explicitly, unwrap it.
  if next_update_node.tag == "CONTEXT_SPECIFIC" and next_update_node.value then
    next_update_node = next_update_node.value[1]
  end

  if not next_update_node or (next_update_node.tag ~= "GENERALIZEDTIME" and next_update_node.tag ~= "UTCTIME") then
    return nil, "unexpected format for nextUpdate field"
  end

  local time_str = next_update_node.value
  if type(time_str) ~= "string" then
    return nil, "nextUpdate value is not a string"
  end

  return parse_time_string(time_str)
end

--------------------------------------------------------------------------------
-- Fetch and cache a new OCSP response.
--
-- This function:
--   1. Extracts the OCSP responder URL from the DER certificate.
--   2. Creates an OCSP request.
--   3. Fetches the OCSP response.
--   4. Validates it.
--   5. Uses luaossl to extract the nextUpdate timestamp and calculates a dynamic cache expiry.
--------------------------------------------------------------------------------
local function fetch_and_cache_ocsp_response(uid, der_cert)
  local url, err = ocsp.get_ocsp_responder_from_der_chain(der_cert)
  if not url and err then
    ngx.log(ngx.ERR, "could not extract OCSP responder URL: ", err)
    return
  end
  if not url and not err then
    ngx.log(ngx.DEBUG, "no OCSP responder URL returned")
    return
  end

  local request, req_err = ocsp.create_ocsp_request(der_cert)
  if not request then
    ngx.log(ngx.ERR, "could not create OCSP request: ", req_err)
    return
  end

  local ocsp_response, req_err = do_ocsp_request(url, request)
  if req_err then
    ngx.log(ngx.ERR, "could not get OCSP response: ", req_err)
    return
  end
  if not ocsp_response or #ocsp_response == 0 then
    ngx.log(ngx.ERR, "OCSP responder returned an empty response")
    return
  end

  local ok, validation_err = ocsp.validate_ocsp_response(ocsp_response, der_cert)
  if not ok then
    ngx.log(ngx.NOTICE, "OCSP response validation failed: ", validation_err)
    return
  end

  -- Use luaossl to extract the nextUpdate timestamp.
  local next_update, time_err = get_ocsp_next_update(ocsp_response)
  if not next_update then
    ngx.log(ngx.ERR, "failed to extract nextUpdate from OCSP response: ", time_err)
    return
  end

  local current_time = ngx.time()
  local grace_time   = 300  -- 5 minutes in seconds
  local expiry       = next_update - current_time - grace_time

  if expiry <= 0 then
    ngx.log(ngx.ERR, "OCSP response is expired or too close to expiry, not caching")
    return
  end

  local success, set_err, forcible = ocsp_response_cache:set(uid, ocsp_response, expiry)
  if not success then
    ngx.log(ngx.ERR, "failed to cache OCSP response: ", set_err)
  end
  if forcible then
    ngx.log(ngx.NOTICE, "removed an existing item when saving OCSP response; consider increasing shared dictionary size for 'ocsp_response_cache'")
  end
end

--------------------------------------------------------------------------------
-- Try to use a cached OCSP response. If missing or stale, refresh in background.
--------------------------------------------------------------------------------
local function ocsp_staple(uid, der_cert)
  local response, flags, is_stale = ocsp_response_cache:get_stale(uid)
  if not response or is_stale then
    ngx.timer.at(0, function()
      fetch_and_cache_ocsp_response(uid, der_cert)
    end)
    return false, nil
  end

  local ok, err = ocsp.set_ocsp_status_resp(response)
  if not ok then
    return false, err
  end

  return true, nil
end

--------------------------------------------------------------------------------
-- Determine if a certificate is configured for the current request.
--------------------------------------------------------------------------------
function _M.configured_for_current_request()
  if ngx.ctx.cert_configured_for_current_request == nil then
    ngx.ctx.cert_configured_for_current_request = get_pem_cert_uid(ngx.var.host) ~= nil
  end

  return ngx.ctx.cert_configured_for_current_request
end

--------------------------------------------------------------------------------
-- Main entry point for dynamically configuring the certificate and optionally stapling OCSP.
--------------------------------------------------------------------------------
function _M.call()
  local hostname, hostname_err = ssl.server_name()
  if hostname_err then
    ngx.log(ngx.ERR, "error while obtaining hostname: " .. hostname_err)
  end
  if not hostname then
    ngx.log(ngx.INFO, "obtained hostname is nil (the client does not support SNI?), falling back to default certificate")
    hostname = DEFAULT_CERT_HOSTNAME
  end

  local pem_cert
  local pem_cert_uid = get_pem_cert_uid(hostname)
  if not pem_cert_uid then
    pem_cert_uid = get_pem_cert_uid(DEFAULT_CERT_HOSTNAME)
  end
  if pem_cert_uid then
    pem_cert = certificate_data:get(pem_cert_uid)
  end
  if not pem_cert then
    ngx.log(ngx.ERR, "certificate not found, falling back to fake certificate for hostname: " .. tostring(hostname))
    return
  end

  local clear_ok, clear_err = ssl.clear_certs()
  if not clear_ok then
    ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates: " .. clear_err)
    return ngx.exit(ngx.ERROR)
  end

  local der_cert, der_priv_key, der_err = get_der_cert_and_priv_key(pem_cert)
  if der_err then
    ngx.log(ngx.ERR, der_err)
    return ngx.exit(ngx.ERROR)
  end

  local set_der_err = set_der_cert_and_key(der_cert, der_priv_key)
  if set_der_err then
    ngx.log(ngx.ERR, set_der_err)
    return ngx.exit(ngx.ERROR)
  end

  if is_ocsp_stapling_enabled_for(pem_cert_uid) then
    local _, stapling_err = ocsp_staple(pem_cert_uid, der_cert)
    if stapling_err then
      ngx.log(ngx.ERR, "error during OCSP stapling: ", stapling_err)
    end
  end
end

return _M
