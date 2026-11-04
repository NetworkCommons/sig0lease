-- D5's XMPP server (docs/demo.md), run by demo/chat.sh, natively or in the prosodyim/prosody:13.0
-- container, with the CHAT_* environment variables it sets. It serves guests at CHAT_DOMAIN and
-- their group chats at rooms.CHAT_DOMAIN, and the page phones open (www/). Its certificate is
-- self-signed and other servers' are too, so servers authenticate each other only by the TLSA
-- records the agent publishes for their names in the DNSSEC-signed zone (DANE).

local domain = ENV_CHAT_DOMAIN
local dir = ENV_CHAT_DIR -- the server's cert.pem and key.pem

interfaces = { "*" }
c2s_ports = { Lua.tonumber(ENV_CHAT_C2S) }
s2s_ports = { Lua.tonumber(ENV_CHAT_S2S) }
http_ports = { Lua.tonumber(ENV_CHAT_HTTP) }
http_interfaces = { "*" }
https_ports = { }
data_path = ENV_CHAT_DATA -- unset in the container: the image's /var/lib/prosody
log = { info = "*console" } -- demo/chat.sh keeps it with its logs
run_as_root = ENV_CHAT_RUN_AS_ROOT == "yes" -- native, where the user is root, as in a container

modules_enabled = {
    "disco", "roster", "saslauth", "tls", "dialback", "ping", "pep", "smacks",
    "websocket", -- the page's connection, at /xmpp-websocket
    "http_files", -- the page
}

certificates = dir
ssl = { certificate = dir .. "/cert.pem", key = dir .. "/key.pem" }

-- Only a server whose certificate its TLSA record matches is accepted, either way. The answers
-- have to be DNSSEC-validated, so libunbound resolves from the root itself (resolvconf = false),
-- with the root's trust anchor: a resolver of the container's or the venue's network may drop
-- the signatures.
s2s_secure_auth = true
use_dane = true
unbound = { resolvconf = false, hoststxt = false, trustfile = "/usr/share/dns/root.ds" }

http_default_host = domain -- a phone may open the page by address
http_paths = { files = "/" }
http_files_dir = ENV_CHAT_WWW

VirtualHost(domain)
    authentication = "anonymous" -- guests: each login a throwaway address at the domain
    allow_anonymous_s2s = true -- guests may join rooms on other servers
    c2s_require_encryption = false -- phones connect over plain HTTP on the venue's network

Component("rooms." .. domain) "muc"
    muc_room_default_persistent = true -- the room stays while nobody is in it
