local kumo = require 'kumo'

kumo.on('proxy_init', function()
  kumo.start_proxy_listener {
    listen = '127.0.0.1:0',
    require_auth = true,
  }
end)

kumo.on('proxy_server_auth_1929', function(username, password, peer_address)
  -- Simple auth: accept testuser/testpass
  return username == 'testuser' and password == 'testpass'
end)
