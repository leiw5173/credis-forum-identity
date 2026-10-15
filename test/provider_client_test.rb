# frozen_string_literal: true

require "openssl"
require "webrick"
require "webrick/https"
require_relative "../lib/spacemit_forum_identity/provider_user"
require_relative "../lib/spacemit_forum_identity/provider_client"

key = OpenSSL::PKey::RSA.new(2048)
certificate = OpenSSL::X509::Certificate.new
certificate.version = 2
certificate.serial = 1
certificate.subject = OpenSSL::X509::Name.parse("/CN=localhost")
certificate.issuer = certificate.subject
certificate.public_key = key.public_key
certificate.not_before = Time.now - 60
certificate.not_after = Time.now + 600
extension = OpenSSL::X509::ExtensionFactory.new
extension.subject_certificate = certificate
extension.issuer_certificate = certificate
certificate.add_extension(extension.create_extension("subjectAltName", "DNS:localhost"))
certificate.add_extension(extension.create_extension("basicConstraints", "CA:TRUE", true))
certificate.sign(key, OpenSSL::Digest.new("SHA256"))
server = WEBrick::HTTPServer.new(Port: 0, BindAddress: "127.0.0.1", SSLEnable: true, SSLCertificate: certificate, SSLPrivateKey: key, Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
server.mount_proc("/userinfo") do |request, response|
  raise "wrong token placement" unless request["Authorization"] == "Bearer synthetic-only" && request.query_string.nil?
  response["Content-Type"] = "application/json"
  response.body = '{"code":200,"data":{"id":"8f14e45f-ceea-4c1f-8f14-e45fceea4c1f","username":"fixture","email":"fixture@example.invalid","status":"1"}}'
end
thread = Thread.new { server.start }
begin
  trust = OpenSSL::X509::Store.new
  trust.add_cert(certificate)
  subject = SpacemitForumIdentity::ProviderClient.fetch("synthetic-only", "https://localhost:#{server.config[:Port]}/userinfo", trust: trust)
  raise "provider identity missing" unless subject[:uuid] == "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f"
ensure
  server.shutdown
  thread.join
end
puts "Ruby real local TLS provider client test PASS"
