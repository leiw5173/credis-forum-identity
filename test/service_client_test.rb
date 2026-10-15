# frozen_string_literal: true

require "openssl"
require "webrick"
require "webrick/https"
require "json"
require_relative "../lib/spacemit_forum_identity/provider_user"
require_relative "../lib/spacemit_forum_identity/service_client"

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
trust = OpenSSL::X509::Store.new
trust.add_cert(certificate)
server = WEBrick::HTTPServer.new(
  Port: 0, BindAddress: "127.0.0.1", SSLEnable: true,
  SSLCertificate: certificate, SSLPrivateKey: key,
  SSLVerifyClient: OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
  SSLCertificateStore: trust, Logger: WEBrick::Log.new(File::NULL), AccessLog: [],
)
server.mount_proc("/integrations/forum-identity/challenge") do |request, response|
  raise "service client certificate missing" unless request.client_cert
  raise "wrong method" unless request.request_method == "POST"
  body = JSON.parse(request.body)
  raise "request changed identity" unless body["instance_id"] == 7
  response["Content-Type"] = "application/json"
  response.body = '{"error_msg":"","data":{"request_version":"fixture","challenge_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expires_at":1000}}'
end
server.mount_proc("/redirect") do |request, response|
  response.status = 302
  response["Location"] = "https://unapproved.invalid"
end
thread = Thread.new { server.start }
begin
  client = SpacemitForumIdentity::ServiceClient.new(
    origin: "https://localhost:#{server.config[:Port]}", certificate: certificate,
    key: key, trust: trust,
  )
  response = client.post("/integrations/forum-identity/challenge", { instance_id: 7 })
  raise "private challenge lost" unless response["request_version"] == "fixture"
  begin
    client.post("/redirect", {})
    raise "unapproved path accepted"
  rescue SpacemitForumIdentity::ServiceClient::Rejected
  end
ensure
  server.shutdown
  thread.join
end
puts "Ruby real mutual-TLS service client tests PASS"
