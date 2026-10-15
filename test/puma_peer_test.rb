# frozen_string_literal: true

require "rack"
require "puma"
require "puma/binder"
require "openssl"
require "net/http"
require "tmpdir"
require_relative "../lib/spacemit_forum_identity/verified_peer"

Dir.mktmpdir do |root|
  key = OpenSSL::PKey::RSA.new(2048)
  certificate = OpenSSL::X509::Certificate.new
  certificate.version = 2
  certificate.serial = 1
  certificate.subject = OpenSSL::X509::Name.parse("/CN=localhost")
  certificate.issuer = certificate.subject
  certificate.public_key = key.public_key
  certificate.not_before = Time.now - 60
  certificate.not_after = Time.now + 600
  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = certificate
  factory.issuer_certificate = certificate
  certificate.add_extension(factory.create_extension("subjectAltName", "DNS:localhost"))
  certificate.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
  certificate.sign(key, OpenSSL::Digest.new("SHA256"))
  client_certificate = OpenSSL::X509::Certificate.new
  client_certificate.version = 2
  client_certificate.serial = 2
  client_certificate.subject = OpenSSL::X509::Name.parse("/CN=identity-client")
  client_certificate.issuer = certificate.subject
  client_certificate.public_key = key.public_key
  client_certificate.not_before = Time.now - 60
  client_certificate.not_after = Time.now + 600
  client_certificate.sign(key, OpenSSL::Digest.new("SHA256"))
  cert_path = File.join(root, "cert.pem")
  key_path = File.join(root, "key.pem")
  File.write(cert_path, certificate.to_pem)
  File.write(key_path, key.to_pem)
  File.chmod(0o600, cert_path)
  File.chmod(0o600, key_path)
  app = SpacemitForumIdentity::VerifiedPeer.new(->(env) {
    verified = env["credis.client_certificate_verified"] == true
    [verified ? 200 : 403, { "content-type" => "text/plain" }, [verified ? "verified" : "forbidden"]]
  })
  server = Puma::Server.new(app)
  tls_context = Puma::MiniSSL::Context.new
  tls_context.key = key_path
  tls_context.cert = cert_path
  tls_context.ca = cert_path
  tls_context.verify_mode = Puma::MiniSSL::VERIFY_PEER
  server.add_ssl_listener("127.0.0.1", 0, tls_context)
  thread = server.run
  port = server.binder.ios.first.addr[1]
  begin
    http = Net::HTTP.new("localhost", port, nil)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    store = OpenSSL::X509::Store.new
    store.add_cert(certificate)
    http.cert_store = store
    response = http.get("/")
    raise "anonymous client authenticated" unless response.code == "403"
    # A different client certificate needs a new TLS connection/session cache.
    http = Net::HTTP.new("localhost", port, nil)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.cert_store = store
    http.cert = client_certificate
    http.key = key
    response = http.get("/")
    raise "real verified Puma certificate unavailable" unless response.code == "200" && response.body == "verified"
  ensure
    server.stop(true)
    thread.join
  end
end
puts "Ruby actual Puma TLS to Rack proof test PASS"
