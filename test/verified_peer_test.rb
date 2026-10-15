# frozen_string_literal: true

require "openssl"
require_relative "../lib/spacemit_forum_identity/verified_peer"

seen = []
app = ->(env) { seen << env.dup; [200, {}, []] }
middleware = SpacemitForumIdentity::VerifiedPeer.new(app)
spoofed = { "HTTP_X_FORWARDED_CLIENT_CERT" => "attacker", "credis.client_certificate_verified" => true, "credis.verified_client_certificate" => "attacker" }
middleware.call(spoofed)
raise "forged identity propagated" if seen.last["credis.client_certificate_verified"] || seen.last["credis.verified_client_certificate"]
key = OpenSSL::PKey::RSA.new(2048)
certificate = OpenSSL::X509::Certificate.new
certificate.serial = 1
certificate.subject = OpenSSL::X509::Name.parse("/CN=synthetic")
certificate.issuer = certificate.subject
certificate.public_key = key.public_key
certificate.not_before = Time.now - 60
certificate.not_after = Time.now + 600
certificate.sign(key, OpenSSL::Digest.new("SHA256"))
middleware.call({ "rack.url_scheme" => "https", "puma.peercert" => certificate })
raise "verified Puma peer certificate missing" unless seen.last["credis.client_certificate_verified"] == true && seen.last["credis.verified_client_certificate"] == certificate
puts "Ruby trusted Rack peer middleware tests PASS"
