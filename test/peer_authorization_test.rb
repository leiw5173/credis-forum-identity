# frozen_string_literal: true

require "securerandom"
require_relative "../lib/spacemit_forum_identity/provider_user"
require_relative "../lib/spacemit_forum_identity/provider_client"
require_relative "../lib/spacemit_forum_identity/authority"
require_relative "../lib/spacemit_forum_identity/configuration"
require_relative "../lib/spacemit_forum_identity/peer_authorization"

identity = "spiffe://credits.test/credits/identity"
raise "spoofed header accepted" if SpacemitForumIdentity::PeerAuthorization.allowed?(nil, identity)
key = OpenSSL::PKey::RSA.new(2048)
certificate = OpenSSL::X509::Certificate.new
certificate.version = 2
certificate.serial = 1
certificate.subject = OpenSSL::X509::Name.parse("/CN=synthetic")
certificate.issuer = certificate.subject
certificate.public_key = key.public_key
certificate.not_before = Time.now - 60
certificate.not_after = Time.now + 600
factory = OpenSSL::X509::ExtensionFactory.new
factory.subject_certificate = certificate
factory.issuer_certificate = certificate
certificate.add_extension(factory.create_extension("subjectAltName", "URI:#{identity}"))
certificate.sign(key, OpenSSL::Digest.new("SHA256"))
raise "verified peer rejected" unless SpacemitForumIdentity::PeerAuthorization.allowed?(certificate, identity)
raise "wrong service accepted" if SpacemitForumIdentity::PeerAuthorization.allowed?(certificate, "spiffe://credits.test/worker")
puts "Ruby peer certificate role authorization tests PASS"
