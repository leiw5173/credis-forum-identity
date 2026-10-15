# frozen_string_literal: true

require "openssl"
require "json"
require "base64"

module SpacemitForumIdentity
  module AssertionFixtures
    PAYLOAD = '{"version":1,"instance_id":7,"platform_id":"test-platform","provider":"oauth2_basic","uuid":"8f14e45f-ceea-4c1f-8f14-e45fceea4c1f","forum_user_id":42,"audience":"https://credits.example.invalid","request_version":"request-v1","association_version":"association-v1","challenge_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce_digest":"","jti":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","authenticated_at":1791878400,"issued_at":1791878400,"expires_at":1791878460}'
  end
end

require_relative "../lib/spacemit_forum_identity/assertion"

key = OpenSSL::PKey.generate_key("ED25519")
claims = JSON.parse(SpacemitForumIdentity::AssertionFixtures::PAYLOAD)
raw = SpacemitForumIdentity::Assertion.sign(
  claims: claims,
  key: key,
  key_id: "fixture-key",
  purpose: "binding",
)
envelope = JSON.parse(raw)
payload = Base64.urlsafe_decode64(envelope.fetch("payload"))
raise "canonical claims differ" unless payload == SpacemitForumIdentity::AssertionFixtures::PAYLOAD
signature = Base64.urlsafe_decode64(envelope.fetch("signature"))
raise "invalid signature" unless key.verify(nil, signature, "spacemit-forum-binding-v1\n#{payload}")
raise "cross-purpose signature accepted" if key.verify(nil, signature, "spacemit-forum-liveness-v1\n#{payload}")

["other", ""].each do |purpose|
  begin
    SpacemitForumIdentity::Assertion.sign(claims: claims, key: key, key_id: "fixture-key", purpose: purpose)
    raise "unknown purpose accepted"
  rescue SpacemitForumIdentity::Assertion::Rejected
  end
end
begin
  SpacemitForumIdentity::Assertion.sign(claims: claims.merge("account_id" => 9), key: key, key_id: "fixture-key", purpose: "binding")
  raise "caller-supplied account accepted"
rescue SpacemitForumIdentity::Assertion::Rejected
end
puts "Ruby canonical Ed25519 assertion tests PASS"
