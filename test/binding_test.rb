# frozen_string_literal: true

require "base64"
require "securerandom"
require "openssl"
require_relative "../lib/spacemit_forum_identity/assertion"
require_relative "../lib/spacemit_forum_identity/binding"

key = OpenSSL::PKey.generate_key("ED25519")
subject = { forum_user_id: 42, uuid: "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f", authenticated_at: 1000, association_version: "association-v1" }
config = { instance_id: 7, platform_id: "test-platform", provider: "oauth2_basic", audience: "https://credits.example.invalid", assertion_key_id: "assertion-v1" }
handle = Base64.urlsafe_encode64("x" * 32, padding: false)
class BindingPeerFixture
  attr_reader :assertion
  def initialize(handle)
    @handle = handle
  end
  def post(path, body)
    case path
    when "/integrations/forum-identity/challenge"
      raise "wrong account query" unless body[:handle] == @handle && body[:uuid] == "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f"
      { "request_version" => "request-v1", "challenge_digest" => Digest::SHA256.hexdigest(@handle), "expires_at" => 1300 }
    when "/integrations/forum-identity/assertions"
      @assertion = body[:assertion]
      { "durable_ack" => true }
    else
      raise "unexpected path"
    end
  end
end
peer = BindingPeerFixture.new(handle)
result = SpacemitForumIdentity::Binding.complete(handle: handle, subject: subject, config: config, client: peer, key: key, now: 1000)
raise "browser received private identity" unless result == { url: "https://credits.example.invalid/settings/forum-binding##{handle}" }
raise "private proof not sent to peer" unless peer.assertion.is_a?(Hash)
puts "Ruby server-side binding proof orchestration test PASS"
