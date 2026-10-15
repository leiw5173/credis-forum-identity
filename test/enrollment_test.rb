# frozen_string_literal: true

require "openssl"
require "json"

require_relative "../lib/spacemit_forum_identity/assertion"
require_relative "../lib/spacemit_forum_identity/enrollment"

class EnrollmentClient
  attr_reader :path, :payload
  def post(path, payload)
    @path, @payload = path, payload
    { "durable_ack" => true, "binding_id" => 7 }
  end
end

enrollment_user = Struct.new(:id)
enrollment_association = Struct.new(:id, :user_id, :provider_name, :provider_uid)
key = OpenSSL::PKey.generate_key("ED25519")
uuid = "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f"
subject = { forum_user_id: 42, uuid: uuid, association_version: "association-v1", username: "fixture",
  email: "fixture@example.invalid", authenticated_at: 1000 }
config = { instance_id: 7, platform_id: "test-platform", provider: "oauth2_basic",
  audience: "https://credits.example.invalid", assertion_key_id: "fixture-key" }
raw = SpacemitForumIdentity::Enrollment.assertion(subject: subject, user: enrollment_user.new(42),
  association: enrollment_association.new(9, 42, "oauth2_basic", uuid), config: config, key: key, now: 1001)
client = EnrollmentClient.new
raise "enrollment not acknowledged" unless SpacemitForumIdentity::Enrollment.deliver(association_id: 9, client: client, row: raw)
raise "wrong enrollment endpoint" unless client.path.end_with?("/enroll")
payload = JSON.parse(Base64.urlsafe_decode64(client.payload.fetch("payload")))
raise "caller supplied local identity" if payload.key?("principal_id") || payload.key?("account_id")
raise "email incorrectly trusted" unless payload["email_verified"] == false
puts "Ruby passport enrollment assertion tests PASS"
