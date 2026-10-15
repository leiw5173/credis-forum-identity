# frozen_string_literal: true

require_relative "../lib/spacemit_forum_identity/current_proof"

association = { id: 9, provider: "oauth2_basic", uuid: "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f", user_id: 42, active: true, approved: true, suspended: false }
config = { instance_id: 7, platform_id: "test-platform", provider: "oauth2_basic", audience: "https://credits.example.invalid" }
request = { "instance_id" => 7, "forum_user_id" => 42, "platform_id" => "test-platform", "request_version" => "request-v1", "association_version" => "association-v1", "nonce" => "c" * 64 }
proof = SpacemitForumIdentity::CurrentProof.claims(request: request, config: config, association: association, version: "association-v1", authenticated_at: 1000, now: 1500)
raise "proof identity changed" unless proof["forum_user_id"] == 42 && proof["nonce_digest"] == "c" * 64 && proof["issued_at"] == 1500 && proof["expires_at"] == 1800
[request.merge("forum_user_id" => 43), request.merge("platform_id" => "other"), request.merge("nonce" => "bad"), request.merge("association_version" => "moved"), request.merge("amount" => 100)].each do |bad|
  begin
    SpacemitForumIdentity::CurrentProof.claims(request: bad, config: config, association: association, version: "association-v1", authenticated_at: 1000, now: 1500)
    raise "incorrect current proof accepted"
  rescue SpacemitForumIdentity::CurrentProof::Rejected
  end
end
puts "Ruby local association current-proof tests PASS"
