# frozen_string_literal: true

require_relative "../lib/spacemit_forum_identity/authority"

config = {
  instance_id: 7, platform_id: "test-platform", provider: "oauth2_basic", client_id: "discourse",
  audience: "https://credits.example.invalid",
  authorize_url: "https://provider.example.invalid/authorize",
  token_url: "https://provider.example.invalid/token",
  userinfo_url: "https://provider.example.invalid/userinfo",
}
association = { id: 9, provider: "oauth2_basic", uuid: "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f", user_id: 42, active: true, approved: true, suspended: false }
marker = { association_id: 9, user_id: 42, uuid: association[:uuid], authenticated_at: 1000, provider: "oauth2_basic", platform_id: "test-platform" }
subject = SpacemitForumIdentity::Authority.for_binding(config: config, association: association, marker: marker, current_user_id: 42, now: 1001)
raise "wrong stable user" unless subject[:forum_user_id] == 42 && subject[:uuid] == association[:uuid]
raise "missing association version" unless subject[:association_version].match?(/\A[0-9a-f]{64}\z/)
[
  { association: association.merge(user_id: 43) },
  { association: association.merge(active: false) },
  { association: association.merge(approved: false) },
  { association: association.merge(suspended: true) },
  { association: association.merge(provider: "other") },
  { marker: marker.merge(authenticated_at: 699) },
  { marker: marker.merge(authenticated_at: 1002) },
  { marker: marker.merge(association_id: 10) },
  { marker: marker.merge(uuid: "9f14e45f-ceea-4c1f-8f14-e45fceea4c1f") },
  { marker: marker.merge(platform_id: "other") },
  { current_user_id: 43 },
  { marker: nil },
].each_with_index do |changes, index|
  begin
    SpacemitForumIdentity::Authority.for_binding(**{config: config, association: association, marker: marker, current_user_id: 42, now: 1001}.merge(changes))
    raise "invalid session authority accepted #{index}"
  rescue SpacemitForumIdentity::Authority::Rejected
  end
end
other = SpacemitForumIdentity::Authority.for_binding(config: config, association: association.merge(id: 10), marker: marker.merge(association_id: 10), current_user_id: 42, now: 1001)
raise "new association reused prior version" if other[:association_version] == subject[:association_version]
puts "Ruby current-session association authority tests PASS"
