# frozen_string_literal: true

require_relative "../lib/spacemit_forum_identity/association_guard"

original = { user_id: 42, uuid: "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f", provider: "oauth2_basic" }
SpacemitForumIdentity::AssociationGuard.check!(original: original, changed: original, operation: :update, enabled: true)
[original.merge(user_id: 43), original.merge(uuid: "other"), original.merge(provider: "other")].each do |changed|
  begin
    SpacemitForumIdentity::AssociationGuard.check!(original: original, changed: changed, operation: :update, enabled: true)
    raise "association rebound"
  rescue SpacemitForumIdentity::AssociationGuard::Rejected
  end
end
begin
  SpacemitForumIdentity::AssociationGuard.check!(original: original, changed: {}, operation: :delete, enabled: true)
  raise "association deleted"
rescue SpacemitForumIdentity::AssociationGuard::Rejected
end
SpacemitForumIdentity::AssociationGuard.check!(original: original.merge(provider: "other"), changed: {}, operation: :delete, enabled: true)
SpacemitForumIdentity::AssociationGuard.check!(original: original.merge(user_id: nil), changed: original, operation: :update, enabled: true)
puts "Ruby immutable association product-path tests PASS"
