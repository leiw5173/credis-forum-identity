# frozen_string_literal: true

require_relative "../lib/spacemit_forum_identity/authentication"

subject = { uuid: "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f", username: "fixture", email: "fixture@example.invalid", email_verified: false }
original = { provider: "oauth2_basic", uid: "wrong", credentials: { token: "synthetic-provider-token" }, extra: { raw_info: "private" }, info: { email: "wrong@example.invalid", admin: true }, session: { existing: true } }
clean = SpacemitForumIdentity::Authentication.sanitized_auth(original, subject)
raise "wrong UUID" unless clean[:uid] == subject[:uuid]
raise "credentials persisted" unless clean[:credentials] == {} && clean[:extra] == {}
raise "email incorrectly verified" unless clean[:info] == { nickname: "fixture", email: "fixture@example.invalid", email_verified: false }
raise "caller mutated" unless original[:credentials][:token] == "synthetic-provider-token"
raise "session lost" unless clean[:session] == original[:session]
user = { id: 42, active: true, approved: true, suspended: false }
association = { id: 9, user_id: 42, uuid: subject[:uuid], provider: "oauth2_basic" }
marker = SpacemitForumIdentity::Authentication.marker(subject: subject, user: user, association: association, platform_id: "test-platform", now: 1000)
raise "marker not bound to account" unless marker[:user_id] == 42 && marker[:association_id] == 9 && marker[:authenticated_at] == 1000
[
  { user: user.merge(active: false) },
  { user: user.merge(suspended: true) },
  { association: association.merge(uuid: "9f14e45f-ceea-4c1f-8f14-e45fceea4c1f") },
  { association: association.merge(user_id: 43) },
].each do |change|
  begin
    SpacemitForumIdentity::Authentication.marker(**{subject: subject, user: user, association: association, platform_id: "test-platform", now: 1000}.merge(change))
    raise "incomplete association authenticated"
  rescue SpacemitForumIdentity::Authentication::Rejected
  end
end
puts "Ruby authentication sanitization and fresh-session marker tests PASS"
