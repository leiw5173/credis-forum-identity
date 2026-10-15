# frozen_string_literal: true

require_relative "../lib/spacemit_forum_identity/provider_user"
require_relative "../lib/spacemit_forum_identity/authentication"
require_relative "../lib/spacemit_forum_identity/authenticator_extension"

module SpacemitForumIdentity
  def self.enabled?; true; end
  def self.configured?; true; end
  def self.config; { platform_id: "test-platform" }; end
end
class SyntheticManagedAuthenticator
  attr_reader :stored_auth
  def after_authenticate(auth, existing_account: nil)
    @stored_auth = auth
    { auth: auth }
  end
  def fetch_user_details(token, id)
    raise "raw upstream parser invoked"
  end
  def name; "oauth2_basic"; end
  def match_by_email; true; end
  def primary_email_verified?(auth); true; end
end
class SyntheticOAuthAuthenticator < SyntheticManagedAuthenticator
  prepend SpacemitForumIdentity::AuthenticatorExtension
end
class << SpacemitForumIdentity
  def fetch_subject(_token)
    { uuid: "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f", username: "fixture", email: "fixture@example.invalid", email_verified: false }
  end
end
instance = SyntheticOAuthAuthenticator.new
result = instance.after_authenticate({ provider: "oauth2_basic", credentials: { token: "synthetic-only" }, info: {}, extra: {} })
raise "generic provider ran without sanitation" unless instance.stored_auth[:credentials] == {} && instance.stored_auth[:uid] == "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f"
raise "email matching retained" unless instance.match_by_email == false
raise "unverified email trusted" unless instance.primary_email_verified?({}) == false
puts "Ruby scoped authenticator extension tests PASS"
