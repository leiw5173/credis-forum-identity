# frozen_string_literal: true

require "tmpdir"
require "json"
require_relative "../lib/spacemit_forum_identity/provider_user"
require_relative "../lib/spacemit_forum_identity/authority"
require_relative "../lib/spacemit_forum_identity/configuration"

Dir.mktmpdir do |directory|
  path = File.join(directory, "identity.json")
  values = {
    instance_id: 7, platform_id: "test-platform", provider: "oauth2_basic", client_id: "discourse",
    authorize_url: "https://provider.example.invalid/authorize", token_url: "https://provider.example.invalid/token",
    userinfo_url: "https://provider.example.invalid/userinfo", audience: "https://credits.example.invalid",
    peer_identity: "spiffe://credits.test/credits/identity", assertion_key_id: "assertion-v1", current_key_id: "current-v1",
  }
  File.write(path, JSON.generate(values))
  File.chmod(0o600, path)
  ENV["CREDIS_FORUM_IDENTITY_CONFIG_FILE"] = path
  raise "configuration changed identity" unless SpacemitForumIdentity::Configuration.load[:instance_id] == 7
  File.write(path, JSON.generate(values.merge(audience: "http://credits.example.invalid")))
  begin
    SpacemitForumIdentity::Configuration.load
    raise "HTTP trust destination accepted"
  rescue SpacemitForumIdentity::Configuration::Rejected
  end
  File.write(path, JSON.generate(values.merge(current_key_id: "assertion-v1")))
  begin
    SpacemitForumIdentity::Configuration.load
    raise "signing domains share key identifier"
  rescue SpacemitForumIdentity::Configuration::Rejected
  end
end
puts "Ruby file configuration boundary tests PASS"
