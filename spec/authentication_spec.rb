# frozen_string_literal: true

require "tmpdir"

describe SpacemitForumIdentity::Authentication do
  fab!(:user) { Fabricate(:user, active: true, approved: true) }
  let(:uuid) { "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f" }
  let(:auth) do
    OmniAuth::AuthHash.new(provider: "oauth2_basic", uid: "wrong", credentials: { token: "synthetic-only" }, info: {}, extra: {})
  end

  around do |example|
    Dir.mktmpdir do |root|
      path = File.join(root, "config.json")
      config = {
        instance_id: 7, platform_id: "test-platform", provider: "oauth2_basic", client_id: "discourse",
        authorize_url: "https://provider.example.invalid/authorize", token_url: "https://provider.example.invalid/token",
        userinfo_url: "https://provider.example.invalid/userinfo", audience: "https://credits.example.invalid",
        peer_identity: "spiffe://credits.test/credits/identity", assertion_key_id: "assertion-v1", current_key_id: "current-v1",
      }
      File.write(path, JSON.generate(config))
      File.chmod(0o600, path)
      previous = ENV.values_at("CREDIS_FORUM_IDENTITY_ENABLED", "CREDIS_FORUM_IDENTITY_CONFIG_FILE")
      ENV["CREDIS_FORUM_IDENTITY_ENABLED"] = "true"
      ENV["CREDIS_FORUM_IDENTITY_CONFIG_FILE"] = path
      begin
        example.run
      ensure
        %w[CREDIS_FORUM_IDENTITY_ENABLED CREDIS_FORUM_IDENTITY_CONFIG_FILE].zip(previous).each do |key, value|
          value ? ENV[key] = value : ENV.delete(key)
        end
      end
    end
  end

  before do
    SiteSetting.oauth2_enabled = true
    SiteSetting.oauth2_client_id = "discourse"
    SiteSetting.oauth2_authorize_url = "https://provider.example.invalid/authorize"
    SiteSetting.oauth2_token_url = "https://provider.example.invalid/token"
    SiteSetting.oauth2_user_json_url = "https://provider.example.invalid/userinfo"
    SiteSetting.oauth2_send_auth_header = true
    SiteSetting.oauth2_send_auth_body = false
    SiteSetting.oauth2_debug_auth = false
    SiteSetting.oauth2_email_verified = false
    SiteSetting.oauth2_allow_association_change = false
    stub_request(:get, "https://provider.example.invalid/userinfo").with(headers: { "Authorization" => "Bearer synthetic-only" }).to_return(
      status: 200, headers: { "Content-Type" => "application/json" },
      body: { code: 200, data: { id: uuid, username: "fixture", email: user.email, status: "1" } }.to_json,
    )
  end

  it "leaves inactive or unapproved accounts to native activation without issuing a binding marker" do
    user.update!(active: false, approved: false)
    UserAssociatedAccount.create!(provider_name: "oauth2_basic", provider_uid: uuid, user: user, last_used: Time.now)
    result = OAuth2BasicAuthenticator.new.after_authenticate(auth)
    session = { SpacemitForumIdentity::SESSION_KEY => { stale: true } }
    request = Struct.new(:env).new({ "omniauth.auth" => auth })
    expect { DiscourseEvent.trigger(:after_auth, OAuth2BasicAuthenticator.new, result, session, {}, request) }.not_to raise_error
    expect(session).not_to have_key(SpacemitForumIdentity::SESSION_KEY)
    expect(user.reload.active).to eq(false)
    expect(user.approved).to eq(false)
  end

  it "waives secondary activation only under the explicit trusted passport policy" do
    SiteSetting.must_approve_users = true
    user.update!(active: false, approved: false)
    UserAssociatedAccount.create!(provider_name: "oauth2_basic", provider_uid: uuid, user: user, last_used: Time.now)
    ENV["CREDIS_FORUM_TRUST_PASSPORT_ACTIVATION"] = "true"
    result = OAuth2BasicAuthenticator.new.after_authenticate(auth)
    session = {}
    request = Struct.new(:env).new({ "omniauth.auth" => auth })
    DiscourseEvent.trigger(:after_auth, OAuth2BasicAuthenticator.new, result, session, {}, request)
    expect(user.reload.active).to eq(true)
    expect(user.approved).to eq(false)
    expect(result.email_valid).to eq(false)
    expect(session).not_to have_key(SpacemitForumIdentity::SESSION_KEY)
    expect(user.email_tokens.where(confirmed: true).count).to eq(0)
  ensure
    ENV.delete("CREDIS_FORUM_TRUST_PASSPORT_ACTIVATION")
  end

  it "does not activate a suspended passport account under the policy" do
    user.update!(active: false, suspended_till: 1.day.from_now)
    UserAssociatedAccount.create!(provider_name: "oauth2_basic", provider_uid: uuid, user: user, last_used: Time.now)
    ENV["CREDIS_FORUM_TRUST_PASSPORT_ACTIVATION"] = "true"
    result = OAuth2BasicAuthenticator.new.after_authenticate(auth)
    request = Struct.new(:env).new({ "omniauth.auth" => auth })
    DiscourseEvent.trigger(:after_auth, OAuth2BasicAuthenticator.new, result, {}, {}, request)
    expect(user.reload.active).to eq(false)
  ensure
    ENV.delete("CREDIS_FORUM_TRUST_PASSPORT_ACTIVATION")
  end

  it "uses native access permission when approval is not required" do
    SiteSetting.must_approve_users = false
    user.update!(approved: false)
    association = UserAssociatedAccount.create!(provider_name: "oauth2_basic", provider_uid: uuid, user: user, last_used: Time.now)
    expect(SpacemitForumIdentity.association_values(association)[:approved]).to eq(true)
    expect(user.reload.approved).to eq(false)
    SiteSetting.must_approve_users = true
    expect(SpacemitForumIdentity.association_values(association)[:approved]).to eq(false)
  end

  it "preserves an existing forum user and persists no provider credentials" do
    association = UserAssociatedAccount.create!(provider_name: "oauth2_basic", provider_uid: uuid, user: user, last_used: Time.now, credentials: {}, info: {}, extra: {})
    result = OAuth2BasicAuthenticator.new.after_authenticate(auth)
    expect(result.user.id).to eq(user.id)
    expect(result.email_valid).to eq(false)
    expect(association.reload.credentials).to eq({})
    expect(association.extra).to eq({})
  end

  it "keeps matching email from attaching a new provider UUID to an existing user" do
    result = OAuth2BasicAuthenticator.new.after_authenticate(auth)
    expect(result.user).to be_nil
    expect(result.email_valid).to eq(false)
    expect(UserAssociatedAccount.find_by(provider_name: "oauth2_basic", provider_uid: uuid).user_id).to be_nil
  end

  it "rejects a disabled provider subject without creating an association" do
    stub_request(:get, "https://provider.example.invalid/userinfo").to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: { code: 200, data: { id: uuid, username: "fixture", email: user.email, status: "0" } }.to_json)
    expect { OAuth2BasicAuthenticator.new.after_authenticate(auth) }.to raise_error(SpacemitForumIdentity::ProviderUser::Rejected)
    expect(UserAssociatedAccount.find_by(provider_name: "oauth2_basic", provider_uid: uuid)).to be_nil
  end
end
