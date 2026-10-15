# frozen_string_literal: true

require "tmpdir"

RSpec.describe SpacemitForumIdentity::BindingsController do
  fab!(:user) { Fabricate(:user, active: true, approved: true) }
  let(:uuid) { "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f" }
  let(:handle) { Base64.urlsafe_encode64("x" * 32, padding: false) }

  around do |example|
    Dir.mktmpdir do |root|
      config = {
        instance_id: 7, platform_id: "test-platform", provider: "oauth2_basic", client_id: "discourse",
        authorize_url: "https://provider.example.invalid/authorize", token_url: "https://provider.example.invalid/token",
        userinfo_url: "https://provider.example.invalid/userinfo", audience: "https://credits.example.invalid",
        peer_identity: "spiffe://credits.test/credits/identity", assertion_key_id: "assertion-v1", current_key_id: "current-v1",
      }
      config_path = File.join(root, "config.json")
      File.write(config_path, JSON.generate(config))
      File.chmod(0o600, config_path)
      key = OpenSSL::PKey.generate_key("ED25519")
      key_path = File.join(root, "assertion-key.pem")
      File.write(key_path, key.private_to_pem)
      File.chmod(0o600, key_path)
      previous = ENV.to_h.slice("CREDIS_FORUM_IDENTITY_ENABLED", "CREDIS_FORUM_IDENTITY_CONFIG_FILE", "CREDIS_FORUM_IDENTITY_ASSERTION_KEY_FILE")
      ENV["CREDIS_FORUM_IDENTITY_ENABLED"] = "true"
      ENV["CREDIS_FORUM_IDENTITY_CONFIG_FILE"] = config_path
      ENV["CREDIS_FORUM_IDENTITY_ASSERTION_KEY_FILE"] = key_path
      begin
        example.run
      ensure
        %w[CREDIS_FORUM_IDENTITY_ENABLED CREDIS_FORUM_IDENTITY_CONFIG_FILE CREDIS_FORUM_IDENTITY_ASSERTION_KEY_FILE].each { |name| previous.key?(name) ? ENV[name] = previous[name] : ENV.delete(name) }
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
    SiteSetting.oauth2_email_verified = false
    SiteSetting.oauth2_allow_association_change = false
    SiteSetting.oauth2_debug_auth = false
    stub_request(:get, "https://provider.example.invalid/userinfo").to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: { code: 200, data: { id: uuid, username: "fixture", email: user.email, status: "1" } }.to_json)
  end

  describe "#show" do
    it "explains missing forum login instead of rendering a not-found page" do
      get "/credis-forum-identity/bind"
      expect(response.status).to eq(200)
      expect(response.body).to include("请先登录论坛")
      expect(response.body).not_to include("确认关联当前账号")
    end

    it "automatically submits the verified session without a confirmation button" do
      sign_in(user)
      SiteSetting.content_security_policy = true
      get "/credis-forum-identity/bind"
      expect(response.status).to eq(200)
      expect(response.body).to include("自动关联")
      nonce = response.body[/<script nonce="([^"]+)"/, 1]
      expect(nonce).to be_present
      expect(response.headers["Content-Security-Policy"]).to include("'nonce-#{nonce}'")
      expect(response.body).to include("'Accept': 'application/json'")
      expect(response.body).not_to include("button.addEventListener('click'")
    end
  end

  describe "#create" do
    it "uses a native authenticated callback then sends the assertion only over the service boundary" do
      UserAssociatedAccount.create!(provider_name: "oauth2_basic", provider_uid: uuid, user: user, last_used: Time.now)
      auth = OmniAuth::AuthHash.new(provider: "oauth2_basic", uid: uuid, credentials: { token: "synthetic-only" }, info: {}, extra: {})
      old_auth = Rails.application.env_config["omniauth.auth"]
      old_test_mode=OmniAuth.config.test_mode
      OmniAuth.config.test_mode=true
      OmniAuth.config.mock_auth[:oauth2_basic]=auth
      Rails.application.env_config["omniauth.auth"] = auth
      get "/auth/oauth2_basic/callback.json"
      expect(response.status).to eq(302)
      expect(Discourse.current_user_provider.new(request.env).current_user.id).to eq(user.id)
      trust = OpenSSL::X509::Store.new
      cert_key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.serial = 1
      cert.version = 2
      cert.subject = OpenSSL::X509::Name.parse("/CN=synthetic")
      cert.issuer = cert.subject
      cert.public_key = cert_key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 600
      cert.sign(cert_key, OpenSSL::Digest.new("SHA256"))
      trust.add_cert(cert)
      # Replace only the TLS transport's credential loader, not the binding logic.
      SpacemitForumIdentity.stubs(:service_client).returns(SpacemitForumIdentity::ServiceClient.new(origin: "https://credits.example.invalid", certificate: cert, key: cert_key, trust: trust))
      digest = Digest::SHA256.hexdigest(handle)
      stub_request(:post, "https://credits.example.invalid/integrations/forum-identity/challenge").to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: { error_msg: "", data: { request_version: "request-v1", challenge_digest: digest, expires_at: Time.now.to_i + 300 } }.to_json)
      stub_request(:post, "https://credits.example.invalid/integrations/forum-identity/assertions").to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: { error_msg: "", data: { durable_ack: true } }.to_json)
      post "/credis-forum-identity/bind", params: { handle: handle }.to_json, headers: { "Content-Type" => "application/json", "Accept" => "application/json" }
      expect(response.status).to eq(200)
      expect(response.parsed_body).to eq({ "url" => "https://credits.example.invalid/settings/forum-binding##{handle}" })
      expect(response.body).not_to include(uuid)
      expect(DB.query_single("SELECT count(*) FROM credis_identity_associations WHERE user_id=:id", id: user.id).first).to eq(1)
    ensure
      Rails.application.env_config["omniauth.auth"] = old_auth
      OmniAuth.config.test_mode=old_test_mode
      OmniAuth.config.mock_auth.delete(:oauth2_basic)
    end
  end
end
