# frozen_string_literal: true

# name: credis-forum-identity
# about: Verified association proofs for an explicitly configured OAuth2 forum.
# version: 0.1
# authors: SpacemiT

module ::SpacemitForumIdentity
  PLUGIN_NAME = "credis-forum-identity"
  SESSION_KEY = "spacemit_forum_identity"
end

require_relative "lib/spacemit_forum_identity/provider_user"
require_relative "lib/spacemit_forum_identity/authority"
require_relative "lib/spacemit_forum_identity/configuration"
require_relative "lib/spacemit_forum_identity/authentication"
require_relative "lib/spacemit_forum_identity/provider_client"
require_relative "lib/spacemit_forum_identity/assertion"
require_relative "lib/spacemit_forum_identity/enrollment"
require_relative "lib/spacemit_forum_identity/authenticator_extension"
require_relative "lib/spacemit_forum_identity/service_client"
require_relative "lib/spacemit_forum_identity/binding"
require_relative "lib/spacemit_forum_identity/current_proof"
require_relative "lib/spacemit_forum_identity/peer_authorization"
require_relative "lib/spacemit_forum_identity/association_guard"
require_relative "lib/spacemit_forum_identity/verified_peer"

require_relative "lib/spacemit_forum_identity/engine"

Rails.application.config.middleware.use(SpacemitForumIdentity::VerifiedPeer)

module ::SpacemitForumIdentity
  def self.enabled?
    ENV["CREDIS_FORUM_IDENTITY_ENABLED"] == "true"
  end

  def self.config
    Configuration.load
  end

  def self.configured?
    values = config
    values[:client_id] == SiteSetting.oauth2_client_id &&
      values[:authorize_url] == SiteSetting.oauth2_authorize_url &&
      values[:token_url] == SiteSetting.oauth2_token_url &&
      values[:userinfo_url] == SiteSetting.oauth2_user_json_url &&
      SiteSetting.oauth2_token_url_method == "POST" &&
      SiteSetting.oauth2_user_json_url_method == "GET" &&
      SiteSetting.oauth2_send_auth_header && !SiteSetting.oauth2_send_auth_body &&
      !SiteSetting.oauth2_debug_auth && !SiteSetting.oauth2_disable_csrf &&
      !SiteSetting.oauth2_allow_association_change && !SiteSetting.oauth2_email_verified
  rescue Configuration::Rejected
    false
  end

  def self.fetch_subject(token)
    ProviderClient.fetch(token, config.fetch(:userinfo_url))
  end

  def self.service_client(values)
    trust = OpenSSL::X509::Store.new
    trust.add_cert(OpenSSL::X509::Certificate.new(Configuration.read_key("CREDIS_FORUM_IDENTITY_PEER_CA")))
    ServiceClient.new(origin: values.fetch(:audience), certificate: OpenSSL::X509::Certificate.new(Configuration.read_key("CREDIS_FORUM_IDENTITY_PEER_CERT")), key: OpenSSL::PKey.read(Configuration.read_key("CREDIS_FORUM_IDENTITY_PEER_KEY")), trust: trust)
  end

  def self.association_values(association)
    user = association.user
    raise Authority::Rejected, "forum association unavailable" unless user
    {
      id: association.id, user_id: user.id, uuid: association.provider_uid,
      provider: association.provider_name, active: user.active?, approved: user.guardian.can_access_forum?,
      suspended: user.suspended?,
    }
  end
end

after_initialize do
  unless defined?(OAuth2BasicAuthenticator)
    raise "forum identity requires installed OAuth2 plugin" if SpacemitForumIdentity.enabled?
    next
  end
  OAuth2BasicAuthenticator.prepend(SpacemitForumIdentity::AuthenticatorExtension)

  UserAssociatedAccount.before_update do |association|
    original = { user_id: association.user_id_in_database, uuid: association.provider_uid_in_database, provider: association.provider_name_in_database }
    changed = { user_id: association.user_id, uuid: association.provider_uid, provider: association.provider_name }
    SpacemitForumIdentity::AssociationGuard.check!(original: original, changed: changed, operation: :update, enabled: SpacemitForumIdentity.enabled?)
  end
  UserAssociatedAccount.before_destroy do |association|
    original = { user_id: association.user_id, uuid: association.provider_uid, provider: association.provider_name }
    SpacemitForumIdentity::AssociationGuard.check!(original: original, changed: {}, operation: :delete, enabled: SpacemitForumIdentity.enabled?)
  end

  on(:after_auth) do |authenticator, result, session, cookies, request|
    next unless SpacemitForumIdentity.enabled? && authenticator.name == "oauth2_basic"
    session.delete(SpacemitForumIdentity::SESSION_KEY)
    next if result.failed? || !result.user || !SpacemitForumIdentity.configured?
    subject = request.env["omniauth.auth"]&.[](:spacemit_identity_subject)
    next unless subject
    association = UserAssociatedAccount.find_by(provider_name: "oauth2_basic", provider_uid: subject[:uuid], user_id: result.user.id)
    next unless association
    if ENV["CREDIS_FORUM_TRUST_PASSPORT_ACTIVATION"] == "true" && !result.user.suspended?
      # Local trust policy waives activation, never asserts verified email or approval.
      result.user.update!(active: true) unless result.user.active?
    end
    values = SpacemitForumIdentity.association_values(association)
    # Unapproved or suspended accounts cannot issue proofs.
    next unless values[:active] == true && values[:approved] == true && values[:suspended] == false
    marker = SpacemitForumIdentity::Authentication.marker(
      subject: subject,
      user: { id: result.user.id, active: values[:active], approved: values[:approved], suspended: values[:suspended] },
      association: { id: association.id, user_id: result.user.id, uuid: association.provider_uid, provider: association.provider_name },
      platform_id: SpacemitForumIdentity.config.fetch(:platform_id), now: Time.now.to_i,
    )
    session[SpacemitForumIdentity::SESSION_KEY] = marker
    begin
      enrollment_subject = marker.merge(
        forum_user_id: result.user.id,
        username: subject.fetch(:username),
        email: subject.fetch(:email),
        association_version: SpacemitForumIdentity::Authority.association_version(SpacemitForumIdentity.config, values),
      )
      assertion = SpacemitForumIdentity::Enrollment.assertion(
        subject: enrollment_subject,
        user: result.user,
        association: association,
        config: SpacemitForumIdentity.config,
        key: OpenSSL::PKey.read(SpacemitForumIdentity::Configuration.read_key("CREDIS_FORUM_IDENTITY_ASSERTION_KEY")),
        now: Time.now.to_i,
      )
      DB.exec("SELECT register_credis_identity_association(:association,:instance,:platform,CAST(:uuid AS uuid),:user)",
        association: association.id, instance: SpacemitForumIdentity.config.fetch(:instance_id),
        platform: SpacemitForumIdentity.config.fetch(:platform_id), uuid: subject.fetch(:uuid), user: result.user.id)
      DB.exec(<<~SQL, association: association.id, assertion: assertion, digest: Digest::SHA256.hexdigest(assertion))
        INSERT INTO credis_identity_enrollment_outbox(association_id,assertion,assertion_sha256)
        VALUES(:association,CAST(:assertion AS jsonb),:digest)
        ON CONFLICT(association_id) DO UPDATE SET assertion=excluded.assertion,assertion_sha256=excluded.assertion_sha256,
          attempts=0,next_attempt_at=clock_timestamp()
        WHERE credis_identity_enrollment_outbox.status='pending'
      SQL
      SpacemitForumIdentity::Enrollment.deliver(
        association_id: association.id,
        client: SpacemitForumIdentity.service_client(SpacemitForumIdentity.config),
      )
    rescue SpacemitForumIdentity::Enrollment::Rejected,
           SpacemitForumIdentity::Assertion::Rejected,
           SpacemitForumIdentity::ServiceClient::Rejected,
           SpacemitForumIdentity::Configuration::Rejected
      Rails.logger.warn("forum passport enrollment deferred")
    end
  end
end
