# frozen_string_literal: true

module SpacemitForumIdentity
  module AuthenticatorExtension
    def after_authenticate(auth, existing_account: nil)
      return super unless SpacemitForumIdentity.enabled?
      raise Authentication::Rejected, "forum identity configuration rejected" unless SpacemitForumIdentity.configured?
      subject = SpacemitForumIdentity.fetch_subject(auth.dig(:credentials, :token))
      cleaned = Authentication.sanitized_auth(auth, subject)
      # Call ManagedAuthenticator directly, retaining oauth2_basic associations
      # without its unbounded/debug/token-persisting userinfo path.
      managed = self.class.superclass.instance_method(:after_authenticate)
      result = managed.bind_call(self, cleaned, existing_account: nil)
      auth[:spacemit_identity_subject] = subject
      result
    end

    def match_by_email
      SpacemitForumIdentity.enabled? ? false : super
    end

    def match_by_username
      SpacemitForumIdentity.enabled? ? false : super
    end

    def can_connect_existing_user?
      SpacemitForumIdentity.enabled? ? false : super
    end

    def can_revoke?
      SpacemitForumIdentity.enabled? ? false : super
    end

    def primary_email_verified?(auth)
      SpacemitForumIdentity.enabled? ? false : super
    end
  end
end
