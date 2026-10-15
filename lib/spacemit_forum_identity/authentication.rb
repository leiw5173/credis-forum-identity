# frozen_string_literal: true

module SpacemitForumIdentity
  class Authentication
    class Rejected < StandardError; end

    def self.sanitized_auth(auth, subject)
      raise Rejected, "forum authentication rejected" unless auth.is_a?(Hash) && subject.is_a?(Hash) && auth[:provider] == "oauth2_basic"
      {
        provider: "oauth2_basic", uid: subject.fetch(:uuid),
        credentials: {}, extra: {}, session: auth[:session],
        info: { nickname: subject.fetch(:username), email: subject.fetch(:email), email_verified: false },
      }
    end

    def self.marker(subject:, user:, association:, platform_id:, now:)
      raise Rejected, "forum authentication rejected" unless
        user.is_a?(Hash) && association.is_a?(Hash) && subject.is_a?(Hash) &&
          user[:id].is_a?(Integer) && user[:id].positive? && user[:active] == true &&
          user[:approved] == true && user[:suspended] == false &&
          association[:id].is_a?(Integer) && association[:id].positive? &&
          association[:user_id] == user[:id] && association[:uuid] == subject[:uuid] &&
          association[:provider] == "oauth2_basic" && platform_id.is_a?(String) &&
          !platform_id.empty? && now.is_a?(Integer) && now.positive?
      {
        association_id: association[:id], user_id: user[:id], uuid: subject[:uuid],
        provider: "oauth2_basic", platform_id: platform_id, authenticated_at: now,
      }
    end
  end
end
