# frozen_string_literal: true

require "digest"
require "json"
require "uri"

module SpacemitForumIdentity
  class Authority
    class Rejected < StandardError; end

    def self.for_binding(config:, association:, marker:, current_user_id:, now:)
      reject! unless config.is_a?(Hash) && association.is_a?(Hash) && marker.is_a?(Hash)
      instance, platform, provider = config.values_at(:instance_id, :platform_id, :provider)
      reject! unless instance.is_a?(Integer) && instance.positive? && text?(platform) &&
        provider == "oauth2_basic" && config[:client_id] == "discourse"
      urls = %i[authorize_url token_url userinfo_url audience].map { |key| URI.parse(config.fetch(key)) }
      reject! unless urls.all? { |uri| uri.is_a?(URI::HTTPS) && uri.host && !uri.userinfo && !uri.query && !uri.fragment } &&
        urls.first(3).map(&:origin).uniq.length == 1
      id, user, uuid = association.values_at(:id, :user_id, :uuid)
      reject! unless id.is_a?(Integer) && id.positive? && user.is_a?(Integer) && user.positive? &&
        current_user_id == user && association[:provider] == provider &&
        association[:active] == true && association[:approved] == true && association[:suspended] == false &&
        uuid.is_a?(String) && uuid.match?(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/) &&
        uuid != "00000000-0000-0000-0000-000000000000"
      at = marker[:authenticated_at]
      reject! unless now.is_a?(Integer) && at.is_a?(Integer) && at.positive? &&
        at <= now && now - at <= 300 && marker[:association_id] == id &&
        marker[:user_id] == user && marker[:uuid] == uuid && marker[:provider] == provider && marker[:platform_id] == platform
      version = association_version(config, association)
      { forum_user_id: user, uuid: uuid, authenticated_at: at, association_version: version }
    rescue KeyError, URI::InvalidURIError
      reject!
    end

    def self.association_version(config, association)
      Digest::SHA256.hexdigest(JSON.generate(["spacemit-forum-association-v1", config.fetch(:instance_id), config.fetch(:platform_id), config.fetch(:provider), association.fetch(:id), association.fetch(:user_id), association.fetch(:uuid)]))
    end

    def self.text?(value)
      value.is_a?(String) && value.bytesize.between?(1, 255) && value.strip == value && !value.match?(/[\x00\r\n]/)
    end

    def self.reject!
      raise Rejected, "forum identity authority rejected"
    end
  end
end
