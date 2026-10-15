# frozen_string_literal: true

require "securerandom"

module SpacemitForumIdentity
  class CurrentProof
    class Rejected < StandardError; end
    FIELDS = %w[instance_id forum_user_id platform_id request_version association_version nonce].freeze
    def self.claims(request:, config:, association:, version:, authenticated_at:, now:)
      raise Rejected, "forum current proof unavailable" unless request.is_a?(Hash) && request.keys.sort == FIELDS.sort &&
        request["instance_id"] == config[:instance_id] && request["platform_id"] == config[:platform_id] &&
        request["forum_user_id"] == association[:user_id] && request["association_version"] == version &&
        association[:provider] == config[:provider] && association[:active] == true && association[:approved] == true && association[:suspended] == false &&
        request["nonce"].is_a?(String) && request["nonce"].match?(/\A[0-9a-f]{64}\z/) &&
        request["request_version"].is_a?(String) && request["request_version"].bytesize.between?(1, 255) &&
        authenticated_at.is_a?(Integer) && authenticated_at.positive? && authenticated_at <= now
      {
        "version" => 1, "instance_id" => config.fetch(:instance_id), "platform_id" => config.fetch(:platform_id),
        "provider" => config.fetch(:provider), "uuid" => association.fetch(:uuid), "forum_user_id" => association.fetch(:user_id),
        "audience" => config.fetch(:audience), "request_version" => request.fetch("request_version"),
        "association_version" => version, "challenge_digest" => "", "nonce_digest" => request.fetch("nonce"),
        "jti" => SecureRandom.hex(32), "authenticated_at" => authenticated_at, "issued_at" => now, "expires_at" => now + 300,
      }
    end
  end
end
