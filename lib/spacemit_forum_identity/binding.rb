# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "securerandom"

module SpacemitForumIdentity
  class Binding
    class Rejected < StandardError; end
    def self.complete(handle:, subject:, config:, client:, key:, now:)
      decoded = Base64.urlsafe_decode64(handle)
      raise Rejected, "forum binding unavailable" unless decoded.bytesize == 32 && Base64.urlsafe_encode64(decoded, padding: false) == handle
      inquiry = client.post("/integrations/forum-identity/challenge", {
        handle: handle, uuid: subject.fetch(:uuid), instance_id: config.fetch(:instance_id), platform_id: config.fetch(:platform_id),
      })
      digest = Digest::SHA256.hexdigest(handle)
      raise Rejected, "forum binding unavailable" unless inquiry["challenge_digest"] == digest &&
        inquiry["request_version"].is_a?(String) && !inquiry["request_version"].empty? &&
        inquiry["expires_at"].is_a?(Integer) && inquiry["expires_at"] > now && inquiry["expires_at"] <= now + 300
      claims = {
        "version" => 1, "instance_id" => config.fetch(:instance_id), "platform_id" => config.fetch(:platform_id),
        "provider" => config.fetch(:provider), "uuid" => subject.fetch(:uuid), "forum_user_id" => subject.fetch(:forum_user_id),
        "audience" => config.fetch(:audience), "request_version" => inquiry.fetch("request_version"),
        "association_version" => subject.fetch(:association_version), "challenge_digest" => digest, "nonce_digest" => "",
        "jti" => SecureRandom.hex(32), "authenticated_at" => subject.fetch(:authenticated_at), "issued_at" => now, "expires_at" => now + 60,
      }
      assertion = Assertion.sign(claims: claims, key: key, key_id: config.fetch(:assertion_key_id), purpose: "binding")
      ack = client.post("/integrations/forum-identity/assertions", { handle: handle, assertion: JSON.parse(assertion) })
      raise Rejected, "forum binding unavailable" unless ack["durable_ack"] == true
      { url: "#{config.fetch(:audience)}/settings/forum-binding##{handle}" }
    rescue ArgumentError, KeyError
      raise Rejected, "forum binding unavailable"
    end
  end
end
