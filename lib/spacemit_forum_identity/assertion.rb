# frozen_string_literal: true

require "json"
require "base64"
require "openssl"

module SpacemitForumIdentity
  class Assertion
    class Rejected < StandardError; end

    FIELDS = %w[
      version instance_id platform_id provider uuid forum_user_id audience
      request_version association_version challenge_digest nonce_digest jti
      authenticated_at issued_at expires_at
    ].freeze
    ENROLLMENT_FIELDS = %w[
      version instance_id platform_id provider uuid forum_user_id audience
      association_version username email email_verified jti authenticated_at issued_at expires_at
    ].freeze
    DOMAINS = {
      "binding" => "spacemit-forum-binding-v1",
      "liveness" => "spacemit-forum-liveness-v1",
      "enrollment" => "spacemit-forum-enrollment-v1",
    }.freeze

    def self.sign(claims:, key:, key_id:, purpose:)
      domain = DOMAINS[purpose]
      fields = purpose == "enrollment" ? ENROLLMENT_FIELDS : FIELDS
      raise Rejected, "forum identity proof rejected" unless
        domain && claims.is_a?(Hash) && claims.keys.sort == fields.sort &&
          key.is_a?(OpenSSL::PKey::PKey) && key.oid == "ED25519" &&
          key_id.is_a?(String) && key_id.length.between?(1, 255) &&
          !key_id.match?(/[\x00\r\n]/)

      # Field order is shared with the Go verifier; do not depend on caller order.
      payload = JSON.generate(fields.to_h { |field| [field, claims.fetch(field)] })
      signature = key.sign(nil, "#{domain}\n#{payload}")
      JSON.generate(
        "key_id" => key_id,
        "payload" => Base64.urlsafe_encode64(payload, padding: false),
        "signature" => Base64.urlsafe_encode64(signature, padding: false),
      )
    rescue OpenSSL::PKey::PKeyError, JSON::GeneratorError
      raise Rejected, "forum identity proof rejected"
    end
  end
end
