# frozen_string_literal: true

require "json"
require "securerandom"

module SpacemitForumIdentity
  class Enrollment
    class Rejected < StandardError; end

    def self.assertion(subject:, user:, association:, config:, key:, now:)
      raise Rejected, "forum enrollment unavailable" unless
        subject[:forum_user_id] == user.id && association.user_id == user.id &&
          association.provider_name == "oauth2_basic" && association.provider_uid == subject[:uuid] &&
          subject[:authenticated_at].is_a?(Integer) && now - subject[:authenticated_at] <= 300

      claims = {
        "version" => 1, "instance_id" => config.fetch(:instance_id), "platform_id" => config.fetch(:platform_id),
        "provider" => config.fetch(:provider), "uuid" => subject.fetch(:uuid), "forum_user_id" => user.id,
        "audience" => config.fetch(:audience), "association_version" => subject.fetch(:association_version),
        "username" => subject.fetch(:username), "email" => subject.fetch(:email), "email_verified" => false,
        "jti" => SecureRandom.hex(32), "authenticated_at" => subject.fetch(:authenticated_at),
        "issued_at" => now, "expires_at" => now + 60,
      }
      Assertion.sign(claims: claims, key: key, key_id: config.fetch(:assertion_key_id), purpose: "enrollment")
    rescue ArgumentError, KeyError
      raise Rejected, "forum enrollment unavailable"
    end

    def self.deliver(association_id:, client:, row: nil)
      row ||= DB.query_single(<<~SQL, association: association_id).first
        SELECT assertion::text FROM credis_identity_enrollment_outbox
        WHERE association_id=:association AND status='pending' AND next_attempt_at<=clock_timestamp()
      SQL
      return false unless row

      ack = client.post("/integrations/forum-identity/enroll", JSON.parse(row))
      raise Rejected, "forum enrollment unavailable" unless ack["durable_ack"] == true && ack["binding_id"].is_a?(Integer)

      if defined?(DB) && DB.respond_to?(:exec)
        DB.exec(<<~SQL, association: association_id)
          UPDATE credis_identity_enrollment_outbox SET status='delivered',attempts=attempts+1,delivered_at=clock_timestamp()
          WHERE association_id=:association AND status='pending'
        SQL
      end
      true
    rescue JSON::ParserError
      raise Rejected, "forum enrollment unavailable"
    end
  end
end
