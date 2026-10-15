# frozen_string_literal: true

require "json"

module SpacemitForumIdentity
  class ProviderUser
    class Rejected < StandardError; end

    class UniqueObject < Hash
      def []=(key, value)
        raise Rejected, "forum identity provider rejected" if key?(key)
        super
      end
    end

    def self.parse(raw)
      reject! unless raw.is_a?(String) && raw.bytesize.between?(1, 65_536) &&
        raw.dup.force_encoding(Encoding::UTF_8).valid_encoding?
      body = JSON.parse(raw, object_class: UniqueObject, max_nesting: 32)
      reject! unless body.is_a?(Hash) && body["code"] == 200 && body["data"].is_a?(Hash)
      user = body.fetch("data")
      uuid, username, email = user.values_at("id", "username", "email")
      reject! unless uuid.is_a?(String) &&
        uuid.match?(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/) &&
        uuid != "00000000-0000-0000-0000-000000000000" && user["status"] == "1"
      reject! unless text?(username) && text?(email) &&
        email.match?(/\A[^\s<>@]+@[^\s<>@]+\z/)
      if block_given?
        value = user["email_verified"]
        type = case value
        when true, false then "boolean"
        when String then "string"
        when Numeric then "number"
        when NilClass then "null"
        else "other"
        end
        present = user.key?("email_verified")
        yield({ present: present, type: present ? type : "absent", strictly_true: value.equal?(true) })
      end
      { uuid: uuid, username: username, email: email, email_verified: false }
    rescue JSON::ParserError, JSON::NestingError
      reject!
    end

    def self.text?(value)
      value.is_a?(String) && value.bytesize.between?(1, 254) &&
        value.strip == value && !value.match?(/[\x00\r\n]/)
    end

    def self.reject!
      raise Rejected, "forum identity provider rejected"
    end
  end
end
