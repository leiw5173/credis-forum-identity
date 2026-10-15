# frozen_string_literal: true

module SpacemitForumIdentity
  class AssociationGuard
    class Rejected < StandardError; end

    def self.check!(original:, changed:, operation:, enabled:)
      return unless enabled && original[:provider] == "oauth2_basic"
      identity = %i[user_id uuid provider]
      immutable = original[:user_id].is_a?(Integer) && original[:user_id].positive?
      return unless immutable
      raise Rejected, "forum identity association cannot be moved or deleted" if
        operation == :delete || identity.any? { |field| original[field] != changed[field] }
    end
  end
end
