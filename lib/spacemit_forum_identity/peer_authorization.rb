# frozen_string_literal: true

require "openssl"

module SpacemitForumIdentity
  class PeerAuthorization
    def self.allowed?(certificate, identity)
      return false unless certificate.is_a?(OpenSSL::X509::Certificate) && identity.is_a?(String) && identity.start_with?("spiffe://")
      extension = certificate.extensions.find { |value| value.oid == "subjectAltName" }
      return false unless extension
      extension.value.split(/,\s*/).include?("URI:#{identity}")
    end
  end
end
