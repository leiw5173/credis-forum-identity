# frozen_string_literal: true

require "net/http"
require "json"
require "uri"
require "openssl"

module SpacemitForumIdentity
  class ServiceClient
    class Rejected < StandardError; end
    PATHS = %w[/integrations/forum-identity/challenge /integrations/forum-identity/assertions /integrations/forum-identity/enroll].freeze

    def initialize(origin:, certificate:, key:, trust:)
      @origin = URI.parse(origin)
      raise Rejected, "forum identity peer unavailable" unless
        @origin.is_a?(URI::HTTPS) && @origin.host && @origin.path.empty? && !@origin.userinfo && !@origin.query && !@origin.fragment &&
          certificate.is_a?(OpenSSL::X509::Certificate) && key.is_a?(OpenSSL::PKey::PKey) && trust.is_a?(OpenSSL::X509::Store)
      @certificate, @key, @trust = certificate, key, trust
    rescue URI::InvalidURIError
      raise Rejected, "forum identity peer unavailable"
    end

    def post(path, body)
      raise Rejected, "forum identity peer unavailable" unless PATHS.include?(path) && body.is_a?(Hash)
      encoded = JSON.generate(body)
      raise Rejected, "forum identity peer unavailable" if encoded.bytesize > 10_240
      http = Net::HTTP.new(@origin.host, @origin.port, nil)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.cert_store = @trust
      http.cert = @certificate
      http.key = @key
      http.open_timeout = 5
      http.read_timeout = 10
      request = Net::HTTP::Post.new(path)
      request["Content-Type"] = "application/json"
      request["Accept"] = "application/json"
      request.body = encoded
      raw = +""
      Timeout.timeout(10) do
        http.request(request) do |response|
          raise Rejected, "forum identity peer unavailable" unless response.code == "200" && response["Content-Type"].to_s.split(";").first == "application/json"
          response.read_body do |chunk|
            raw << chunk
            raise Rejected, "forum identity peer unavailable" if raw.bytesize > 8192
          end
        end
      end
      value = JSON.parse(raw, object_class: ProviderUser::UniqueObject, max_nesting: 16)
      raise Rejected, "forum identity peer unavailable" unless value.is_a?(Hash) && value["error_msg"] == "" && value["data"].is_a?(Hash)
      value.fetch("data")
    rescue JSON::ParserError, ProviderUser::Rejected, IOError, SystemCallError, OpenSSL::SSL::SSLError, Timeout::Error
      raise Rejected, "forum identity peer unavailable"
    end
  end
end
