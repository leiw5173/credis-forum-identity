# frozen_string_literal: true

require "net/http"
require "uri"

module SpacemitForumIdentity
  class ProviderClient
    def self.fetch(token, endpoint, trust: nil)
      raise ProviderUser::Rejected, "forum identity provider rejected" unless
        token.is_a?(String) && token.bytesize.between?(1, 8192) && !token.match?(/[\x00\r\n]/)
      uri = URI.parse(endpoint)
      raise ProviderUser::Rejected, "forum identity provider rejected" unless
        uri.is_a?(URI::HTTPS) && uri.host && !uri.userinfo && !uri.query && !uri.fragment
      http = Net::HTTP.new(uri.host, uri.port, nil)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.cert_store = trust if trust
      http.open_timeout = 5
      http.read_timeout = 10
      request = Net::HTTP::Get.new(uri.request_uri)
      request["Authorization"] = "Bearer #{token}"
      request["Accept"] = "application/json"
      raw = +""
      Timeout.timeout(10) do
        http.request(request) do |response|
          raise ProviderUser::Rejected, "forum identity provider rejected" unless
            response.code == "200" && response["Content-Type"].to_s.split(";").first == "application/json"
          response.read_body do |chunk|
            raw << chunk
            raise ProviderUser::Rejected, "forum identity provider rejected" if raw.bytesize > 65_536
          end
        end
      end
      ProviderUser.parse(raw) do |metadata|
        if ENV["CREDIS_FORUM_EMAIL_VERIFICATION_PROBE"] == "true"
          warn "credis_email_verification_probe present=#{metadata[:present]} type=#{metadata[:type]} strictly_true=#{metadata[:strictly_true]}"
        end
      end
    rescue URI::InvalidURIError, IOError, SystemCallError, OpenSSL::SSL::SSLError, Timeout::Error
      raise ProviderUser::Rejected, "forum identity provider rejected"
    end
  end
end
