# frozen_string_literal: true

require "openssl"

module SpacemitForumIdentity
  class VerifiedPeer
    def initialize(app)
      @app = app
    end
    def call(env)
      env.delete("credis.client_certificate_verified")
      env.delete("credis.verified_client_certificate")
      # Puma exposes peercert only after its configured TLS peer verification.
      # HTTP header names are prefixed HTTP_ and cannot become this Rack key.
      certificate = env["puma.peercert"]
      if env["rack.url_scheme"] == "https" && certificate.is_a?(OpenSSL::X509::Certificate)
        env["credis.client_certificate_verified"] = true
        env["credis.verified_client_certificate"] = certificate
      end
      @app.call(env)
    end
  end
end
