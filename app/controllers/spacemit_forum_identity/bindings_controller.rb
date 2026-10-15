# frozen_string_literal: true

module SpacemitForumIdentity
  class BindingsController < ::ApplicationController
    requires_plugin SpacemitForumIdentity::PLUGIN_NAME
    wrap_parameters false
    requires_login only: %i[create]
    skip_before_action :check_xhr, only: :show
    skip_before_action :verify_authenticity_token, :check_xhr, :redirect_to_login_if_required, only: :current_proof

    def show
      raise Discourse::NotFound unless SpacemitForumIdentity.enabled? && SpacemitForumIdentity.configured?
      response.headers["Cache-Control"] = "no-store"
      response.headers["Referrer-Policy"] = "no-referrer"
      @binding_signed_in = current_user.present?
      render "spacemit_forum_identity/bindings/show", layout: false
    end

    def create
      raise Discourse::NotFound unless SpacemitForumIdentity.enabled? && SpacemitForumIdentity.configured?
      raise Discourse::InvalidParameters.new(:binding) unless request.request_parameters.keys == ["handle"] && request.raw_post.bytesize <= 1024
      association = UserAssociatedAccount.find_by(provider_name: "oauth2_basic", user_id: current_user.id)
      raise Authority::Rejected, "forum identity unavailable" unless association
      marker = session[SpacemitForumIdentity::SESSION_KEY]
      marker = marker.symbolize_keys if marker.is_a?(Hash)
      config = SpacemitForumIdentity.config
      subject = nil
      UserAssociatedAccount.transaction do
        association.lock!
        values = SpacemitForumIdentity.association_values(association)
        subject = Authority.for_binding(config: config, association: values, marker: marker, current_user_id: current_user.id, now: Time.now.to_i)
        DB.exec("SELECT register_credis_identity_association(:association,:instance,:platform,CAST(:uuid AS uuid),:user)", association: association.id, instance: config.fetch(:instance_id), platform: config.fetch(:platform_id), uuid: subject.fetch(:uuid), user: current_user.id)
      end
      client = SpacemitForumIdentity.service_client(config)
      key = OpenSSL::PKey.read(Configuration.read_key("CREDIS_FORUM_IDENTITY_ASSERTION_KEY"))
      result = Binding.complete(handle: params.require(:handle), subject: subject, config: config, client: client, key: key, now: Time.now.to_i)
      response.headers["Cache-Control"] = "no-store"
      render json: result
    rescue Authority::Rejected, Binding::Rejected, ServiceClient::Rejected, Configuration::Rejected, Assertion::Rejected
      render json: { error: "forum binding unavailable; recent provider login required" }, status: :conflict
    end

    def current_proof
      raise Discourse::NotFound unless SpacemitForumIdentity.enabled? && SpacemitForumIdentity.configured?
      # The dedicated TLS gateway must pass the certificate as trusted Rack data,
      # never copy a browser-controlled HTTP forwarding header into this value.
      certificate = request.env["credis.verified_client_certificate"]
      config = SpacemitForumIdentity.config
      head :forbidden and return unless certificate.is_a?(OpenSSL::X509::Certificate) &&
        request.env["credis.client_certificate_verified"] == true && PeerAuthorization.allowed?(certificate, config.fetch(:peer_identity))
      raise Discourse::InvalidParameters.new(:proof) if request.raw_post.bytesize > 2048
      request_data = JSON.parse(request.raw_post, object_class: ProviderUser::UniqueObject)
      association = UserAssociatedAccount.find_by(provider_name: "oauth2_basic", user_id: request_data["forum_user_id"])
      raise CurrentProof::Rejected, "forum association unavailable" unless association
      saved = DB.query("SELECT provider_uid::text,user_id FROM credis_identity_associations WHERE association_id=:id AND instance_id=:instance AND platform_id=:platform", id: association.id, instance: config.fetch(:instance_id), platform: config.fetch(:platform_id)).first
      raise CurrentProof::Rejected, "forum association unavailable" unless saved && saved.provider_uid == association.provider_uid && saved.user_id == association.user_id
      values = SpacemitForumIdentity.association_values(association)
      version = Authority.association_version(config, values)
      claims = CurrentProof.claims(request: request_data, config: config, association: values, version: version, authenticated_at: association.last_used.to_i, now: Time.now.to_i)
      key = OpenSSL::PKey.read(Configuration.read_key("CREDIS_FORUM_IDENTITY_CURRENT_KEY"))
      raw = Assertion.sign(claims: claims, key: key, key_id: config.fetch(:current_key_id), purpose: "liveness")
      response.headers["Cache-Control"] = "no-store"
      render body: raw, content_type: "application/json"
    rescue JSON::ParserError, ProviderUser::Rejected, CurrentProof::Rejected, Authority::Rejected, Configuration::Rejected, Assertion::Rejected
      render json: { error: "forum current proof unavailable" }, status: :conflict
    end
  end
end
