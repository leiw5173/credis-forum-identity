# frozen_string_literal: true

require "json"
require "uri"

module SpacemitForumIdentity
  class Configuration
    class Rejected < StandardError; end

    def self.load
      path = ENV["CREDIS_FORUM_IDENTITY_CONFIG_FILE"]
      reject! if ENV.key?("CREDIS_FORUM_IDENTITY_CONFIG") || !path || !path.start_with?("/")
      info = File.lstat(path)
      reject! unless info.file? && !info.symlink? && (info.mode & 0o077).zero? && info.size.between?(1, 16_384)
      raw = File.binread(path, 16_385)
      values = JSON.parse(raw, object_class: ProviderUser::UniqueObject)
      allowed = %w[instance_id platform_id provider client_id authorize_url token_url userinfo_url audience peer_identity assertion_key_id current_key_id]
      reject! unless values.is_a?(Hash) && values.keys.sort == allowed.sort && values["provider"] == "oauth2_basic" && values["client_id"] == "discourse"
      config = values.transform_keys(&:to_sym)
      reject! unless config[:instance_id].is_a?(Integer) && config[:instance_id].positive? &&
        Authority.text?(config[:platform_id]) && Authority.text?(config[:assertion_key_id]) &&
        Authority.text?(config[:current_key_id]) && config[:assertion_key_id] != config[:current_key_id]
      endpoints = %i[authorize_url token_url userinfo_url audience].map { |field| URI.parse(config.fetch(field)) }
      reject! unless endpoints.all? { |uri| uri.is_a?(URI::HTTPS) && uri.host && !uri.userinfo && !uri.query && !uri.fragment } &&
        endpoints.first(3).map { |uri| [uri.scheme, uri.host, uri.port] }.uniq.length == 1 && endpoints.last.path.empty?
      peer = URI.parse(config[:peer_identity])
      reject! unless peer.scheme == "spiffe" && peer.host && !peer.path.empty? && !peer.userinfo && !peer.query && !peer.fragment
      config
    rescue JSON::ParserError, SystemCallError, ProviderUser::Rejected, URI::InvalidURIError, TypeError, KeyError
      reject!
    end

    def self.read_key(name)
      path = ENV[name + "_FILE"]
      reject! if ENV.key?(name) || !path || !path.start_with?("/")
      info = File.lstat(path)
      reject! unless info.file? && !info.symlink? && (info.mode & 0o077).zero? && info.size.between?(1, 16_384)
      File.binread(path, 16_385)
    rescue SystemCallError
      reject!
    end

    def self.reject!
      raise Rejected, "forum identity configuration rejected"
    end
  end
end
