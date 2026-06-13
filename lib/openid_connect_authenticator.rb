# frozen_string_literal: true
# require_relative 'overrided_managed_auth'
# class OpenIDConnectAuthenticator < CustomAuth::OverridedManagedAuthenticator
class RobloxOpenIDConnectAuthenticator < Auth::ManagedAuthenticator
  def name
    "rbxoidc"
  end

  def can_revoke?
    SiteSetting.openid_connect_rbx_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.openid_connect_rbx_allow_association_change
  end

  def enabled?
    SiteSetting.openid_connect_rbx_enabled
  end

  def primary_email_verified?(auth)
    supplied_verified_boolean = auth["extra"]["raw_info"]["email_verified"]
    # If the payload includes the email_verified boolean, use it. Otherwise assume true
    if supplied_verified_boolean.nil?
      true
    else
      # Many providers violate the spec, and send this as a string rather than a boolean
      supplied_verified_boolean == true || supplied_verified_boolean == "true"
    end
  end

  def always_update_user_email?
    SiteSetting.openid_connect_rbx_overrides_email
  end

  def always_update_user_avatar?
    SiteSetting.openid_connect_rbx_overrides_avatar
  end

  def match_by_email
    SiteSetting.openid_connect_rbx_match_by_email
  end

  def discovery_document
    document_url = SiteSetting.openid_connect_rbx_discovery_document.presence
    if !document_url
      oidc_log("No discovery document URL specified", error: true)
      return
    end

    from_cache = true
    result =
      Discourse
        .cache
        .fetch("openid-connect-discovery-#{document_url}", expires_in: 10.minutes) do
          from_cache = false
          oidc_log("Fetching discovery document from #{document_url}")
          connection =
            Faraday.new(request: { timeout: request_timeout_seconds }) do |c|
              c.use Faraday::Response::RaiseError
              c.adapter FinalDestination::FaradayAdapter
            end
          JSON.parse(connection.get(document_url).body)
        rescue Faraday::Error, JSON::ParserError => e
          oidc_log("Fetching discovery document raised error #{e.class} #{e.message}", error: true)
          nil
        end

    oidc_log("Discovery document loaded from cache") if from_cache
    oidc_log("Discovery document is\n\n#{result.to_yaml}")

    result
  end

  def oidc_log(message, error: false)
    if error
      Rails.logger.error("RBXOIDC Log: #{message}")
    elsif SiteSetting.openid_connect_rbx_verbose_logging
      Rails.logger.warn("RBXOIDC Log: #{message}")
    end
  end

  def register_middleware(omniauth)
    omniauth.provider :openid_connect_rbx,
                      name: :rbxoidc,
                      error_handler:
                        lambda { |error, message|
                          handlers = SiteSetting.openid_connect_rbx_error_redirects.split("\n")
                          handlers.each do |row|
                            parts = row.split("|")
                            return parts[1] if message.include? parts[0]
                          end
                          nil
                        },
                      verbose_logger: lambda { |message| oidc_log(message) },
                      setup:
                        lambda { |env|
                          opts = env["omniauth.strategy"].options

                          token_params = {}
                          token_params[
                            :scope
                          ] = SiteSetting.openid_connect_rbx_token_scope if SiteSetting.openid_connect_rbx_token_scope.present?

                          opts.deep_merge!(
                            client_id: SiteSetting.openid_connect_rbx_client_id,
                            client_secret: SiteSetting.openid_connect_rbx_client_secret,
                            discovery_document: discovery_document,
                            scope: SiteSetting.openid_connect_rbx_authorize_scope,
                            token_params: token_params,
                            passthrough_authorize_options:
                              SiteSetting.openid_connect_rbx_authorize_parameters.split("|"),
                            claims: SiteSetting.openid_connect_rbx_claims,
                          )

                          opts[:client_options][:connection_opts] = {
                            request: {
                              timeout: request_timeout_seconds,
                            },
                          }

                          opts[:client_options][:connection_build] = lambda do |builder|
                            if SiteSetting.openid_connect_rbx_verbose_logging
                              builder.response :logger,
                                               Rails.logger,
                                               { bodies: true, formatter: OIDCFaradayFormatter }
                            end

                            builder.request :url_encoded # form-encode POST params
                            builder.adapter FinalDestination::FaradayAdapter # make requests with FinalDestination::HTTP
                          end
                        }
  end

  def retrieve_avatar(user, url)
    return unless user && url
    # Check if the user has a custom avatar already AND the always_update_user_avatar? setting is false
    
    return if user.user_avatar.try(:custom_upload_id).present? && !always_update_user_avatar?
    Jobs.enqueue(:download_avatar_from_url, url: url, user_id: user.id, override_gravatar: true)
  end

  def request_timeout_seconds
    GlobalSetting.openid_connect_rbx_request_timeout_seconds
  end
end
