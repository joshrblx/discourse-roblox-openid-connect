# frozen_string_literal: true

# name: discourse-roblox-openid-connect
# about: Add support for openid-connect as a login provider
# version: 1.0
# authors: David Taylor (Edited by Headless & j0shrbIx)
# url: https://github.com/Djboy08/discourse-roblox-openid-connect
# transpile_js: true

enabled_site_setting :openid_connect_rbx_enabled

require_relative "lib/openid_connect_faraday_formatter"
require_relative "lib/omniauth_open_id_connect"
require_relative "lib/roblox_openid_connect_authenticator"

GlobalSetting.add_default :openid_connect_rbx_request_timeout_seconds, 10

# RP-initiated logout
# https://openid.net/specs/openid-connect-rpinitiated-1_0.html
on(:before_session_destroy) do |data|
  next if !SiteSetting.openid_connect_rbx_rp_initiated_logout

  authenticator = RobloxOpenIDConnectAuthenticator.new

  oidc_record = data[:user]&.user_associated_accounts&.find_by(provider_name: "rbxoidc")
  if !oidc_record
    authenticator.oidc_log "Logout: No rbxoidc user_associated_account record for user"
    next
  end

  token = oidc_record.extra["id_token"]
  if !token
    authenticator.oidc_log "Logout: No rbxoidc id_token in user_associated_account record"
    next
  end

  end_session_endpoint = authenticator.discovery_document["end_session_endpoint"].presence
  if !end_session_endpoint
    authenticator.oidc_log "Logout: No end_session_endpoint found in discovery document",
                           error: true
    next
  end

  begin
    uri = URI.parse(end_session_endpoint)
  rescue URI::Error
    authenticator.oidc_log "Logout: unable to parse end_session_endpoint #{end_session_endpoint}",
                           error: true
  end

  authenticator.oidc_log "Logout: Redirecting user_id=#{data[:user].id} to end_session_endpoint"

  params = URI.decode_www_form(String(uri.query))

  params << ["id_token_hint", token]

  post_logout_redirect = SiteSetting.openid_connect_rbx_rp_initiated_logout_redirect.presence
  params << ["post_logout_redirect_uri", post_logout_redirect] if post_logout_redirect

  uri.query = URI.encode_www_form(params)
  data[:redirect_url] = uri.to_s
end

auth_provider authenticator: RobloxOpenIDConnectAuthenticator.new