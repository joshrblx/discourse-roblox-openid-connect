# frozen_string_literal: true
class RobloxOpenIDConnectAuthenticator < Auth::ManagedAuthenticator
  # ============================================================
  # CONFIGURATION — edit these
  # ============================================================

  GROUPS = [
    {
      roblox_group_id: 218181086,        # Your first Roblox group ID
      rank_map: {
        200 => { discourse_group: "developers", title: nil },
        148 => { discourse_group: "horizon", title: nil },
        149 => { discourse_group: "horizon", title: nil },
        150 => { discourse_group: "horizon", title: nil },
        5 => { discourse_group: "quality-assurance", title: "Quality Assurance" }
      }
    },
    {
      roblox_group_id: 860308753,        # Your second Roblox group ID
      rank_map: {
        106 => { discourse_group: nil, title: "Chief Executive Officer" },
        105 => { discourse_group: nil, title: "Deputy Chief Executive" },
      }
    },
    {
      roblox_group_id: 879181875,
      rank_map: {
        54 => { discourse_group: nil, title: "Commissioner" },
        53 => { discourse_group: nil, title: "Deputy Commissioner" },
      }
    },
    {
      roblox_group_id: 418300484,
      rank_map: {
        106 => { discourse_group: nil, title: "Brigadier" },
        105 => { discourse_group: nil, title: "Colonel" },
      }
    }
    # Add more groups here in the same format
  ]
  # ============================================================

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
    if supplied_verified_boolean.nil?
      true
    else
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
                          token_params[:scope] = SiteSetting.openid_connect_rbx_token_scope if SiteSetting.openid_connect_rbx_token_scope.present?

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
                            request: { timeout: request_timeout_seconds },
                          }

                          opts[:client_options][:connection_build] = lambda do |builder|
                            if SiteSetting.openid_connect_rbx_verbose_logging
                              builder.response :logger,
                                               Rails.logger,
                                               { bodies: true, formatter: OIDCFaradayFormatter }
                            end
                            builder.request :url_encoded
                            builder.adapter FinalDestination::FaradayAdapter
                          end
                        }
  end

  def retrieve_avatar(user, url)
    return unless user && url
    return if user.user_avatar.try(:custom_upload_id).present? && !always_update_user_avatar?
    Jobs.enqueue(:download_avatar_from_url, url: url, user_id: user.id, override_gravatar: true)
  end

  def request_timeout_seconds
    GlobalSetting.openid_connect_rbx_request_timeout_seconds
  end

  def after_authenticate(auth_token, existing_account: nil)
    result = super

    # Auto-generate email if blank (SMTP disabled)
    if result.email.blank?
      uid = auth_token[:uid] || auth_token.dig(:extra, :raw_info, :sub)
      result.email = "roblox_#{uid}@#{Discourse.current_hostname}"
      result.email_valid = true
    end

    # Sync Roblox group ranks to Discourse groups
    if result.user
      roblox_uid = auth_token[:uid] || auth_token.dig(:extra, :raw_info, :sub)
      sync_roblox_groups(result.user, roblox_uid) if roblox_uid
    end

    result
  end

  private

  def fetch_roblox_rank(roblox_group_id, roblox_uid)
    url = "https://apis.roblox.com/cloud/v2/groups/#{roblox_group_id}/memberships?filter=user=='users/#{roblox_uid}'"
    connection = Faraday.new do |c|
      c.adapter FinalDestination::FaradayAdapter
    end
    response = connection.get(url) do |req|
      req.headers["x-api-key"] = SiteSetting.openid_connect_rbx_roblox_api_key
    end
    return 0 unless response.status == 200
    data = JSON.parse(response.body)
    memberships = data["groupMemberships"] || []
    return 0 if memberships.empty?
    memberships.first.dig("role", "rank") || 0
  rescue => e
    oidc_log("Error fetching Roblox rank for group #{roblox_group_id}: #{e.message}", error: true)
    0
  end

  def sync_roblox_groups(user, roblox_uid)
    highest_title = nil

    GROUPS.each do |group_config|
      rank = fetch_roblox_rank(group_config[:roblox_group_id], roblox_uid)
      oidc_log("Roblox group #{group_config[:roblox_group_id]}: user #{roblox_uid} has rank #{rank}")

      # Collect all discourse group names for this Roblox group
      all_discourse_groups = group_config[:rank_map].values.map { |v| v[:discourse_group] }.uniq

      # Determine which groups the user qualifies for
      qualified = group_config[:rank_map]
        .select { |min_rank, _| rank >= min_rank }
        .values

      qualified_group_names = qualified.map { |v| v[:discourse_group] }

      # Add/remove groups
      all_discourse_groups.each do |group_name|
        discourse_group = Group.find_by(name: group_name)
        next unless discourse_group

        if qualified_group_names.include?(group_name)
          discourse_group.add(user) unless discourse_group.users.include?(user)
          oidc_log("Added #{user.username} to group #{group_name}")
        else
          discourse_group.remove(user) if discourse_group.users.include?(user)
          oidc_log("Removed #{user.username} from group #{group_name}")
        end
      end

      # Track highest title from qualified ranks
      qualified.each do |v|
        highest_title ||= v[:title] if v[:title]
      end
    end

    # Set title to highest earned title across all groups, or clear it
    user.update(title: highest_title || "")
  rescue => e
    oidc_log("Error syncing groups for #{user.username}: #{e.message}", error: true)
  end
end