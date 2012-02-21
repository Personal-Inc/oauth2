require 'multi_json'

module OAuth2
  module Strategy
    class ClientCredentials < Base
      # Retrieve an access token given the client id and client secret.
      # Note that you must also provide a <tt>:redirect_uri</tt> option
      # in order to successfully verify your request for most OAuth 2.0
      # endpoints.
      def get_access_token(options={})
        response = @client.request(:post,
                                   @client.access_token_url,
                                   access_token_params(options)
                                  )

        params   = MultiJson.decode(response) rescue nil
        # the ActiveSupport JSON parser won't cause an exception when
        # given a form encoded string, so make sure that it was
        # actually parsed in an Hash. This covers even the case where
        # it caused an exception since it'll still be nil.
        params   = Rack::Utils.parse_query(response) unless params.is_a? Hash

        access   = params.delete('access_token')
        refresh  = params.delete('refresh_token')
        expires_in = params.delete('expires_in')
        OAuth2::AccessToken.new(@client, access, refresh, expires_in, params)
      end

      def access_token_params(options={}) #:nodoc:
        super(options).merge({
          'grant_type'  => 'client_credentials '
        })
      end

    end
  end
end