# To change this template, choose Tools | Templates
# and open the template in the editor.

require File.expand_path(File.dirname(__FILE__) + '/../../spec_helper')

describe OAuth2::Strategy::ClientCredentials do
  let(:client) do
    cli = OAuth2::Client.new('abc', 'def', :site => 'http://api.example.com')
    cli.connection.build do |b|
      b.adapter :test do |stub|
        stub.post('/oauth/access_token') do |env|
          case @mode
          when "formencoded"
            [200, {}, 'expires_in=600&access_token=salmon&refresh_token=trout']
          when "json"
            [200, {}, '{"expires_in":600,"access_token":"salmon","refresh_token":"trout"}']
          end
        end
      end
    end
    cli
  end

  subject {client.credentials}

  %w(json formencoded).each do |mode|
    describe "#get_access_token (#{mode})" do
      before do
        @mode = mode
        @access = subject.get_access_token()
      end

      it 'returns AccessToken with same Client' do
        @access.client.should == client
      end

      it 'returns AccessToken with #token' do
        @access.token.should == 'salmon'
      end

      it 'returns AccessToken with #refresh_token' do
        @access.refresh_token.should == 'trout'
      end

      it 'returns AccessToken with #expires_in' do
        @access.expires_in.should == 600
      end

      it 'returns AccessToken with #expires_at' do
        @access.expires_at.should be_kind_of(Time)
      end
    end
  end

end