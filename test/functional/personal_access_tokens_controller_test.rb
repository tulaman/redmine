# frozen_string_literal: true

# Redmine - project management software
# Copyright (C) 2006-  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require_relative '../test_helper'

class PersonalAccessTokensControllerTest < Redmine::ControllerTest
  def setup
    Setting.rest_api_enabled = '1'
    @request.session[:user_id] = 2
    @user = User.find(2)
    ActionMailer::Base.deliveries.clear
  end

  def teardown
    Setting.rest_api_enabled = '0'
  end

  def create_token(user = @user, name = 'CI')
    PersonalAccessToken.create!(:user => user, :name => name, :expiration_date => user.today + 30)
  end

  def test_index_should_list_own_tokens_only
    own = create_token
    other = create_token(User.find(3), 'Other')
    get :index
    assert_response :success
    assert_select "tr#personal-access-token-#{own.id}" do
      assert_select 'td.name', :text => 'CI'
      assert_select 'td.token', :text => own.masked_value
      assert_select 'td.buttons a.icon-del'
    end
    assert_select "tr#personal-access-token-#{other.id}", 0
  end

  def test_index_should_mark_expired_tokens
    token = create_token
    PersonalAccessToken.where(:id => token.id).update_all(:expires_on => 1.day.ago)
    get :index
    assert_select "tr#personal-access-token-#{token.id}.expired td.expires_on", :text => /expired/
  end

  def test_index_without_tokens
    get :index
    assert_response :success
    assert_select 'p.nodata'
  end

  def test_new
    freeze_time do
      get :new
      assert_response :success
      assert_select 'form[action=?]', '/my/personal_access_tokens' do
        assert_select 'input[name=?]', 'personal_access_token[name]'
        assert_select 'input[type=date][name=?][value=?]', 'personal_access_token[expiration_date]', (@user.today + 30).iso8601
      end
    end
  end

  def test_create_should_show_plaintext_once
    assert_difference 'PersonalAccessToken.count', 1 do
      post :create, :params => {:personal_access_token => {:name => 'Deploy', :expiration_date => (@user.today + 10).iso8601}}
    end
    assert_response :success
    assert_includes @response.headers['Cache-Control'], 'no-store'
    token = PersonalAccessToken.order(:id).last
    assert_equal @user, token.user
    assert_select 'pre#personal-access-token-value', :count => 1
    plaintext = css_select('pre#personal-access-token-value').first.text.strip
    assert_match PersonalAccessToken::FORMAT, plaintext
    assert_equal token, PersonalAccessToken.authenticate(plaintext)
    assert_equal 1, response.body.scan(plaintext).size
    assert_nil flash[:notice]

    get :index
    assert_not_include plaintext, response.body
  end

  def test_create_should_ignore_user_param
    post :create, :params => {:personal_access_token => {:name => 'Deploy', :expiration_date => (@user.today + 10).iso8601, :user_id => 1}}
    assert_equal @user, PersonalAccessToken.order(:id).last.user
  end

  def test_create_with_invalid_params
    assert_no_difference 'PersonalAccessToken.count' do
      post :create, :params => {:personal_access_token => {:name => '', :expiration_date => (@user.today + 1000).iso8601}}
    end
    assert_response :unprocessable_content
    assert_select_error /Name cannot be blank/
    assert_select_error /Expiration date must be less than or equal to/
    assert_select 'pre#personal-access-token-value', 0
  end

  def test_create_should_require_sudo_mode
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    assert_no_difference 'PersonalAccessToken.count' do
      post :create, :params => {:personal_access_token => {:name => 'Deploy', :expiration_date => (@user.today + 10).iso8601}}
    end
    assert_select 'input[name=sudo_password]'
    # the sudo form must resubmit the original create params
    assert_select 'input[type=hidden][name=?]', 'personal_access_token[name]'

    assert_no_difference 'PersonalAccessToken.count' do
      post :create, :params => {:personal_access_token => {:name => 'Deploy', :expiration_date => (@user.today + 10).iso8601}, :sudo_password => 'wrong'}
    end
    assert_select 'input[name=sudo_password]'

    assert_difference 'PersonalAccessToken.count', 1 do
      post :create, :params => {:personal_access_token => {:name => 'Deploy', :expiration_date => (@user.today + 10).iso8601}, :sudo_password => 'jsmith'}
    end
    assert_response :success
    assert_select 'pre#personal-access-token-value', 1
  end

  def test_destroy_own_token
    token = create_token
    delete :destroy, :params => {:id => token.id}
    assert_redirected_to '/my/personal_access_tokens'
    assert_nil PersonalAccessToken.find_by(:id => token.id)
    assert_equal 'Successful deletion.', flash[:notice]
  end

  def test_destroy_foreign_token_should_respond_with_404
    token = create_token(User.find(3), 'Other')
    delete :destroy, :params => {:id => token.id}
    assert_response :not_found
    assert PersonalAccessToken.find_by(:id => token.id)
  end

  def test_destroy_should_require_sudo_mode
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    token = create_token
    delete :destroy, :params => {:id => token.id}
    assert_select 'input[name=sudo_password]'
    assert PersonalAccessToken.find_by(:id => token.id)

    delete :destroy, :params => {:id => token.id, :sudo_password => 'jsmith'}
    assert_redirected_to '/my/personal_access_tokens'
    assert_nil PersonalAccessToken.find_by(:id => token.id)
  end

  def test_anonymous_should_be_redirected_to_login
    @request.session[:user_id] = nil
    get :index
    assert_response :redirect
    assert_match %r{/login}, response.location
  end

  def test_should_respond_with_403_when_rest_api_is_disabled
    Setting.rest_api_enabled = '0'
    get :index
    assert_response :forbidden
  end

  def test_create_should_respond_with_403_when_rest_api_is_disabled
    Setting.rest_api_enabled = '0'
    assert_no_difference 'PersonalAccessToken.count' do
      post :create, :params => {:personal_access_token => {:name => 'Deploy', :expiration_date => (@user.today + 10).iso8601}}
    end
    assert_response :forbidden
  end

  def test_destroy_should_respond_with_403_when_rest_api_is_disabled
    token = create_token
    Setting.rest_api_enabled = '0'
    assert_no_difference 'PersonalAccessToken.count' do
      delete :destroy, :params => {:id => token.id}
    end
    assert_response :forbidden
  end
end
