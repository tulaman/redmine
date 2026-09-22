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

class AdminPersonalAccessTokensControllerTest < Redmine::ControllerTest
  def setup
    Setting.rest_api_enabled = '1'
    @request.session[:user_id] = 1
    ActionMailer::Base.deliveries.clear
    @jsmith_token = create_token(User.find(2), 'jsmith CI')
    @dlopper_token = create_token(User.find(3), 'dlopper CI')
  end

  def teardown
    Setting.rest_api_enabled = '0'
  end

  def create_token(user, name)
    PersonalAccessToken.create!(:user => user, :name => name, :expiration_date => user.today + 30)
  end

  def test_index_should_list_tokens_of_all_users
    get :index
    assert_response :success
    assert_select "tr#personal-access-token-#{@jsmith_token.id}" do
      assert_select 'td.user a[href=?]', '/users/2'
      assert_select 'td.name', :text => 'jsmith CI'
      assert_select 'td.token', :text => @jsmith_token.masked_value
      assert_select 'td.buttons a.icon-del'
    end
    assert_select "tr#personal-access-token-#{@dlopper_token.id}"
    assert_select "tr#personal-access-token-#{@jsmith_token.id}[class]", 0
    assert_not_include @jsmith_token.plaintext_token, response.body
    assert_not_include @jsmith_token.token_digest, response.body
  end

  def test_index_delete_link_should_carry_encoded_back_url
    get :index, :params => {:status => 'active'}
    assert_select "tr#personal-access-token-#{@jsmith_token.id} td.buttons a[href=?]",
                  "/admin/personal_access_tokens/#{@jsmith_token.id}?back_url=%2Fadmin%2Fpersonal_access_tokens%3Fstatus%3Dactive"
  end

  def test_index_should_filter_by_status
    PersonalAccessToken.where(:id => @dlopper_token.id).update_all(:expires_on => 1.day.ago)
    get :index, :params => {:status => 'expired'}
    assert_select "tr#personal-access-token-#{@dlopper_token.id}.expired"
    assert_select "tr#personal-access-token-#{@jsmith_token.id}", 0

    get :index, :params => {:status => 'active'}
    assert_select "tr#personal-access-token-#{@jsmith_token.id}"
    assert_select "tr#personal-access-token-#{@dlopper_token.id}", 0
  end

  def test_index_should_ignore_unknown_status
    # Expire dlopper's token so that treating the unknown status as 'active'
    # (instead of ignoring it) would wrongly hide this row.
    PersonalAccessToken.where(:id => @dlopper_token.id).update_all(:expires_on => 1.day.ago)
    get :index, :params => {:status => 'bogus'}
    assert_response :success
    assert_select "tr#personal-access-token-#{@jsmith_token.id}"
    assert_select "tr#personal-access-token-#{@dlopper_token.id}"
  end

  def test_index_should_filter_by_user
    get :index, :params => {:user => 'jsmi'}
    assert_select "tr#personal-access-token-#{@jsmith_token.id}"
    assert_select "tr#personal-access-token-#{@dlopper_token.id}", 0
  end

  def test_index_should_filter_by_user_first_name
    # 'John' matches jsmith's firstname only, not any login or email, so this
    # proves the filter searches first/last name and not just the login.
    get :index, :params => {:user => 'John'}
    assert_select "tr#personal-access-token-#{@jsmith_token.id}"
    assert_select "tr#personal-access-token-#{@dlopper_token.id}", 0
  end

  def test_index_should_filter_by_status_and_user
    # dlopper's default token becomes expired; an extra expired jsmith token
    # and an extra active dlopper token are added so that dropping either
    # the status or the user filter would wrongly include one of them.
    PersonalAccessToken.where(:id => @dlopper_token.id).update_all(:expires_on => 1.day.ago)
    expired_jsmith_token = create_token(User.find(2), 'jsmith CI expired')
    PersonalAccessToken.where(:id => expired_jsmith_token.id).update_all(:expires_on => 1.day.ago)
    active_dlopper_token = create_token(User.find(3), 'dlopper CI active')

    get :index, :params => {:status => 'active', :user => 'jsmith'}
    assert_select "tr#personal-access-token-#{@jsmith_token.id}"
    assert_select "tr#personal-access-token-#{@dlopper_token.id}", 0
    assert_select "tr#personal-access-token-#{expired_jsmith_token.id}", 0
    assert_select "tr#personal-access-token-#{active_dlopper_token.id}", 0
  end

  def test_index_should_paginate
    with_settings :per_page_options => '1' do
      get :index
      assert_select 'table.personal-access-tokens tbody tr', 1
      assert_select 'span.pagination'
    end
  end

  def test_index_should_show_correct_token_on_requested_page
    with_settings :per_page_options => '1' do
      get :index, :params => {:page => 2}
      assert_select "tr#personal-access-token-#{@dlopper_token.id}"
      assert_select "tr#personal-access-token-#{@jsmith_token.id}", 0
    end
  end

  def test_index_pagination_link_should_keep_filter_params
    create_token(User.find(2), 'jsmith CI 2')
    with_settings :per_page_options => '1' do
      get :index, :params => {:status => 'active', :user => 'jsmith'}
      # Hash#to_query sorts keys alphabetically, hence page before status before user.
      assert_select 'ul.pages li.page a[href=?]', '/admin/personal_access_tokens?page=2&status=active&user=jsmith'
    end
  end

  def test_index_should_mark_locked_users
    User.find(3).lock!
    get :index
    assert_select "tr#personal-access-token-#{@dlopper_token.id} td.user", :text => /locked/
  end

  def test_index_menu_item_should_use_server_authentication_icon
    # Matches the icon used by the equivalent link under My account.
    get :index
    assert_select '#admin-menu a.icon-server-authentication[href=?]', '/admin/personal_access_tokens'
  end

  def test_index_should_require_admin
    @request.session[:user_id] = 2
    get :index
    assert_response :forbidden
  end

  def test_index_should_respond_with_403_when_rest_api_is_disabled
    Setting.rest_api_enabled = '0'
    get :index
    assert_response :forbidden
  end

  def test_destroy_should_delete_any_token_and_notify_owner
    delete :destroy, :params => {:id => @jsmith_token.id}
    assert_redirected_to '/admin/personal_access_tokens'
    assert_nil PersonalAccessToken.find_by(:id => @jsmith_token.id)
    mail = ActionMailer::Base.deliveries.last
    assert_equal [User.find(2).mail], mail.to
    assert_mail_body_match 'Personal access token jsmith CI was removed.', mail
    assert_equal 'admin', mail.header['X-Redmine-Sender'].to_s
  end

  def test_destroy_should_deliver_exactly_one_mail_to_owner
    assert_difference 'ActionMailer::Base.deliveries.size', 1 do
      delete :destroy, :params => {:id => @jsmith_token.id}
    end
  end

  def test_destroy_unknown_token_should_respond_with_404
    delete :destroy, :params => {:id => 999_999}
    assert_response :not_found
  end

  def test_destroy_should_require_sudo_mode
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    delete :destroy, :params => {:id => @jsmith_token.id}
    assert_select 'input[name=sudo_password]'
    assert PersonalAccessToken.find_by(:id => @jsmith_token.id)

    delete :destroy, :params => {:id => @jsmith_token.id, :sudo_password => 'admin'}
    assert_redirected_to '/admin/personal_access_tokens'
    assert_nil PersonalAccessToken.find_by(:id => @jsmith_token.id)
  end

  def test_destroy_should_preserve_back_url_through_sudo_mode
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    back_url = '/admin/personal_access_tokens?status=active'
    delete :destroy, :params => {:id => @jsmith_token.id, :back_url => back_url}
    assert_select 'input[name=sudo_password]'
    assert_select 'input[type=hidden][name=back_url][value=?]', back_url
    assert PersonalAccessToken.find_by(:id => @jsmith_token.id)

    delete :destroy, :params => {:id => @jsmith_token.id, :sudo_password => 'admin', :back_url => back_url}
    assert_redirected_to back_url
    assert_nil PersonalAccessToken.find_by(:id => @jsmith_token.id)
  end

  def test_destroy_should_redirect_to_back_url_param
    back_url = '/admin/personal_access_tokens?status=active'
    delete :destroy, :params => {:id => @jsmith_token.id, :back_url => back_url}
    assert_redirected_to back_url
  end

  def test_destroy_should_ignore_unsafe_back_url_param
    delete :destroy, :params => {:id => @jsmith_token.id, :back_url => 'http://evil.example.com/'}
    assert_redirected_to '/admin/personal_access_tokens'
  end

  def test_destroy_should_require_admin
    @request.session[:user_id] = 2
    delete :destroy, :params => {:id => @dlopper_token.id}
    assert_response :forbidden
    assert PersonalAccessToken.find_by(:id => @dlopper_token.id)
  end
end
