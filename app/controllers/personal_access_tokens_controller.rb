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

class PersonalAccessTokensController < ApplicationController
  self.main_menu = false

  before_action :require_login, :require_rest_api_enabled, :set_user
  before_action :find_personal_access_token, :only => :destroy

  require_sudo_mode :create, :destroy, :parameters => %w(personal_access_token)

  def index
    @personal_access_tokens = User.current.personal_access_tokens.sorted.to_a
  end

  def new
    @personal_access_token = User.current.personal_access_tokens.build
    @personal_access_token.expiration_date = PersonalAccessToken.default_expiration_date(User.current)
  end

  def create
    @personal_access_token = User.current.personal_access_tokens.build
    @personal_access_token.safe_attributes = params[:personal_access_token]
    if @personal_access_token.save
      # The plaintext token is rendered once and must not be cached
      no_store
      render :action => 'created'
    else
      render :action => 'new', :status => :unprocessable_content
    end
  end

  def destroy
    @personal_access_token.destroy
    flash[:notice] = l(:notice_successful_delete)
    redirect_to personal_access_tokens_path
  end

  private

  def set_user
    @user = User.current
  end

  def find_personal_access_token
    @personal_access_token = User.current.personal_access_tokens.find_by(:id => params[:id])
    render_404 unless @personal_access_token
  end
end
