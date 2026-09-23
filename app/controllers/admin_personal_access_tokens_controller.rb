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

class AdminPersonalAccessTokensController < ApplicationController
  layout 'admin'
  self.main_menu = false
  menu_item :personal_access_tokens

  before_action :require_admin, :require_rest_api_enabled
  before_action :find_personal_access_token, :only => :destroy

  require_sudo_mode :destroy

  def index
    scope = PersonalAccessToken.preload(:user).sorted
    case params[:status]
    when 'active'
      scope = scope.active
    when 'expired'
      scope = scope.expired
    end
    scope = scope.where(:user_id => User.like(params[:user]).select(:id)) if params[:user].present?

    @personal_access_token_count = scope.count
    @personal_access_token_pages = Paginator.new @personal_access_token_count, per_page_option, params['page']
    @personal_access_tokens = scope.limit(@personal_access_token_pages.per_page).offset(@personal_access_token_pages.offset).to_a
  end

  def destroy
    @personal_access_token.destroy
    flash[:notice] = l(:notice_successful_delete)
    redirect_back_or_default admin_personal_access_tokens_path
  end

  private

  def find_personal_access_token
    @personal_access_token = PersonalAccessToken.find_by(:id => params[:id])
    render_404 unless @personal_access_token
  end
end
