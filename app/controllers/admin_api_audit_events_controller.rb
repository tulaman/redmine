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

class AdminApiAuditEventsController < ApplicationController
  CSV_EXPORT_LIMIT = 50_000

  layout 'admin'
  self.main_menu = false
  menu_item :api_audit_events

  before_action :require_admin

  helper :sort
  include SortHelper
  helper :queries
  include QueriesHelper
  helper :api_audit_event_queries
  include ApiAuditEventQueriesHelper

  def index
    retrieve_query(ApiAuditEventQuery, !request.format.csv?)

    if @query.valid?
      scope = @query.results_scope
      respond_to do |format|
        format.html do
          @event_count = scope.count
          @event_pages = Paginator.new @event_count, per_page_option, params['page']
          @events = scope.limit(@event_pages.per_page).offset(@event_pages.offset).to_a
          render :layout => !request.xhr?
        end
        format.csv do
          events = scope.limit(CSV_EXPORT_LIMIT).to_a
          send_data(query_to_csv(events, @query, params), :type => 'text/csv; header=present',
                    :filename => "#{filename_for_export(@query, 'api_audit_events')}.csv")
        end
      end
    else
      respond_to do |format|
        format.html {render :layout => !request.xhr?}
        format.csv {head :unprocessable_content}
      end
    end
  end
end
