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

class PersonalAccessTokenTest < ActiveSupport::TestCase
  def setup
    User.current = nil
    ActionMailer::Base.deliveries.clear
    @user = User.find(2)
  end

  def create_token(attributes = {})
    PersonalAccessToken.create!({:user => @user, :name => 'CI', :expiration_date => @user.today + 30}.merge(attributes))
  end

  def test_create_should_generate_prefixed_plaintext_token
    token = create_token
    assert_match /\Aredmine_pat_[A-Za-z0-9]{40}\z/, token.plaintext_token
  end

  def test_create_should_store_digest_and_last_chars_only
    token = create_token
    plaintext = token.plaintext_token
    row = PersonalAccessToken.connection.select_one("SELECT * FROM personal_access_tokens WHERE id = #{token.id}")
    assert_equal Digest::SHA256.hexdigest(plaintext), row['token_digest']
    assert_equal plaintext[-4..], row['token_last_chars']
    assert_not row.values.map(&:to_s).any? {|value| value.include?(plaintext)}
  end

  def test_plaintext_token_should_not_be_available_after_reload
    token = create_token
    assert_nil PersonalAccessToken.find(token.id).plaintext_token
  end

  def test_masked_value
    token = create_token
    assert_equal "redmine_pat_…#{token.plaintext_token[-4..]}", token.masked_value
  end

  def test_inspect_should_not_include_token_digest
    token = create_token
    # Default AR#inspect truncates long strings, so a full-digest check would pass
    # vacuously; check for a filtered attribute marker and a digest prefix instead.
    assert_includes token.inspect, '[FILTERED]'
    assert_not_includes token.inspect, token.token_digest[0, 20]
  end

  def test_name_should_be_required
    token = PersonalAccessToken.new(:user => @user, :name => '', :expiration_date => @user.today + 1)
    assert_not token.save
    assert_include :name, token.errors.attribute_names
  end

  def test_name_should_be_limited_to_60_characters
    token = PersonalAccessToken.new(:user => @user, :name => 'a' * 61, :expiration_date => @user.today + 1)
    assert_not token.save
    assert_include :name, token.errors.attribute_names
  end

  def test_name_should_be_unique_per_user_case_insensitively
    create_token(:name => 'Deploy')
    token = PersonalAccessToken.new(:user => @user, :name => 'deploy', :expiration_date => @user.today + 1)
    assert_not token.save
    assert_include :name, token.errors.attribute_names
    other_user = User.find(3)
    assert PersonalAccessToken.new(:user => other_user, :name => 'deploy', :expiration_date => other_user.today + 1).save
  end

  def test_expiration_date_should_be_required
    token = PersonalAccessToken.new(:user => @user, :name => 'CI')
    assert_not token.save
    assert_include :expiration_date, token.errors.attribute_names
  end

  def test_expiration_date_should_be_rejected_when_not_a_date
    token = PersonalAccessToken.new(:user => @user, :name => 'CI', :expiration_date => 'not-a-date')
    assert_not token.save
    assert_include :expiration_date, token.errors.attribute_names
  end

  def test_expiration_date_should_reject_non_ymd_iso8601_strings
    # Date.iso8601 also accepts ISO week-date strings (e.g. 2026-W40-5); only
    # plain YYYY-MM-DD is a valid expiration_date input, even when the
    # week-date string resolves to a valid future date.
    week_date = (@user.today + 10).strftime('%G-W%V-%u')
    token = PersonalAccessToken.new(:user => @user, :name => 'CI', :expiration_date => week_date)
    assert_not token.save
    assert_include :expiration_date, token.errors.attribute_names
  end

  def test_expiration_date_should_reject_invalid_calendar_dates
    # '2026-02-30' matches the YYYY-MM-DD shape but is not a real date;
    # Date.iso8601 raises ArgumentError for it.
    token = PersonalAccessToken.new(:user => @user, :name => 'CI', :expiration_date => '2026-02-30')
    assert_not token.save
    assert_include :expiration_date, token.errors.attribute_names
  end

  def test_expiration_date_should_be_in_the_future
    freeze_time do
      token = PersonalAccessToken.new(:user => @user, :name => 'CI', :expiration_date => @user.today)
      assert_not token.save
      assert_include :expiration_date, token.errors.attribute_names
    end
  end

  def test_expiration_date_should_not_exceed_max_lifetime
    freeze_time do
      with_settings :personal_access_token_max_lifetime => '10' do
        assert PersonalAccessToken.new(:user => @user, :name => 'ok', :expiration_date => @user.today + 10).save
        token = PersonalAccessToken.new(:user => @user, :name => 'too far', :expiration_date => @user.today + 11)
        assert_not token.save
        assert_include :expiration_date, token.errors.attribute_names
      end
    end
  end

  def test_expiration_date_should_accept_iso_string
    freeze_time do
      token = create_token(:expiration_date => (@user.today + 5).iso8601)
      assert_equal @user.today + 5, token.expiration_date
    end
  end

  def test_expires_on_should_be_end_of_day_in_owner_time_zone
    freeze_time do
      @user.pref.update!(:time_zone => 'Tokyo')
      @user.reload
      date = @user.today + 5
      token = create_token(:expiration_date => date)
      expected = ActiveSupport::TimeZone['Tokyo'].local(date.year, date.month, date.day).end_of_day.change(:usec => 0)
      assert_equal expected.to_i, token.expires_on.to_i
    end
  end

  def test_expires_on_should_use_server_local_zone_when_owner_has_no_time_zone
    # Time.use_zone changes Time.zone to Tokyo for the duration of the block, so
    # this discriminates the fix even when the test machine's own local zone
    # happens to be UTC: a regression to the old Time.zone-based fallback would
    # compute Tokyo's end of day instead of the server's local end of day.
    Time.use_zone('Tokyo') do
      freeze_time do
        assert_nil @user.time_zone
        date = @user.today + 5
        token = create_token(:expiration_date => date)
        expected = Time.local(date.year, date.month, date.day).end_of_day.change(:usec => 0)
        assert_equal expected, token.expires_on
      end
    end
  end

  def test_expires_on_should_not_change_after_create
    token = create_token
    original_expires_on = token.expires_on
    token.expiration_date = @user.today + 1000
    assert token.save
    assert_equal original_expires_on, token.reload.expires_on
  end

  def test_max_lifetime_should_default_to_90_days
    assert_equal 90, PersonalAccessToken.max_lifetime
  end

  def test_max_lifetime_should_fall_back_to_90_for_non_positive_values
    with_settings :personal_access_token_max_lifetime => '0' do
      assert_equal 90, PersonalAccessToken.max_lifetime
    end
    with_settings :personal_access_token_max_lifetime => '-5' do
      assert_equal 90, PersonalAccessToken.max_lifetime
    end
  end

  def test_max_lifetime_should_use_setting
    with_settings :personal_access_token_max_lifetime => '365' do
      assert_equal 365, PersonalAccessToken.max_lifetime
    end
  end

  def test_default_expiration_date
    freeze_time do
      assert_equal @user.today + 30, PersonalAccessToken.default_expiration_date(@user)
      with_settings :personal_access_token_max_lifetime => '7' do
        assert_equal @user.today + 7, PersonalAccessToken.default_expiration_date(@user)
      end
    end
  end

  def test_locked_user_should_not_own_new_tokens
    user = User.find(5)
    token = PersonalAccessToken.new(:user => user, :name => 'CI', :expiration_date => user.today + 1)
    assert_not token.save
    assert_include :user, token.errors.attribute_names
  end

  def test_anonymous_user_should_not_own_tokens
    anonymous = User.anonymous
    token = PersonalAccessToken.new(:user => anonymous, :name => 'CI', :expiration_date => anonymous.today + 1)
    assert_not token.save
    assert_include :user, token.errors.attribute_names
  end

  def test_authenticate_should_return_token_for_valid_plaintext
    token = create_token
    assert_equal token, PersonalAccessToken.authenticate(token.plaintext_token)
  end

  def test_authenticate_should_return_nil_for_expired_token
    token = create_token
    travel_to token.expires_on + 1.second do
      assert_nil PersonalAccessToken.authenticate(token.plaintext_token)
    end
  end

  def test_authenticate_should_return_nil_at_exact_expiry_boundary
    token = create_token
    travel_to token.expires_on do
      assert_nil PersonalAccessToken.authenticate(token.plaintext_token)
    end
  end

  def test_authenticate_should_return_nil_when_owner_is_locked
    token = create_token
    @user.lock!
    assert_nil PersonalAccessToken.authenticate(token.plaintext_token)
    @user.activate!
    assert_equal token, PersonalAccessToken.authenticate(token.plaintext_token)
  end

  def test_authenticate_should_return_nil_when_owner_is_registered
    token = create_token
    @user.register!
    assert_nil PersonalAccessToken.authenticate(token.plaintext_token)
  end

  def test_authenticate_should_return_nil_for_unknown_token
    assert_nil PersonalAccessToken.authenticate('redmine_pat_' + ('a' * 40))
  end

  def test_authenticate_should_not_query_database_for_malformed_values
    PersonalAccessToken.expects(:find_by).never
    [nil, '', 'redmine_pat_short', 'a' * 40, 'redmine_pat_' + ('a' * 39) + '-', ['redmine_pat_' + ('a' * 40)]].each do |value|
      assert_nil PersonalAccessToken.authenticate(value)
    end
  end

  def test_token_format
    assert PersonalAccessToken.token_format?('redmine_pat_' + ('A1b2' * 10))
    assert_not PersonalAccessToken.token_format?('0123456789abcdef0123456789abcdef01234567')
    assert_not PersonalAccessToken.token_format?(nil)
  end

  def test_expired
    token = create_token
    assert_not token.expired?
    travel_to token.expires_on + 1.second do
      assert token.expired?
    end
  end

  def test_expired_at_exact_expiry_boundary
    token = create_token
    travel_to token.expires_on do
      assert token.expired?
    end
  end

  def test_active_and_expired_scopes
    active = create_token(:name => 'active')
    expired = create_token(:name => 'expired')
    # expires_on is attr_readonly (immutable after create); update_all issues a
    # direct SQL update to simulate an already-expired row for this test.
    PersonalAccessToken.where(:id => expired.id).update_all(:expires_on => 1.day.ago)
    assert_include active, PersonalAccessToken.active
    assert_not_include expired, PersonalAccessToken.active
    assert_include expired, PersonalAccessToken.expired
    assert_not_include active, PersonalAccessToken.expired
  end

  def test_destroying_user_should_delete_tokens
    user = User.generate!
    token = create_token(:user => user)
    user.destroy
    assert_nil PersonalAccessToken.find_by(:id => token.id)
  end

  def test_create_should_notify_owner
    create_token(:name => 'Deploy')
    mail = ActionMailer::Base.deliveries.last
    assert_not_nil mail
    assert_equal [@user.mail], mail.to
    assert_mail_body_match 'Personal access token Deploy was added.', mail
  end

  def test_destroy_should_notify_owner
    token = create_token(:name => 'Deploy')
    ActionMailer::Base.deliveries.clear
    token.destroy
    mail = ActionMailer::Base.deliveries.last
    assert_not_nil mail
    assert_equal [@user.mail], mail.to
    assert_mail_body_match 'Personal access token Deploy was removed.', mail
  end
end
