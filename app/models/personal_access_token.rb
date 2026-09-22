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

class PersonalAccessToken < ApplicationRecord
  include Redmine::SafeAttributes
  include Redmine::I18n

  PREFIX = 'redmine_pat_'
  SECRET_LENGTH = 40
  FORMAT = /\A#{PREFIX}[A-Za-z0-9]{#{SECRET_LENGTH}}\z/
  DEFAULT_MAX_LIFETIME = 90
  DEFAULT_LIFETIME = 30
  NAME_LENGTH_LIMIT = 60
  DATE_FORMAT = /\A\d{4}-\d{2}-\d{2}\z/

  belongs_to :user

  attr_readonly :user_id, :token_digest, :token_last_chars, :expires_on
  self.filter_attributes += [:token_digest]

  # Plaintext value, only available on the instance that generated it
  attr_reader :plaintext_token

  scope :sorted, lambda {order(:expires_on, :id)}
  scope :active, lambda {where("#{table_name}.expires_on > ?", Time.now)}
  scope :expired, lambda {where("#{table_name}.expires_on <= ?", Time.now)}

  safe_attributes 'name', 'expiration_date'

  before_validation :generate_token, :on => :create
  before_validation :set_expires_on, :on => :create

  validates_presence_of :name
  validates_length_of :name, :maximum => NAME_LENGTH_LIMIT
  validates_uniqueness_of :name, :scope => :user_id, :case_sensitive => false
  validates_presence_of :token_digest, :token_last_chars
  validate :validate_user, :on => :create
  validate :validate_expiration_date, :on => :create

  after_create_commit :deliver_security_notification_create
  after_destroy_commit :deliver_security_notification_destroy

  # Returns true if the given value has the shape of a personal access token
  def self.token_format?(value)
    value.is_a?(String) && FORMAT.match?(value)
  end

  def self.digest(value)
    Digest::SHA256.hexdigest(value)
  end

  # Returns the token matching the given plaintext value if it can be used
  # to authenticate, or nil. Malformed values never reach the database.
  def self.authenticate(value)
    return nil unless token_format?(value)

    digest = digest(value)
    token = find_by(:token_digest => digest)
    # The lookup already matched by equality, so this is not a timing-attack
    # mitigation here; it is kept as defence in depth.
    return nil unless token && ActiveSupport::SecurityUtils.secure_compare(token.token_digest, digest)
    return nil if token.expired?
    return nil unless token.user&.active?

    token
  end

  # Maximum lifetime in days, a non-positive setting falls back to the default
  def self.max_lifetime
    days = Setting.personal_access_token_max_lifetime.to_i
    days > 0 ? days : DEFAULT_MAX_LIFETIME
  end

  def self.default_expiration_date(user)
    user.today + [DEFAULT_LIFETIME, max_lifetime].min
  end

  def self.latest_expiration_date(user)
    user.today + max_lifetime
  end

  def expiration_date
    return @expiration_date if @expiration_date
    return nil unless expires_on

    user&.time_zone ? expires_on.in_time_zone(user.time_zone).to_date : expires_on.localtime.to_date
  end

  def expiration_date=(value)
    @expiration_date = value.is_a?(Date) ? value : parse_expiration_date(value)
    @expiration_date_invalid = value.present? && @expiration_date.nil?
  end

  def expired?
    expires_on <= Time.now
  end

  def masked_value
    "#{PREFIX}…#{token_last_chars}"
  end

  private

  # Returns the parsed date for a strict YYYY-MM-DD string, or nil when the
  # value is blank, has a different shape, or is not a valid calendar date
  # (e.g. '2026-02-30').
  def parse_expiration_date(value)
    s = value.to_s
    Date.iso8601(s) if DATE_FORMAT.match?(s)
  rescue ArgumentError
    nil
  end

  def generate_token
    @plaintext_token = PREFIX + SecureRandom.alphanumeric(SECRET_LENGTH)
    self.token_digest = self.class.digest(@plaintext_token)
    self.token_last_chars = @plaintext_token[-4..]
  end

  def set_expires_on
    if @expiration_date
      y, m, d = @expiration_date.year, @expiration_date.month, @expiration_date.day
      local_midnight = user&.time_zone ? user.time_zone.local(y, m, d) : Time.local(y, m, d)
      self.expires_on = local_midnight.end_of_day.change(:usec => 0)
    elsif @expiration_date_invalid
      self.expires_on = nil
    end
  end

  def validate_user
    errors.add(:user, :invalid) unless user.is_a?(User) && !user.anonymous? && user.active?
  end

  def validate_expiration_date
    if @expiration_date_invalid
      errors.add(:expiration_date, :invalid)
    elsif expiration_date.nil?
      errors.add(:expiration_date, :blank)
    elsif user
      today = user.today
      latest = self.class.latest_expiration_date(user)
      if expiration_date <= today
        errors.add(:expiration_date, :greater_than, :count => format_date(today))
      elsif expiration_date > latest
        errors.add(:expiration_date, :less_than_or_equal_to, :count => format_date(latest))
      end
    end
  end

  def deliver_security_notification_create
    deliver_security_notification(:mail_body_security_notification_add)
  end

  def deliver_security_notification_destroy
    deliver_security_notification(:mail_body_security_notification_remove)
  end

  def deliver_security_notification(message)
    Mailer.deliver_security_notification(
      user,
      User.current,
      :message => message,
      :field => :label_personal_access_token,
      :value => name
    )
  end
end
