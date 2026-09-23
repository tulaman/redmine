# frozen_string_literal: true

class CreatePersonalAccessTokens < ActiveRecord::Migration[7.2]
  def change
    create_table :personal_access_tokens do |t|
      t.integer :user_id, :null => false
      t.string :name, :null => false
      t.string :token_digest, :limit => 64, :null => false
      t.string :token_last_chars, :limit => 4, :null => false
      t.datetime :expires_on, :null => false
      t.datetime :created_on, :null => false
      t.datetime :updated_on, :null => false
    end
    add_index :personal_access_tokens, :user_id
    add_index :personal_access_tokens, :token_digest, :unique => true
  end
end
