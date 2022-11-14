# == Schema Information
#
# Table name: users
#
#  id              :bigint           not null, primary key
#  username        :string           not null
#  password_digest :string           not null
#  session_token   :string           not null
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#
class User < ApplicationRecord
    validates :username, presence: true, uniqueness: true
    validates :password_digest, presence: true
    validates :session_token, presence: true
    validates :password, length: {minimum: 6}, allow_nil: true

    attr_reader :password
    before_validation :ensure_session_token

    def self.find_by_credentials(username, password)
    end

    def password=(password)
    end

    def is_password?(password)
    end

    def reset_session_token
    end

    def ensure_session_token
    end
end
