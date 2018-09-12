class User < ApplicationRecord
  validates :user_name, :session_token, presence: true, uniqueness: true 
  validates :password_digest, presence: true 
  validates :password, length: {minimum: 6, allow_nil: true}
  
  
  after_initialize :ensure_session_token 
  
  attr_reader :password 
  
  def password=(pw)
    @password = pw 
    self.password_digest = BCrypt::Password.create(pw)
  end 
  
  def ensure_session_token
    self.session_token ||= SecureRandom.urlsafe_base64
  end 
  
  def reset_session_token!
    self.session_token = SecureRandom.urlsafe_base64
    self.save!
    self.session_token
  end 
  
  def is_password?(pw)
    BCrypt::Password.new(self.password_digest).is_password?(pw)
  end 
  
  def self.find_by_credentials(user_name, password)
    user = User.find_by(user_name: user_name)
    user && user.is_password?(password) ? user : nil 
  end 
  
end


# create_table :users do |t|
#   t.string :user_name, null: false
#   t.string :password_digest, null: false 
#   t.string :session_token, null: false
# 
#   t.timestamps
# end
# add_index :users, :user_name, unique: true 
# add_index :users, :session_token, unique: true 