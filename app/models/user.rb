class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  validates :username, :presence => true, :uniqueness => {:case_sensitive => false}, 
                       :format => {:with => /\A[A-Za-z0-9\-\_\.]+\z/, :message => I18n.t('errors.messages.space_name') }, 
                       :length => {:in => 4..20}
end
