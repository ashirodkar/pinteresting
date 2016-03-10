class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  validates :password, 	:presence => true,
  						:on => :create,
  						:format => {:with => /\A.*(?=.{10,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\@\#\$\%\^\&\+\=]).*\Z/ }	

  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
end
