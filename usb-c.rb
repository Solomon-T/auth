class User < ApplicationRecord
    validates :password, length: { minimum: 6, allow_nil: true }
    
    after_initialize :ensure_session_token

    def self.find_by_credentials(username, password)
        user = User.find_by(username: username)

        return nil if user.nil?
        user.is_password?(password) ? user : nil
    end

    def is_password?(password)
        BCrypt::Password.new(self.password_digest).is_password?(password)
    end
    
    def password=(password)
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end
    
    def reset_session_token!
        self.session_token = SecureRandom.base64(64)
        self.save!
        self.session_token
    end

    private
    def ensure_session_token
        self.session_token ||= SecureRandom.base64(64)
    end
end


class ApplicationController < ActionController::Base

    # Solomon you might find it usefull to add some helper methods
    helper_method :current_user 

    # CELLL
    def current_user
        @current_user ||= User.find_by(session_token: session[:session_token])
    end

    def ensure_logged_in 
        redirect_to new_session_url unless logged_in?
    end

    def logged_in?
        !!current_user
    end

    def login!(user)
        # @current_user = user??
        session[:session_token] = user.reset_session_token!
    end

    def logout!
        current_user.reset_session_token!
        session[:session_token] = nil
        @current_user = nil #she didnt have this
    end
end



class SessionsController < ApplicationController

    before_action :ensure_logged_in, only: [:destroy]

    def new
        render :new
    end

    def create # logging in method
        user = User.find_by_credentials(
            params[:user][:username], 
            params[:user][:password]
        )

        if user  #she used @user every where
            login!(user)
            redirect_to users_url
        else
            flash.now[:errors] = ["Invalid username or password"]
            render :new
        end
    end

  def destroy 
    logout!
    redirect_to new_session_url
  end
end



class UsersController < ApplicationController

    before_action :ensure_logged_in, only: [:show, :index]

    def new
        @user = User.new
        render :new
    end

    def create 
        @user = User.new(user_params)

        if @user.save
            login!(@user)
            redirect_to users_url
        else
            flash[:errors] = @user.errors.full_messages
            render :new
        end
    end

    def index
        @users = User.all
        render :index
    end

    def show
        @user = User.find_by(id: params[:id])
        render :show
    end

    def user_params
        params.require(:user).permit(:username, :password)
    end
end
