class ApplicationController < ActionController::Base

    helper_method :current_user, :logged_in?

    def current_user
        @current_user ||= User.find_by(session_token: session[:session_token])
    end

    def require_logged_in
        redirect_to new_session_url unless logged_in?
    end

    def require_logged_out
        redirect_to cats_url if logged_in?
    end

    def login(user)
        session[:session_token] = user.reset_session_token
    end

    def logout
        current_user.reset_session_token if logged_in?
        session[:session_token] = nil
        @current_user = nil
    end

    def logged_in?
        !!current_user
    end
end