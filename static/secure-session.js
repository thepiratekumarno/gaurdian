// Secure Session Management for SecretGuardian
// Add to static folder

class SecureSessionManager {
    constructor() {
        this.isAuthenticatedPage = false;
        this.isLoginPage = false;
        this.currentPath = window.location.pathname;
        this.init();
    }

    init() {
        this.detectPageType();
        this.setupSecureNavigation();
        this.setupSessionHandling();
        this.preventCacheBackNavigation();
        
        // Set up periodic session validation
        this.setupSessionValidation();
    }

    detectPageType() {
        // Detect if we're on a secure/authenticated page
        const securePaths = ['/dashboard', '/repositories', '/reports', '/scan'];
        this.isAuthenticatedPage = securePaths.some(path => this.currentPath.startsWith(path));
        
        // Detect if we're on login page
        this.isLoginPage = this.currentPath === '/login' || this.currentPath === '/';
    }

    setupSecureNavigation() {
        // Handle login success - prevent back navigation to login
        if (this.isAuthenticatedPage) {
            this.secureAuthenticatedPage();
        }
        
        // Handle login page - check if already authenticated
        if (this.isLoginPage) {
            this.handleLoginPage();
        }
    }

    secureAuthenticatedPage() {
        // Prevent browser caching of authenticated pages
        this.preventPageCaching();
        
        // Replace history entry to prevent back navigation to login
        if (document.referrer && (document.referrer.includes('/login') || document.referrer.includes('/auth/'))) {
            // Replace the current history entry to remove login page from back navigation
            history.replaceState(null, '', this.currentPath);
        }
        
        // Handle browser back/forward buttons
        window.addEventListener('popstate', (event) => {
            this.handleBackNavigation(event);
        });
        
        // Handle page visibility change (tab switching, minimize)
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                // Page became visible, validate session
                this.validateSession();
            }
        });
        
        // Handle beforeunload - warn about unsaved changes
        this.setupBeforeUnloadWarning();
    }

    handleLoginPage() {
        // Check if user is already authenticated
        this.checkAuthenticationStatus()
            .then(isAuthenticated => {
                if (isAuthenticated) {
                    // User is already logged in, redirect to dashboard
                    this.secureRedirectToDashboard();
                } else {
                    // Clear any stale authentication state
                    this.clearAuthenticationState();
                }
            });
    }

    async checkAuthenticationStatus() {
        try {
            const response = await fetch('/api/me', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'Cache-Control': 'no-cache'
                }
            });
            
            return response.ok;
        } catch (error) {
            console.log('Session check failed:', error);
            return false;
        }
    }

    secureRedirectToDashboard() {
        // Clear browser history and redirect
        window.location.replace('/dashboard');
    }

    preventPageCaching() {
        // Add cache control meta tags dynamically
        const meta = document.createElement('meta');
        meta.httpEquiv = 'Cache-Control';
        meta.content = 'no-cache, no-store, must-revalidate';
        document.head.appendChild(meta);

        const metaPragma = document.createElement('meta');
        metaPragma.httpEquiv = 'Pragma';
        metaPragma.content = 'no-cache';
        document.head.appendChild(metaPragma);

        const metaExpires = document.createElement('meta');
        metaExpires.httpEquiv = 'Expires';
        metaExpires.content = '0';
        document.head.appendChild(metaExpires);
    }

    preventCacheBackNavigation() {
        // Disable browser back button cache
        if (this.isAuthenticatedPage) {
            // Push a dummy state to prevent back navigation
            history.pushState(null, '', this.currentPath);
            
            // Listen for popstate (back button)
            window.addEventListener('popstate', () => {
                // Re-push the state to prevent actual back navigation
                history.pushState(null, '', this.currentPath);
            });
        }
    }

    handleBackNavigation(event) {
        // Prevent back navigation from authenticated pages to non-authenticated pages
        const fromSecurePage = this.isAuthenticatedPage;
        
        if (fromSecurePage) {
            // Check if trying to navigate back to login or public pages
            this.validateSession()
                .then(isValid => {
                    if (!isValid) {
                        // Session invalid, redirect to login
                        this.handleSessionExpired();
                    } else {
                        // Session valid, but prevent back navigation to login
                        history.pushState(null, '', this.currentPath);
                    }
                });
        }
    }

    setupSessionValidation() {
        // Validate session every 5 minutes
        setInterval(() => {
            if (this.isAuthenticatedPage) {
                this.validateSession();
            }
        }, 5 * 60 * 1000); // 5 minutes

        // Validate session on focus (when user returns to tab)
        window.addEventListener('focus', () => {
            if (this.isAuthenticatedPage) {
                this.validateSession();
            }
        });
    }

    async validateSession() {
        try {
            const response = await fetch('/api/me', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'Cache-Control': 'no-cache'
                }
            });

            if (!response.ok) {
                if (response.status === 401) {
                    this.handleSessionExpired();
                    return false;
                }
            }
            
            return response.ok;
        } catch (error) {
            console.error('Session validation failed:', error);
            // Don't force logout on network errors
            return true;
        }
    }

    handleSessionExpired() {
        // Clear all session data
        this.clearAuthenticationState();
        
        // Show session expired message
        this.showSessionExpiredNotification();
        
        // Redirect to login after short delay
        setTimeout(() => {
            window.location.replace('/login?session=expired');
        }, 2000);
    }

    clearAuthenticationState() {
        // Clear session storage
        sessionStorage.clear();
        
        // Clear any authentication-related local storage
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && (key.includes('auth') || key.includes('session') || key.includes('token'))) {
                keysToRemove.push(key);
            }
        }
        keysToRemove.forEach(key => localStorage.removeItem(key));
        
        // Clear flash messages
        this.clearFlashMessages();
    }

    async clearFlashMessages() {
        try {
            await fetch('/api/clear-flash', {
                method: 'POST',
                credentials: 'same-origin'
            });
        } catch (error) {
            console.log('Could not clear flash messages:', error);
        }
    }

    showSessionExpiredNotification() {
        // Create session expired notification
        const notification = document.createElement('div');
        notification.id = 'session-expired-notification';
        notification.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: linear-gradient(135deg, rgba(192, 21, 47, 0.95), rgba(255, 84, 89, 0.95));
            color: white;
            padding: 2rem 2.5rem;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            z-index: 10000;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            font-family: "FKGroteskNeue", "Geist", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        `;

        notification.innerHTML = `
            <div style="margin-bottom: 1rem;">
                <i class="fas fa-exclamation-triangle" style="font-size: 2rem; color: #FFE4B5;"></i>
            </div>
            <h3 style="margin: 0 0 0.5rem 0; font-size: 1.2rem;">Session Expired</h3>
            <p style="margin: 0; opacity: 0.9; font-size: 0.9rem;">
                Your session has expired for security reasons.<br>
                Redirecting to login...
            </p>
        `;

        document.body.appendChild(notification);

        // Add backdrop
        const backdrop = document.createElement('div');
        backdrop.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(5px);
            z-index: 9999;
        `;
        document.body.appendChild(backdrop);
    }

    setupBeforeUnloadWarning() {
        // Warn user before leaving secure pages
        let hasUnsavedChanges = false;
        
        // Monitor form changes
        document.addEventListener('input', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {
                hasUnsavedChanges = true;
            }
        });
        
        // Reset on form submission
        document.addEventListener('submit', () => {
            hasUnsavedChanges = false;
        });
        
        window.addEventListener('beforeunload', (e) => {
            if (hasUnsavedChanges && this.isAuthenticatedPage) {
                e.preventDefault();
                e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
                return e.returnValue;
            }
        });
    }

    setupSessionHandling() {
        // Handle successful login redirects
        if (window.location.search.includes('login=success')) {
            // Clear the URL parameter
            const url = new URL(window.location);
            url.searchParams.delete('login');
            history.replaceState(null, '', url.toString());
            
            // Show welcome notification
            this.showWelcomeNotification();
        }
        
        // Handle session expired parameter
        if (window.location.search.includes('session=expired')) {
            const url = new URL(window.location);
            url.searchParams.delete('session');
            history.replaceState(null, '', url.toString());
            
            this.showSessionExpiredMessage();
        }
    }

    showWelcomeNotification() {
        // Show welcome back notification
        if (window.SecretGuardian && window.SecretGuardian.showNotification) {
            window.SecretGuardian.showNotification(
                'Welcome back! You are now securely logged in.',
                'success',
                4000
            );
        }
    }

    showSessionExpiredMessage() {
        // Show session expired message on login page
        if (window.SecretGuardian && window.SecretGuardian.showNotification) {
            window.SecretGuardian.showNotification(
                'Your session has expired. Please log in again.',
                'warning',
                5000
            );
        }
    }

    // Enhanced logout function
    async secureLogout() {
        try {
            // Clear authentication state
            this.clearAuthenticationState();
            
            // Call server logout
            await fetch('/logout', {
                method: 'GET',
                credentials: 'same-origin'
            });
            
            // Force full page reload and redirect
            window.location.replace('/login');
            
        } catch (error) {
            console.error('Logout error:', error);
            // Force redirect even if server call fails
            window.location.replace('/login');
        }
    }

    // Public method to check if session is active
    isSessionActive() {
        return this.isAuthenticatedPage;
    }

    // Public method to extend session
    async extendSession() {
        try {
            const response = await fetch('/api/me', {
                method: 'GET',
                credentials: 'same-origin'
            });
            return response.ok;
        } catch (error) {
            return false;
        }
    }
}

// Enhanced login form handling
class LoginFormEnhancer {
    constructor() {
        this.init();
    }

    init() {
        this.enhanceLoginForms();
        this.setupOAuthHandling();
    }

    enhanceLoginForms() {
        // Enhance traditional login form
        const loginForm = document.querySelector('form[action="/token"]');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                this.handleLoginSubmit(e, loginForm);
            });
        }

        // Enhance OAuth buttons
        const oauthButtons = document.querySelectorAll('a[href*="/auth/"]');
        oauthButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                this.handleOAuthClick(e, button);
            });
        });
    }

    handleLoginSubmit(event, form) {
        const submitButton = form.querySelector('button[type="submit"]');
        if (submitButton) {
            this.addLoadingState(submitButton);
        }

        // Let the form submit naturally, server will redirect
    }

    handleOAuthClick(event, button) {
        this.addLoadingState(button);
        // Let the OAuth flow proceed naturally
    }

    addLoadingState(button) {
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Authenticating...';
        button.disabled = true;
        
        // Reset after 10 seconds as fallback
        setTimeout(() => {
            button.innerHTML = originalText;
            button.disabled = false;
        }, 10000);
    }

    setupOAuthHandling() {
        // Check for OAuth callback success
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('auth') === 'success') {
            // OAuth was successful, the server should redirect
            // If we're still on login page, something went wrong
            setTimeout(() => {
                if (window.location.pathname === '/login') {
                    window.location.reload();
                }
            }, 1000);
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize secure session management
    window.secureSessionManager = new SecureSessionManager();
    
    // Initialize login form enhancements
    window.loginFormEnhancer = new LoginFormEnhancer();
    
    // Enhanced logout function for global use
    window.secureLogout = () => {
        return window.secureSessionManager.secureLogout();
    };
});

// Expose for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SecureSessionManager, LoginFormEnhancer };
}