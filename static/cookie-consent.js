// Cookie Consent Management System for SecretGuardian
// Add to static folder

class CookieConsent {
    constructor() {
        this.cookieName = 'secretguardian_cookie_consent';
        this.consentVersion = '1.0';
        this.init();
    }

    init() {
        // Check if consent already given
        if (!this.hasConsent()) {
            this.showConsentBanner();
        }
        
        // Initialize analytics and other cookies only if consent given
        if (this.hasConsent()) {
            this.initializeCookies();
        }
    }

    hasConsent() {
        const consent = this.getCookie(this.cookieName);
        return consent === this.consentVersion;
    }

    showConsentBanner() {
        // Create banner HTML
        const bannerHTML = `
            <div id="cookie-consent-banner" class="cookie-consent-banner">
                <div class="cookie-consent-content">
                    <div class="cookie-consent-text">
                        <div class="cookie-icon">
                            <i class="fas fa-cookie-bite"></i>
                        </div>
                        <div class="cookie-message">
                            <h4>We use cookies</h4>
                            <p>SecretGuardian uses essential cookies to ensure proper functionality and improve your security scanning experience. We also use analytics cookies to help us understand how you interact with our platform.</p>
                        </div>
                    </div>
                    <div class="cookie-consent-actions">
                        <button id="cookie-settings-btn" class="btn btn--outline btn--sm">
                            <i class="fas fa-cog"></i> Settings
                        </button>
                        <button id="cookie-accept-btn" class="btn btn--primary btn--sm">
                            <i class="fas fa-check"></i> Accept All
                        </button>
                    </div>
                </div>
                
                <!-- Cookie Settings Modal -->
                <div id="cookie-settings-modal" class="cookie-settings-modal" style="display: none;">
                    <div class="cookie-settings-content">
                        <div class="cookie-settings-header">
                            <h3>Cookie Settings</h3>
                            <button id="cookie-settings-close" class="cookie-settings-close">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                        
                        <div class="cookie-settings-body">
                            <div class="cookie-category">
                                <div class="cookie-category-header">
                                    <div class="cookie-category-info">
                                        <h4>Essential Cookies</h4>
                                        <p>Required for basic site functionality</p>
                                    </div>
                                    <div class="cookie-toggle">
                                        <input type="checkbox" id="essential-cookies" checked disabled>
                                        <label for="essential-cookies" class="toggle-label">Always On</label>
                                    </div>
                                </div>
                                <div class="cookie-category-details">
                                    <p>These cookies are necessary for the website to function and cannot be disabled. They include authentication, security, and basic functionality cookies.</p>
                                </div>
                            </div>
                            
                            <div class="cookie-category">
                                <div class="cookie-category-header">
                                    <div class="cookie-category-info">
                                        <h4>Analytics Cookies</h4>
                                        <p>Help us improve our service</p>
                                    </div>
                                    <div class="cookie-toggle">
                                        <input type="checkbox" id="analytics-cookies" checked>
                                        <label for="analytics-cookies" class="toggle-label"></label>
                                    </div>
                                </div>
                                <div class="cookie-category-details">
                                    <p>These cookies help us understand how visitors interact with our website by collecting and reporting information anonymously.</p>
                                </div>
                            </div>
                            
                            <div class="cookie-category">
                                <div class="cookie-category-header">
                                    <div class="cookie-category-info">
                                        <h4>Functional Cookies</h4>
                                        <p>Enhanced features and personalization</p>
                                    </div>
                                    <div class="cookie-toggle">
                                        <input type="checkbox" id="functional-cookies" checked>
                                        <label for="functional-cookies" class="toggle-label"></label>
                                    </div>
                                </div>
                                <div class="cookie-category-details">
                                    <p>These cookies enable enhanced functionality and personalization, such as remembering your preferences and settings.</p>
                                </div>
                            </div>
                        </div>
                        
                        <div class="cookie-settings-footer">
                            <button id="cookie-save-settings" class="btn btn--primary">
                                <i class="fas fa-save"></i> Save Settings
                            </button>
                            <button id="cookie-accept-all-modal" class="btn btn--secondary">
                                <i class="fas fa-check-double"></i> Accept All
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Add banner to body
        document.body.insertAdjacentHTML('beforeend', bannerHTML);
        
        // Add CSS styles
        this.addStyles();
        
        // Add event listeners
        this.addEventListeners();
        
        // Animate banner in
        setTimeout(() => {
            const banner = document.getElementById('cookie-consent-banner');
            if (banner) {
                banner.classList.add('show');
            }
        }, 100);
    }

    addStyles() {
        const styles = `
            <style id="cookie-consent-styles">
                .cookie-consent-banner {
                    position: fixed;
                    bottom: -100%;
                    left: 0;
                    right: 0;
                    background: linear-gradient(135deg, rgba(13, 18, 36, 0.98), rgba(31, 33, 33, 0.98));
                    backdrop-filter: blur(20px);
                    border-top: 2px solid #32B8C6;
                    box-shadow: 0 -10px 25px rgba(0, 0, 0, 0.3);
                    z-index: 10000;
                    transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                    font-family: "FKGroteskNeue", "Geist", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                }
                
                .cookie-consent-banner.show {
                    bottom: 0;
                }
                
                .cookie-consent-content {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding: 1.5rem 2rem;
                    max-width: 1200px;
                    margin: 0 auto;
                    gap: 2rem;
                }
                
                .cookie-consent-text {
                    display: flex;
                    align-items: flex-start;
                    gap: 1rem;
                    flex: 1;
                }
                
                .cookie-icon {
                    color: #32B8C6;
                    font-size: 1.5rem;
                    margin-top: 0.25rem;
                    flex-shrink: 0;
                }
                
                .cookie-message h4 {
                    color: #f5f5f5;
                    margin: 0 0 0.5rem 0;
                    font-size: 1.1rem;
                    font-weight: 600;
                }
                
                .cookie-message p {
                    color: #a7a9a9;
                    margin: 0;
                    font-size: 0.9rem;
                    line-height: 1.5;
                }
                
                .cookie-consent-actions {
                    display: flex;
                    gap: 1rem;
                    flex-shrink: 0;
                }
                
                .cookie-settings-modal {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: rgba(0, 0, 0, 0.8);
                    backdrop-filter: blur(10px);
                    z-index: 10001;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 2rem;
                }
                
                .cookie-settings-content {
                    background: linear-gradient(135deg, rgba(13, 18, 36, 0.95), rgba(31, 33, 33, 0.95));
                    border-radius: 12px;
                    border: 1px solid rgba(94, 82, 64, 0.2);
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
                    max-width: 600px;
                    width: 100%;
                    max-height: 80vh;
                    overflow-y: auto;
                }
                
                .cookie-settings-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding: 1.5rem 2rem;
                    border-bottom: 1px solid rgba(94, 82, 64, 0.2);
                }
                
                .cookie-settings-header h3 {
                    color: #f5f5f5;
                    margin: 0;
                    font-size: 1.3rem;
                    font-weight: 600;
                }
                
                .cookie-settings-close {
                    background: none;
                    border: none;
                    color: #a7a9a9;
                    font-size: 1.2rem;
                    cursor: pointer;
                    padding: 0.5rem;
                    border-radius: 6px;
                    transition: all 0.2s ease;
                }
                
                .cookie-settings-close:hover {
                    color: #32B8C6;
                    background: rgba(50, 184, 198, 0.1);
                }
                
                .cookie-settings-body {
                    padding: 2rem;
                }
                
                .cookie-category {
                    margin-bottom: 2rem;
                    border: 1px solid rgba(94, 82, 64, 0.2);
                    border-radius: 8px;
                    overflow: hidden;
                }
                
                .cookie-category:last-child {
                    margin-bottom: 0;
                }
                
                .cookie-category-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding: 1.5rem;
                    background: rgba(13, 18, 36, 0.5);
                }
                
                .cookie-category-info h4 {
                    color: #f5f5f5;
                    margin: 0 0 0.25rem 0;
                    font-size: 1rem;
                    font-weight: 600;
                }
                
                .cookie-category-info p {
                    color: #a7a9a9;
                    margin: 0;
                    font-size: 0.85rem;
                }
                
                .cookie-toggle {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }
                
                .cookie-toggle input[type="checkbox"] {
                    display: none;
                }
                
                .toggle-label {
                    position: relative;
                    width: 50px;
                    height: 24px;
                    background: #626470;
                    border-radius: 12px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    font-size: 0.75rem;
                    color: #a7a9a9;
                }
                
                .toggle-label:before {
                    content: '';
                    position: absolute;
                    top: 2px;
                    left: 2px;
                    width: 20px;
                    height: 20px;
                    background: #f5f5f5;
                    border-radius: 50%;
                    transition: all 0.3s ease;
                }
                
                input[type="checkbox"]:checked + .toggle-label {
                    background: #32B8C6;
                }
                
                input[type="checkbox"]:checked + .toggle-label:before {
                    transform: translateX(26px);
                }
                
                input[type="checkbox"]:disabled + .toggle-label {
                    opacity: 0.6;
                    cursor: not-allowed;
                }
                
                .cookie-category-details {
                    padding: 1.5rem;
                    background: rgba(38, 40, 40, 0.3);
                }
                
                .cookie-category-details p {
                    color: #a7a9a9;
                    margin: 0;
                    font-size: 0.85rem;
                    line-height: 1.5;
                }
                
                .cookie-settings-footer {
                    display: flex;
                    gap: 1rem;
                    padding: 1.5rem 2rem;
                    border-top: 1px solid rgba(94, 82, 64, 0.2);
                    justify-content: flex-end;
                }
                
                /* Mobile responsive */
                @media (max-width: 768px) {
                    .cookie-consent-content {
                        flex-direction: column;
                        align-items: flex-start;
                        gap: 1.5rem;
                        padding: 1.5rem;
                    }
                    
                    .cookie-consent-actions {
                        width: 100%;
                        justify-content: space-between;
                    }
                    
                    .cookie-settings-modal {
                        padding: 1rem;
                    }
                    
                    .cookie-settings-header {
                        padding: 1rem 1.5rem;
                    }
                    
                    .cookie-settings-body {
                        padding: 1.5rem;
                    }
                    
                    .cookie-settings-footer {
                        padding: 1rem 1.5rem;
                        flex-direction: column;
                    }
                }
            </style>
        `;
        
        document.head.insertAdjacentHTML('beforeend', styles);
    }

    addEventListeners() {
        // Accept all cookies
        const acceptBtn = document.getElementById('cookie-accept-btn');
        acceptBtn?.addEventListener('click', () => {
            this.acceptAllCookies();
        });

        // Show settings modal
        const settingsBtn = document.getElementById('cookie-settings-btn');
        settingsBtn?.addEventListener('click', () => {
            this.showSettingsModal();
        });

        // Close settings modal
        const closeBtn = document.getElementById('cookie-settings-close');
        closeBtn?.addEventListener('click', () => {
            this.hideSettingsModal();
        });

        // Save custom settings
        const saveBtn = document.getElementById('cookie-save-settings');
        saveBtn?.addEventListener('click', () => {
            this.saveCustomSettings();
        });

        // Accept all from modal
        const acceptAllModalBtn = document.getElementById('cookie-accept-all-modal');
        acceptAllModalBtn?.addEventListener('click', () => {
            this.acceptAllCookies();
        });

        // Close modal on backdrop click
        const modal = document.getElementById('cookie-settings-modal');
        modal?.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.hideSettingsModal();
            }
        });
    }

    showSettingsModal() {
        const modal = document.getElementById('cookie-settings-modal');
        if (modal) {
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }

    hideSettingsModal() {
        const modal = document.getElementById('cookie-settings-modal');
        if (modal) {
            modal.style.display = 'none';
            document.body.style.overflow = '';
        }
    }

    acceptAllCookies() {
        this.setCookie(this.cookieName, this.consentVersion, 365);
        this.setCookie('analytics_consent', 'true', 365);
        this.setCookie('functional_consent', 'true', 365);
        this.initializeCookies();
        this.hideBanner();
    }

    saveCustomSettings() {
        const analyticsConsent = document.getElementById('analytics-cookies')?.checked || false;
        const functionalConsent = document.getElementById('functional-cookies')?.checked || false;
        
        this.setCookie(this.cookieName, this.consentVersion, 365);
        this.setCookie('analytics_consent', analyticsConsent.toString(), 365);
        this.setCookie('functional_consent', functionalConsent.toString(), 365);
        
        this.initializeCookies();
        this.hideSettingsModal();
        this.hideBanner();
    }

    hideBanner() {
        const banner = document.getElementById('cookie-consent-banner');
        if (banner) {
            banner.classList.remove('show');
            setTimeout(() => {
                banner.remove();
                // Remove styles
                const styles = document.getElementById('cookie-consent-styles');
                styles?.remove();
            }, 400);
        }
    }

    initializeCookies() {
        const analyticsConsent = this.getCookie('analytics_consent') === 'true';
        const functionalConsent = this.getCookie('functional_consent') === 'true';
        
        // Initialize analytics if consented
        if (analyticsConsent) {
            this.initializeAnalytics();
        }
        
        // Initialize functional cookies if consented
        if (functionalConsent) {
            this.initializeFunctional();
        }
        
        console.log('SecretGuardian: Cookies initialized based on user consent');
    }

    initializeAnalytics() {
        // Initialize your analytics here (Google Analytics, etc.)
        console.log('Analytics cookies enabled');
    }

    initializeFunctional() {
        // Initialize functional cookies here
        console.log('Functional cookies enabled');
    }

    // Cookie utility methods
    setCookie(name, value, days) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Lax;Secure`;
    }

    getCookie(name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
        }
        return null;
    }

    deleteCookie(name) {
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
    }

    // Public methods for external use
    hasAnalyticsConsent() {
        return this.getCookie('analytics_consent') === 'true';
    }

    hasFunctionalConsent() {
        return this.getCookie('functional_consent') === 'true';
    }

    showConsentBannerAgain() {
        this.deleteCookie(this.cookieName);
        this.deleteCookie('analytics_consent');
        this.deleteCookie('functional_consent');
        this.showConsentBanner();
    }
}

// Initialize cookie consent when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.cookieConsent = new CookieConsent();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CookieConsent;
}