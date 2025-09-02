// SecretGuardian - Dark Mode Only Landing Page JavaScript

window.SecretGuardian = {
    // Initialize the application
    init() {
        this.enforceHardDarkMode();
        this.setupEventListeners();
        this.initializeAnimations();
        this.setupNotifications();
        this.setupKeyboardShortcuts();
    },

    // Force dark mode permanently
    enforceHardDarkMode() {
        // Set dark theme permanently
        document.documentElement.setAttribute('data-color-scheme', 'dark');
        document.body.classList.add('dark-theme');
        
        // Remove any light mode classes if they exist
        document.body.classList.remove('light-theme');
        
        // Set CSS custom properties for dark mode
        document.documentElement.style.setProperty('--color-background', 'rgba(31, 33, 33, 1)');
        document.documentElement.style.setProperty('--color-surface', 'rgba(38, 40, 40, 1)');
        document.documentElement.style.setProperty('--color-text', 'rgba(245, 245, 245, 1)');
        
        // Override any system theme detection
        if (window.matchMedia) {
            window.matchMedia('(prefers-color-scheme: light)').removeEventListener = () => {};
            window.matchMedia('(prefers-color-scheme: dark)').removeEventListener = () => {};
        }
    },

    // Setup global event listeners
    setupEventListeners() {
        // Navbar scroll effects
        const navbar = document.querySelector('.navbar');
        if (navbar) {
            let lastScrollY = window.scrollY;
            window.addEventListener('scroll', () => {
                const currentScrollY = window.scrollY;
                
                // Change navbar background on scroll - Dark mode only
                if (currentScrollY > 50) {
                    navbar.style.background = 'rgba(31, 33, 33, 0.98)';
                    navbar.style.backdropFilter = 'blur(25px)';
                    navbar.style.borderBottom = '1px solid rgba(119, 124, 124, 0.5)';
                } else {
                    navbar.style.background = 'rgba(31, 33, 33, 0.95)';
                    navbar.style.backdropFilter = 'blur(20px)';
                    navbar.style.borderBottom = '1px solid rgba(119, 124, 124, 0.3)';
                }

                // Hide/show navbar on scroll
                if (currentScrollY > lastScrollY && currentScrollY > 100) {
                    navbar.style.transform = 'translateY(-100%)';
                } else {
                    navbar.style.transform = 'translateY(0)';
                }

                lastScrollY = currentScrollY;
            });
        }

        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    const offsetTop = target.offsetTop - 80;
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                }
            });
        });

        // Mobile menu toggle
        const mobileToggle = document.querySelector('.mobile-menu-toggle');
        const navMenu = document.querySelector('.nav-menu');
        if (mobileToggle && navMenu) {
            mobileToggle.addEventListener('click', () => {
                navMenu.classList.toggle('active');
                const icon = mobileToggle.querySelector('i');
                if (icon) {
                    icon.classList.toggle('fa-bars');
                    icon.classList.toggle('fa-times');
                }
            });

            // Close menu when clicking outside
            document.addEventListener('click', (e) => {
                if (!mobileToggle.contains(e.target) && !navMenu.contains(e.target)) {
                    navMenu.classList.remove('active');
                    const icon = mobileToggle.querySelector('i');
                    if (icon) {
                        icon.classList.add('fa-bars');
                        icon.classList.remove('fa-times');
                    }
                }
            });
        }

        // Form enhancements
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', this.handleFormSubmit.bind(this));
        });

        // Button click effects
        document.querySelectorAll('.btn').forEach(btn => {
            btn.addEventListener('click', this.createRippleEffect);
        });

        // Showcase image clicks
        document.querySelectorAll('.preview-overlay, .showcase-overlay').forEach(overlay => {
            overlay.addEventListener('click', (e) => {
                const img = e.currentTarget.previousElementSibling || 
                           e.currentTarget.parentElement.querySelector('img');
                if (img) {
                    this.openImageModal(img.src, img.alt);
                }
            });
        });

        // Parallax effect for sections
        this.setupParallaxEffect();
    },

    // Setup parallax effect for elements
    setupParallaxEffect() {
        const parallaxElements = document.querySelectorAll('.hero-section, .stats-section');
        window.addEventListener('scroll', () => {
            const scrollTop = window.pageYOffset;
            parallaxElements.forEach((element, index) => {
                const rate = scrollTop * -0.05 * (index + 1);
                element.style.transform = `translateY(${rate}px)`;
            });
        });
    },

    // Initialize animations and intersection observer
    initializeAnimations() {
        // Intersection Observer for scroll animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                    
                    // Add staggered animation for grid items
                    if (entry.target.parentElement?.classList.contains('features-grid') ||
                        entry.target.parentElement?.classList.contains('security-grid') ||
                        entry.target.parentElement?.classList.contains('stats-grid')) {
                        const siblings = Array.from(entry.target.parentElement.children);
                        const index = siblings.indexOf(entry.target);
                        entry.target.style.animationDelay = `${index * 0.1}s`;
                    }

                    observer.unobserve(entry.target);
                }
            });
        }, observerOptions);

        // Observe elements for animation
        document.querySelectorAll(`
            .feature-card,
            .security-item,
            .stat-card,
            .showcase-item,
            .benefit-item,
            .section-header
        `).forEach(el => {
            observer.observe(el);
        });

        // Counter animation for statistics
        this.animateCounters();
        
        // Add hover effects to cards
        this.setupHoverEffects();
    },

    // Setup hover effects for interactive elements
    setupHoverEffects() {
        // Feature cards hover effect
        document.querySelectorAll('.feature-card').forEach(card => {
            card.addEventListener('mouseenter', () => {
                card.style.transform = 'translateY(-8px)';
                card.style.transition = 'all 0.3s ease';
                card.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.2)';
            });

            card.addEventListener('mouseleave', () => {
                card.style.transform = 'translateY(0)';
                card.style.boxShadow = '0 1px 3px rgba(0, 0, 0, 0.4), 0 1px 2px rgba(0, 0, 0, 0.2)';
            });
        });

        // Security items hover effect
        document.querySelectorAll('.security-item').forEach(item => {
            item.addEventListener('mouseenter', () => {
                item.style.transform = 'translateY(-4px)';
                item.style.transition = 'all 0.3s ease';
            });

            item.addEventListener('mouseleave', () => {
                item.style.transform = 'translateY(0)';
            });
        });

        // Stat cards hover effect
        document.querySelectorAll('.stat-card').forEach(card => {
            card.addEventListener('mouseenter', () => {
                card.style.transform = 'translateY(-4px) scale(1.02)';
                card.style.transition = 'all 0.3s ease';
            });

            card.addEventListener('mouseleave', () => {
                card.style.transform = 'translateY(0) scale(1)';
            });
        });

        // Benefit items hover effect
        document.querySelectorAll('.benefit-item').forEach(item => {
            item.addEventListener('mouseenter', () => {
                const icon = item.querySelector('.benefit-icon');
                if (icon) {
                    icon.style.transform = 'scale(1.1) rotate(5deg)';
                    icon.style.transition = 'all 0.3s ease';
                }
            });

            item.addEventListener('mouseleave', () => {
                const icon = item.querySelector('.benefit-icon');
                if (icon) {
                    icon.style.transform = 'scale(1) rotate(0deg)';
                }
            });
        });
    },

    // Animate number counters
    animateCounters() {
        const counters = document.querySelectorAll('[data-count], .stat-number');
        
        const counterObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const target = entry.target;
                    const finalValue = target.getAttribute('data-count') || target.textContent;
                    
                    if (finalValue.includes('%')) {
                        this.animateNumber(target, 0, parseInt(finalValue), 2000, '%');
                    } else if (finalValue.includes('+')) {
                        this.animateNumber(target, 0, parseInt(finalValue), 2000, '+');
                    } else if (!isNaN(parseInt(finalValue))) {
                        this.animateNumber(target, 0, parseInt(finalValue), 2000);
                    }

                    counterObserver.unobserve(target);
                }
            });
        }, { threshold: 0.5 });

        counters.forEach(counter => counterObserver.observe(counter));
    },

    // Animate a number from start to end
    animateNumber(element, start, end, duration, suffix = '') {
        const range = end - start;
        const increment = range / (duration / 16);
        let current = start;

        const timer = setInterval(() => {
            current += increment;
            if (current >= end) {
                element.textContent = end + suffix;
                clearInterval(timer);
            } else {
                element.textContent = Math.floor(current) + suffix;
            }
        }, 16);
    },

    // Setup notification system
    setupNotifications() {
        // Create notification container if it doesn't exist
        if (!document.getElementById('notification-container')) {
            const container = document.createElement('div');
            container.id = 'notification-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                display: flex;
                flex-direction: column;
                gap: 10px;
                max-width: 400px;
                pointer-events: none;
            `;
            document.body.appendChild(container);
        }
    },

    // Show notification
    showNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notification-container');
        if (!container) return;

        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;

        const colors = {
            success: '#32B8C6',
            error: '#FF5459',
            warning: '#E68161',
            info: '#50B8C6'
        };

        notification.style.cssText = `
            background: linear-gradient(145deg, rgba(38, 40, 40, 0.95), rgba(31, 33, 33, 1));
            color: #F5F5F5;
            padding: 1rem 1.5rem;
            border-radius: 12px;
            border-left: 4px solid ${colors[type] || colors.info};
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.2);
            transform: translateX(100%);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.9rem;
            line-height: 1.4;
            pointer-events: auto;
            backdrop-filter: blur(20px);
        `;

        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-triangle',
            warning: 'fa-exclamation-circle',
            info: 'fa-info-circle'
        };

        notification.innerHTML = `
            <i class="fas ${icons[type] || icons.info}" style="color: ${colors[type] || colors.info}"></i>
            <span>${message}</span>
            <i class="fas fa-times" style="cursor: pointer; margin-left: auto; opacity: 0.7;"></i>
        `;

        // Close button functionality
        notification.querySelector('.fa-times').addEventListener('click', () => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => notification.remove(), 300);
        });

        container.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 10);

        // Auto remove
        if (duration > 0) {
            setTimeout(() => {
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => {
                    if (notification.parentElement) {
                        notification.remove();
                    }
                }, 300);
            }, duration);
        }

        return notification;
    },

    // Open image modal for showcase
    openImageModal(src, alt) {
        const modal = document.createElement('div');
        modal.className = 'image-modal';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.95);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            cursor: pointer;
            opacity: 0;
            transition: opacity 0.3s ease;
            backdrop-filter: blur(10px);
        `;

        const img = document.createElement('img');
        img.src = src;
        img.alt = alt;
        img.style.cssText = `
            max-width: 90vw;
            max-height: 90vh;
            border-radius: 12px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.2);
            object-fit: contain;
        `;

        const closeButton = document.createElement('button');
        closeButton.innerHTML = '<i class="fas fa-times"></i>';
        closeButton.style.cssText = `
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(38, 40, 40, 0.8);
            border: 2px solid rgba(245, 245, 245, 0.3);
            color: #F5F5F5;
            font-size: 18px;
            padding: 12px;
            border-radius: 50%;
            cursor: pointer;
            backdrop-filter: blur(10px);
            transition: all 0.2s ease;
            width: 44px;
            height: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
        `;

        closeButton.addEventListener('mouseenter', () => {
            closeButton.style.background = 'rgba(50, 184, 198, 0.8)';
            closeButton.style.transform = 'scale(1.1)';
        });

        closeButton.addEventListener('mouseleave', () => {
            closeButton.style.background = 'rgba(38, 40, 40, 0.8)';
            closeButton.style.transform = 'scale(1)';
        });

        // Add loading indicator
        const loader = document.createElement('div');
        loader.style.cssText = `
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            color: #F5F5F5;
            font-size: 2rem;
        `;
        loader.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

        modal.appendChild(loader);
        modal.appendChild(closeButton);
        document.body.appendChild(modal);

        // Handle image loading
        img.onload = () => {
            loader.remove();
            modal.appendChild(img);
        };

        img.onerror = () => {
            loader.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Failed to load image';
        };

        // Animate in
        setTimeout(() => {
            modal.style.opacity = '1';
        }, 10);

        // Close functions
        const closeModal = () => {
            modal.style.opacity = '0';
            setTimeout(() => modal.remove(), 300);
        };

        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });

        closeButton.addEventListener('click', closeModal);

        // Close on escape
        const handleEscape = (e) => {
            if (e.key === 'Escape') {
                closeModal();
                document.removeEventListener('keydown', handleEscape);
            }
        };
        document.addEventListener('keydown', handleEscape);
    },

    // Handle form submissions
    handleFormSubmit(event) {
        const form = event.target;
        const submitButton = form.querySelector('[type="submit"]');
        
        if (submitButton && !submitButton.disabled) {
            const originalText = submitButton.innerHTML;
            
            // Add loading state
            submitButton.classList.add('loading');
            submitButton.disabled = true;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
            
            // Reset after timeout (fallback)
            setTimeout(() => {
                if (submitButton.classList.contains('loading')) {
                    submitButton.classList.remove('loading');
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalText;
                }
            }, 10000);
        }
    },

    // Create ripple effect on button clicks
    createRippleEffect(event) {
        const button = event.currentTarget;
        const rect = button.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;

        const ripple = document.createElement('span');
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: rgba(50, 184, 198, 0.3);
            border-radius: 50%;
            transform: scale(0);
            animation: ripple 0.6s linear;
            pointer-events: none;
        `;

        // Add ripple animation if not exists
        if (!document.querySelector('#ripple-styles')) {
            const style = document.createElement('style');
            style.id = 'ripple-styles';
            style.textContent = `
                @keyframes ripple {
                    to {
                        transform: scale(4);
                        opacity: 0;
                    }
                }
            `;
            document.head.appendChild(style);
        }

        button.style.position = 'relative';
        button.style.overflow = 'hidden';
        button.appendChild(ripple);

        setTimeout(() => {
            ripple.remove();
        }, 600);
    },

    // Setup keyboard shortcuts
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (event) => {
            // Escape to close notifications and modals
            if (event.key === 'Escape') {
                document.querySelectorAll('.notification').forEach(n => n.remove());
                document.querySelectorAll('.image-modal').forEach(m => {
                    m.style.opacity = '0';
                    setTimeout(() => m.remove(), 300);
                });
            }

            // Alt + H for home
            if (event.altKey && event.key === 'h') {
                event.preventDefault();
                window.location.href = '#hero-section';
            }

            // Alt + F for features
            if (event.altKey && event.key === 'f') {
                event.preventDefault();
                const featuresSection = document.querySelector('#features');
                if (featuresSection) {
                    featuresSection.scrollIntoView({ behavior: 'smooth' });
                }
            }

            // Alt + S for security
            if (event.altKey && event.key === 's') {
                event.preventDefault();
                const securitySection = document.querySelector('#security');
                if (securitySection) {
                    securitySection.scrollIntoView({ behavior: 'smooth' });
                }
            }
        });
    },

    // Utility functions
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // Initialize background animations
    initBackgroundAnimations() {
        // Add floating animation to feature icons
        document.querySelectorAll('.feature-icon, .benefit-icon, .security-icon').forEach((icon, index) => {
            icon.style.animation = `float ${4 + (index % 3)}s ease-in-out infinite`;
            icon.style.animationDelay = `${(index % 5) * 0.5}s`;
        });

        // Add CSS for floating animation if not exists
        if (!document.querySelector('#floating-styles')) {
            const style = document.createElement('style');
            style.id = 'floating-styles';
            style.textContent = `
                @keyframes float {
                    0%, 100% { transform: translateY(0px); }
                    50% { transform: translateY(-8px); }
                }
            `;
            document.head.appendChild(style);
        }
    },

    // Add loading states for async operations
    addLoadingState(element, text = 'Loading...') {
        element.classList.add('loading');
        element.disabled = true;
        const originalContent = element.innerHTML;
        element.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
        
        return () => {
            element.classList.remove('loading');
            element.disabled = false;
            element.innerHTML = originalContent;
        };
    },

    // Smooth reveal animations on page sections
    revealSections() {
        const sections = document.querySelectorAll('section');
        sections.forEach((section, index) => {
            section.style.opacity = '0';
            section.style.transform = 'translateY(30px)';
            
            setTimeout(() => {
                section.style.transition = 'all 0.8s ease-out';
                section.style.opacity = '1';
                section.style.transform = 'translateY(0)';
            }, index * 200);
        });
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.SecretGuardian.init();
    window.SecretGuardian.initBackgroundAnimations();
    
    // Show welcome notification after a short delay
    setTimeout(() => {
        window.SecretGuardian.showNotification(
            'Welcome to SecretGuardian! Secure your repositories today.',
            'success',
            4000
        );
    }, 1000);
});

// Handle page visibility changes - Pause animations when not visible
document.addEventListener('visibilitychange', () => {
    const elements = document.querySelectorAll('[style*="animation"]');
    if (document.hidden) {
        elements.forEach(el => el.style.animationPlayState = 'paused');
    } else {
        elements.forEach(el => el.style.animationPlayState = 'running');
    }
});

// Performance optimizations - Preload critical images
if ('requestIdleCallback' in window) {
    window.requestIdleCallback(() => {
        const criticalImages = [
            'favicon.jpg',
            'screenshot-dashboard.jpg',
            'screenshot-reports.jpg',
            'screenshot-repos.jpg'
        ];

        criticalImages.forEach(src => {
            const img = new Image();
            img.src = src;
        });
    });
}

// Smooth entrance animations on page load
window.addEventListener('load', () => {
    // Add entrance animation to the hero content
    const heroContent = document.querySelector('.hero-content');
    if (heroContent) {
        heroContent.style.transform = 'translateY(30px)';
        heroContent.style.opacity = '0';
        
        setTimeout(() => {
            heroContent.style.transition = 'all 1s ease-out';
            heroContent.style.transform = 'translateY(0)';
            heroContent.style.opacity = '1';
        }, 200);
    }

    // Reveal sections with staggered animation
    setTimeout(() => {
        window.SecretGuardian.revealSections();
    }, 500);
});

// Export for use in other scripts if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.SecretGuardian;
}