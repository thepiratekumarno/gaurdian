// Secret Guardian - JavaScript with Solarin Theme Colors

document.addEventListener('DOMContentLoaded', function() {
    // Initialize homepage animations if on homepage
    if (document.getElementById('hero-canvas')) {
        initThreeJSBackground();
        initScrollAnimations();
    }
    
    // Initialize general features for all pages
    initNavigation();
    initUtilities();
});

// Three.js Background Animation for Homepage - Solarin Colors
function initThreeJSBackground() {
    const canvas = document.getElementById('hero-canvas');
    if (!canvas) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ 
        canvas: canvas, 
        alpha: true,
        antialias: true 
    });

    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);

    // Create particles with Solarin colors
    const particlesGeometry = new THREE.BufferGeometry();
    const particlesCount = 1000;
    const posArray = new Float32Array(particlesCount * 3);
    const colorArray = new Float32Array(particlesCount * 3);

    // Solarin color palette
    const solarinColors = [
        { r: 0.196, g: 0.722, b: 0.776 }, // Bright teal #32B8C6
        { r: 0.067, g: 0.392, b: 0.400 }, // Deep teal #116466
        { r: 0.851, g: 0.690, b: 0.549 }, // Copper #D9B08C
        { r: 1.000, g: 0.796, b: 0.604 }, // Peach #FFCB9A
        { r: 0.820, g: 0.910, b: 0.886 }  // Mint #D1E8E2
    ];

    for(let i = 0; i < particlesCount; i++) {
        // Position
        posArray[i * 3] = (Math.random() - 0.5) * 50;
        posArray[i * 3 + 1] = (Math.random() - 0.5) * 50;
        posArray[i * 3 + 2] = (Math.random() - 0.5) * 50;

        // Color - randomly pick from Solarin palette
        const colorIndex = Math.floor(Math.random() * solarinColors.length);
        const color = solarinColors[colorIndex];
        colorArray[i * 3] = color.r;
        colorArray[i * 3 + 1] = color.g;
        colorArray[i * 3 + 2] = color.b;
    }

    particlesGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
    particlesGeometry.setAttribute('color', new THREE.BufferAttribute(colorArray, 3));

    const particlesMaterial = new THREE.PointsMaterial({
        size: 0.025,
        vertexColors: true,
        transparent: true,
        opacity: 0.8,
        blending: THREE.AdditiveBlending
    });

    const particlesMesh = new THREE.Points(particlesGeometry, particlesMaterial);
    scene.add(particlesMesh);

    // Create connections between nearby particles
    const connections = new THREE.BufferGeometry();
    const connectionPositions = [];
    const connectionColors = [];

    for(let i = 0; i < particlesCount; i++) {
        for(let j = i + 1; j < particlesCount; j++) {
            const distance = Math.sqrt(
                Math.pow(posArray[i * 3] - posArray[j * 3], 2) +
                Math.pow(posArray[i * 3 + 1] - posArray[j * 3 + 1], 2) +
                Math.pow(posArray[i * 3 + 2] - posArray[j * 3 + 2], 2)
            );

            if(distance < 3.5) {
                connectionPositions.push(
                    posArray[i * 3], posArray[i * 3 + 1], posArray[i * 3 + 2],
                    posArray[j * 3], posArray[j * 3 + 1], posArray[j * 3 + 2]
                );

                // Use bright teal for connections
                const opacity = 1 - (distance / 3.5);
                connectionColors.push(0.196, 0.722, 0.776, opacity * 0.3);
                connectionColors.push(0.196, 0.722, 0.776, opacity * 0.3);
            }
        }
    }

    connections.setAttribute('position', new THREE.Float32BufferAttribute(connectionPositions, 3));
    connections.setAttribute('color', new THREE.Float32BufferAttribute(connectionColors, 4));

    const connectionMaterial = new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        blending: THREE.AdditiveBlending
    });

    const connectionMesh = new THREE.LineSegments(connections, connectionMaterial);
    scene.add(connectionMesh);

    camera.position.z = 15;

    // Animation variables
    let mouseX = 0;
    let mouseY = 0;
    let time = 0;
    
    document.addEventListener('mousemove', (event) => {
        mouseX = (event.clientX / window.innerWidth) * 2 - 1;
        mouseY = -(event.clientY / window.innerHeight) * 2 + 1;
    });

    function animate() {
        requestAnimationFrame(animate);
        time += 0.01;

        // Rotate particles slowly with some wave motion
        particlesMesh.rotation.x += 0.0003;
        particlesMesh.rotation.y += 0.0008;
        connectionMesh.rotation.x += 0.0003;
        connectionMesh.rotation.y += 0.0008;

        // Add subtle floating motion
        particlesMesh.position.y = Math.sin(time * 0.5) * 0.5;
        connectionMesh.position.y = Math.sin(time * 0.5) * 0.5;

        // Mouse interaction with smooth following
        camera.position.x += (mouseX * 0.2 - camera.position.x) * 0.02;
        camera.position.y += (mouseY * 0.2 - camera.position.y) * 0.02;
        camera.lookAt(scene.position);

        renderer.render(scene, camera);
    }

    animate();

    // Handle window resize
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
}

// Scroll Animations for Homepage
function initScrollAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
                
                // Add stagger effect to feature cards
                if (entry.target.classList.contains('homepage-feature-card')) {
                    const cards = document.querySelectorAll('.homepage-feature-card');
                    const index = Array.from(cards).indexOf(entry.target);
                    entry.target.style.transitionDelay = `${index * 0.1}s`;
                }
                
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Observe elements for animation
    const animateElements = document.querySelectorAll('.homepage-feature-card, .homepage-step');
    animateElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'opacity 0.8s cubic-bezier(0.175, 0.885, 0.32, 1.275), transform 0.8s cubic-bezier(0.175, 0.885, 0.32, 1.275)';
        observer.observe(el);
    });

    // Navbar scroll effect for homepage
    const navbar = document.querySelector('.homepage-navbar');
    if (navbar) {
        window.addEventListener('scroll', () => {
            if (window.scrollY > 50) {
                navbar.style.background = 'rgba(44, 53, 49, 0.98)';
                navbar.style.backdropFilter = 'blur(25px)';
                navbar.style.borderBottom = '1px solid rgba(50, 184, 198, 0.3)';
            } else {
                navbar.style.background = 'rgba(44, 53, 49, 0.95)';
                navbar.style.backdropFilter = 'blur(20px)';
                navbar.style.borderBottom = '1px solid rgba(50, 184, 198, 0.2)';
            }
        });
    }

    // Enhanced smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                const offsetTop = target.offsetTop - 70;
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });
                
                // Add temporary highlight effect
                target.style.transition = 'box-shadow 0.3s ease';
                target.style.boxShadow = '0 0 30px rgba(50, 184, 198, 0.3)';
                setTimeout(() => {
                    target.style.boxShadow = '';
                }, 1000);
            }
        });
    });

    // Parallax effect for hero section
    const heroSection = document.querySelector('.homepage-hero');
    if (heroSection) {
        window.addEventListener('scroll', () => {
            const scrolled = window.pageYOffset;
            const rate = scrolled * -0.3;
            heroSection.style.transform = `translateY(${rate}px)`;
        });
    }
}

// Navigation for all pages
function initNavigation() {
    // Mobile navigation toggle (if you add it later)
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');

    if (navToggle && navMenu) {
        navToggle.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            navToggle.classList.toggle('active');
        });
    }

    // Add active states to navigation links
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });

    // Add ripple effect to buttons
    const buttons = document.querySelectorAll('.homepage-btn, .btn');
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.width = ripple.style.height = size + 'px';
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';
            ripple.classList.add('ripple');
            
            this.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
}

// Enhanced utility functions for all pages
function initUtilities() {
    // Enhanced hover effects with Solarin colors
    const interactiveElements = document.querySelectorAll('.btn, .card, .homepage-feature-card, .homepage-step');
    
    interactiveElements.forEach(element => {
        element.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-3px)';
            if (this.classList.contains('homepage-feature-card')) {
                this.style.boxShadow = '0 10px 40px rgba(50, 184, 198, 0.3)';
            }
        });
        
        element.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            if (this.classList.contains('homepage-feature-card')) {
                this.style.boxShadow = '';
            }
        });
    });

    // Enhanced form handling with better feedback
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
            if (submitBtn) {
                const originalText = submitBtn.innerHTML || submitBtn.value;
                if (submitBtn.tagName === 'BUTTON') {
                    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
                    submitBtn.style.background = 'linear-gradient(135deg, #32B8C6, #116466)';
                } else {
                    submitBtn.value = 'Processing...';
                }
                submitBtn.disabled = true;
                
                // Re-enable after 5 seconds as fallback
                setTimeout(() => {
                    if (submitBtn.tagName === 'BUTTON') {
                        submitBtn.innerHTML = originalText;
                        submitBtn.style.background = '';
                    } else {
                        submitBtn.value = originalText;
                    }
                    submitBtn.disabled = false;
                }, 5000);
            }
        });
    });

    // Auto-focus first input in forms with better UX
    const firstInput = document.querySelector('input[type="text"], input[type="email"], textarea');
    if (firstInput && !firstInput.hasAttribute('readonly')) {
        // Delay focus to avoid issues with page load
        setTimeout(() => firstInput.focus(), 100);
    }

    // Add loading shimmer effect
    const shimmerElements = document.querySelectorAll('[data-shimmer]');
    shimmerElements.forEach(element => {
        element.style.background = 'linear-gradient(90deg, transparent, rgba(50, 184, 198, 0.1), transparent)';
        element.style.backgroundSize = '200% 100%';
        element.style.animation = 'shimmer 2s infinite';
    });
}

// Enhanced counter Animation with Solarin styling
function animateCounter(element, target, duration = 2000) {
    let start = 0;
    const increment = target / (duration / 16);
    
    const timer = setInterval(() => {
        start += increment;
        if (start >= target) {
            element.textContent = target;
            element.style.color = '#32B8C6'; // Solarin teal
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(start);
        }
    }, 16);
}

// Enhanced counter observer with stagger effect
const counterObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry, index) => {
        if (entry.isIntersecting) {
            const targetValue = parseInt(entry.target.getAttribute('data-target'));
            if (targetValue && !isNaN(targetValue)) {
                setTimeout(() => {
                    animateCounter(entry.target, targetValue);
                }, index * 200); // Stagger animation
                counterObserver.unobserve(entry.target);
            }
        }
    });
}, { threshold: 0.5 });

// Observe counter elements
document.querySelectorAll('[data-target]').forEach(counter => {
    counterObserver.observe(counter);
});

// Global utility functions with Solarin theme
if (typeof window !== 'undefined') {
    window.SecretGuardian = {
        // Enhanced notification with Solarin colors
        showNotification: function(message, type = 'info') {
            // Remove existing notifications
            const existingNotifications = document.querySelectorAll('.notification');
            existingNotifications.forEach(notif => notif.remove());

            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            
            const icon = type === 'success' ? 'check-circle' : 
                        type === 'error' ? 'exclamation-circle' : 
                        type === 'warning' ? 'exclamation-triangle' : 'info-circle';
            
            notification.innerHTML = `
                <i class="fas fa-${icon}"></i>
                <span>${message}</span>
                <button class="notification-close">&times;</button>
            `;
            
            document.body.appendChild(notification);
            
            // Enhanced animation
            notification.style.transform = 'translateX(100%)';
            notification.style.opacity = '0';
            setTimeout(() => {
                notification.style.transform = 'translateX(0)';
                notification.style.opacity = '1';
            }, 10);
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.style.transform = 'translateX(100%)';
                    notification.style.opacity = '0';
                    setTimeout(() => notification.remove(), 300);
                }
            }, 5000);
            
            // Close button
            notification.querySelector('.notification-close').addEventListener('click', () => {
                notification.style.transform = 'translateX(100%)';
                notification.style.opacity = '0';
                setTimeout(() => notification.remove(), 300);
            });
        },

        // Enhanced date formatting
        formatDate: function(date) {
            return new Date(date).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        },

        // Enhanced clipboard with feedback
        copyToClipboard: function(text) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    this.showNotification('✨ Copied to clipboard!', 'success');
                }).catch(() => {
                    this.showNotification('❌ Failed to copy to clipboard', 'error');
                });
            } else {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                textArea.style.position = 'fixed';
                textArea.style.opacity = '0';
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand('copy');
                    this.showNotification('✨ Copied to clipboard!', 'success');
                } catch (err) {
                    this.showNotification('❌ Failed to copy to clipboard', 'error');
                }
                document.body.removeChild(textArea);
            }
        },

        // Always return Solarin theme
        getTheme: function() {
            return 'solarin';
        },

        // Enhanced tooltips with Solarin styling
        initTooltips: function() {
            const tooltipElements = document.querySelectorAll('[data-tooltip]');
            tooltipElements.forEach(element => {
                element.addEventListener('mouseenter', function() {
                    const tooltip = document.createElement('div');
                    tooltip.className = 'tooltip solarin-tooltip';
                    tooltip.textContent = this.getAttribute('data-tooltip');
                    document.body.appendChild(tooltip);
                    
                    const rect = this.getBoundingClientRect();
                    tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
                    tooltip.style.top = rect.top - tooltip.offsetHeight - 12 + 'px';
                    
                    // Animate in
                    tooltip.style.opacity = '0';
                    tooltip.style.transform = 'translateY(10px)';
                    setTimeout(() => {
                        tooltip.style.opacity = '1';
                        tooltip.style.transform = 'translateY(0)';
                    }, 10);
                });
                
                element.addEventListener('mouseleave', function() {
                    const tooltips = document.querySelectorAll('.tooltip');
                    tooltips.forEach(tooltip => {
                        tooltip.style.opacity = '0';
                        tooltip.style.transform = 'translateY(10px)';
                        setTimeout(() => tooltip.remove(), 150);
                    });
                });
            });
        }
    };
}

// Enhanced CSS for notifications and tooltips with Solarin theme
const utilityCSS = `
@keyframes shimmer {
    0% { background-position: -200% 0; }
    100% { background-position: 200% 0; }
}

@keyframes ripple {
    to {
        transform: scale(4);
        opacity: 0;
    }
}

.ripple {
    position: absolute;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.3);
    transform: scale(0);
    animation: ripple 0.6s linear;
    pointer-events: none;
}

.notification {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 10000;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px 20px;
    background: rgba(17, 100, 102, 0.95);
    border: 1px solid rgba(50, 184, 198, 0.3);
    border-radius: 12px;
    backdrop-filter: blur(15px);
    color: #F5F5F5;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    max-width: 400px;
    font-size: 14px;
    transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}

.notification-success {
    border-left: 4px solid #32B8C6;
    background: rgba(50, 184, 198, 0.15);
}

.notification-error {
    border-left: 4px solid #FF6B6B;
    background: rgba(255, 107, 107, 0.15);
}

.notification-warning {
    border-left: 4px solid #FFCB9A;
    background: rgba(255, 203, 154, 0.15);
}

.notification-info {
    border-left: 4px solid #32B8C6;
    background: rgba(50, 184, 198, 0.15);
}

.notification-close {
    background: none;
    border: none;
    color: #8A9BA8;
    font-size: 18px;
    cursor: pointer;
    padding: 0;
    margin-left: auto;
    transition: color 0.2s ease;
    border-radius: 50%;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.notification-close:hover {
    color: #F5F5F5;
    background: rgba(255, 255, 255, 0.1);
}

.tooltip, .solarin-tooltip {
    position: absolute;
    z-index: 10001;
    padding: 10px 14px;
    background: rgba(17, 100, 102, 0.95);
    color: #F5F5F5;
    font-size: 12px;
    border-radius: 8px;
    pointer-events: none;
    white-space: nowrap;
    border: 1px solid rgba(50, 184, 198, 0.3);
    backdrop-filter: blur(10px);
    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3);
    transition: all 0.15s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}

.tooltip::after, .solarin-tooltip::after {
    content: '';
    position: absolute;
    top: 100%;
    left: 50%;
    transform: translateX(-50%);
    border: 6px solid transparent;
    border-top-color: rgba(17, 100, 102, 0.95);
}

/* Enhanced loading states */
.loading {
    opacity: 0.7;
    pointer-events: none;
    position: relative;
}

.loading::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(90deg, transparent, rgba(50, 184, 198, 0.1), transparent);
    background-size: 200% 100%;
    animation: shimmer 1.5s infinite;
}

/* Smooth page transitions */
body {
    transition: opacity 0.3s ease;
}

body.page-transition {
    opacity: 0;
}

/* Enhanced scrollbar for webkit browsers */
::-webkit-scrollbar {
    width: 8px;
}

::-webkit-scrollbar-track {
    background: rgba(44, 53, 49, 0.3);
}

::-webkit-scrollbar-thumb {
    background: linear-gradient(180deg, #32B8C6, #116466);
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: linear-gradient(180deg, #D9B08C, #FFCB9A);
}
`;

// Inject enhanced utility CSS
const style = document.createElement('style');
style.textContent = utilityCSS;
document.head.appendChild(style);

// Enhanced loading states with Solarin theme
window.addEventListener('beforeunload', () => {
    document.body.classList.add('page-transition');
});

window.addEventListener('load', () => {
    document.body.classList.remove('page-transition');
    document.body.classList.add('loaded');
    
    // Add entrance animation to page elements
    const elements = document.querySelectorAll('.homepage-hero-content, .homepage-section-header');
    elements.forEach((element, index) => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(30px)';
        setTimeout(() => {
            element.style.transition = 'all 0.8s cubic-bezier(0.175, 0.885, 0.32, 1.275)';
            element.style.opacity = '1';
            element.style.transform = 'translateY(0)';
        }, index * 200);
    });
});
