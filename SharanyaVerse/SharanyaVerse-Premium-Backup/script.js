// ===== Premium Portfolio JavaScript - SharanyaVerse =====

// === Hamburger Menu ===
const hamburger = document.getElementById('hamburger');
const navMenu = document.getElementById('nav-menu');
const navLinks = document.querySelectorAll('.nav-link');

hamburger?.addEventListener('click', () => {
    navMenu.classList.toggle('active');
    hamburger.classList.toggle('active');
});

navLinks.forEach(link => {
    link.addEventListener('click', () => {
        navMenu.classList.remove('active');
        hamburger?.classList.remove('active');
    });
});

// === Navbar Scroll Effect ===
const navbar = document.getElementById('navbar');
let lastScroll = 0;

window.addEventListener('scroll', () => {
    const currentScroll = window.pageYOffset;
    
    if (currentScroll > 50) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
    
    lastScroll = currentScroll;
});

// === Smooth Scroll ===
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        const href = this.getAttribute('href');
        if (href === '#') return;
        
        e.preventDefault();
        const target = document.querySelector(href);
        
        if (target) {
            const offsetTop = target.offsetTop - 70;
            window.scrollTo({
                top: offsetTop,
                behavior: 'smooth'
            });
        }
    });
});

// === Typing Animation for Hero ===
const typingText = document.getElementById('typing-text');
if (typingText) {
    const roles = [
        'Software Developer',
        'Programmer',
        'AI Enthusiast',
        'Problem Solver'
    ];
    
    let roleIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let typingSpeed = 100;
    
    function type() {
        const currentRole = roles[roleIndex];
        
        if (isDeleting) {
            typingText.textContent = currentRole.substring(0, charIndex - 1);
            charIndex--;
            typingSpeed = 50;
        } else {
            typingText.textContent = currentRole.substring(0, charIndex + 1);
            charIndex++;
            typingSpeed = 100;
        }
        
        if (!isDeleting && charIndex === currentRole.length) {
            typingSpeed = 2000;
            isDeleting = true;
        } else if (isDeleting && charIndex === 0) {
            isDeleting = false;
            roleIndex = (roleIndex + 1) % roles.length;
            typingSpeed = 500;
        }
        
        setTimeout(type, typingSpeed);
    }
    
    setTimeout(type, 1000);
}

// === Counter Animation for Stats ===
function animateCounter(element) {
    const target = parseInt(element.getAttribute('data-target'));
    const duration = 2000;
    const step = target / (duration / 16);
    let current = 0;
    
    const timer = setInterval(() => {
        current += step;
        if (current >= target) {
            element.textContent = target + '+';
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 16);
}

// === Intersection Observer for Animations ===
const observerOptions = {
    threshold: 0.2,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
            
            // Animate counters
            if (entry.target.classList.contains('stat-number')) {
                animateCounter(entry.target);
            }
            
            // Animate skill bars
            if (entry.target.classList.contains('skill-card')) {
                const progress = entry.target.querySelector('.skill-progress');
                if (progress) {
                    const target = progress.getAttribute('data-progress');
                    setTimeout(() => {
                        progress.style.width = target + '%';
                    }, 200);
                }
            }
            
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

// Elements to observe
const animateElements = document.querySelectorAll(
    '.skill-card, .project-card, .contact-card, .highlight-card, .about-card, .stat-number'
);

animateElements.forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(30px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(el);
});

// === Active Nav Link on Scroll ===
const sections = document.querySelectorAll('section[id]');

function highlightNav() {
    const scrollY = window.pageYOffset;
    
    sections.forEach(section => {
        const sectionHeight = section.offsetHeight;
        const sectionTop = section.offsetTop - 100;
        const sectionId = section.getAttribute('id');
        const navLink = document.querySelector(`.nav-link[href="#${sectionId}"]`);
        
        if (scrollY > sectionTop && scrollY <= sectionTop + sectionHeight) {
            navLinks.forEach(link => link.classList.remove('active'));
            navLink?.classList.add('active');
        }
    });
}

window.addEventListener('scroll', highlightNav);

// === Project Links Configuration ===
const projectLinks = {
    'Emotion Detection System': {
        github: 'https://github.com/yourusername/emotion-detection',
        demo: '#'
    },
    'Student Result Management System': {
        github: 'https://github.com/yourusername/student-result-system',
        demo: '#'
    }
};

// Update project links
document.querySelectorAll('.project-card').forEach(card => {
    const title = card.querySelector('h3')?.textContent;
    if (title && projectLinks[title]) {
        const githubLinks = card.querySelectorAll('.fa-github').forEach(icon => {
            const link = icon.closest('a');
            if (link) link.href = projectLinks[title].github;
        });
        
        const demoLinks = card.querySelectorAll('.fa-external-link-alt').forEach(icon => {
            const link = icon.closest('a');
            if (link) link.href = projectLinks[title].demo;
        });
        
        const viewLink = card.querySelector('.btn-link');
        if (viewLink) viewLink.href = projectLinks[title].github;
    }
});

// === Particle Effect ===
function createParticles() {
    const hero = document.querySelector('.hero');
    if (!hero) return;
    
    const particleCount = 30;
    
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        
        const size = Math.random() * 3 + 1;
        const startX = Math.random() * 100;
        const startY = Math.random() * 100;
        const duration = Math.random() * 20 + 15;
        const delay = Math.random() * 5;
        
        particle.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            background: rgba(59, 130, 246, ${Math.random() * 0.5 + 0.2});
            border-radius: 50%;
            left: ${startX}%;
            top: ${startY}%;
            pointer-events: none;
            animation: particleFloat ${duration}s linear ${delay}s infinite;
        `;
        
        hero.appendChild(particle);
    }
    
    // Add particle animation
    if (!document.getElementById('particle-animation')) {
        const style = document.createElement('style');
        style.id = 'particle-animation';
        style.textContent = `
            @keyframes particleFloat {
                0% {
                    transform: translate(0, 0) scale(1);
                    opacity: 0;
                }
                10% {
                    opacity: 1;
                }
                90% {
                    opacity: 1;
                }
                100% {
                    transform: translate(${Math.random() * 200 - 100}px, -100vh) scale(0);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }
}

// === Back to Top Button ===
function createBackToTopButton() {
    const button = document.createElement('button');
    button.innerHTML = '<i class="fas fa-arrow-up"></i>';
    button.className = 'back-to-top';
    button.setAttribute('aria-label', 'Back to top');
    
    button.style.cssText = `
        position: fixed;
        bottom: 30px;
        right: 30px;
        width: 50px;
        height: 50px;
        background: linear-gradient(135deg, #3B82F6, #8B5CF6);
        color: white;
        border: none;
        border-radius: 12px;
        cursor: pointer;
        display: none;
        align-items: center;
        justify-content: center;
        font-size: 1.2rem;
        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4);
        transition: all 0.3s ease;
        z-index: 999;
        backdrop-filter: blur(10px);
    `;
    
    button.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
    
    button.addEventListener('mouseenter', () => {
        button.style.transform = 'translateY(-5px)';
        button.style.boxShadow = '0 8px 25px rgba(59, 130, 246, 0.6)';
    });
    
    button.addEventListener('mouseleave', () => {
        button.style.transform = 'translateY(0)';
        button.style.boxShadow = '0 4px 15px rgba(59, 130, 246, 0.4)';
    });
    
    document.body.appendChild(button);
    
    window.addEventListener('scroll', () => {
        if (window.pageYOffset > 500) {
            button.style.display = 'flex';
        } else {
            button.style.display = 'none';
        }
    });
}

// === Cursor Glow Effect (Desktop Only) ===
function createCursorGlow() {
    if (window.innerWidth < 768) return;
    
    const cursor = document.createElement('div');
    cursor.className = 'cursor-glow';
    cursor.style.cssText = `
        position: fixed;
        width: 300px;
        height: 300px;
        background: radial-gradient(circle, rgba(59, 130, 246, 0.08), transparent 70%);
        border-radius: 50%;
        pointer-events: none;
        z-index: 9999;
        transition: transform 0.3s ease;
        display: none;
    `;
    
    document.body.appendChild(cursor);
    
    let mouseX = 0;
    let mouseY = 0;
    let cursorX = 0;
    let cursorY = 0;
    
    document.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
        cursor.style.display = 'block';
    });
    
    function animateCursor() {
        cursorX += (mouseX - cursorX) * 0.1;
        cursorY += (mouseY - cursorY) * 0.1;
        
        cursor.style.left = cursorX - 150 + 'px';
        cursor.style.top = cursorY - 150 + 'px';
        
        requestAnimationFrame(animateCursor);
    }
    
    animateCursor();
}

// === Scroll Progress Indicator ===
function createScrollProgress() {
    const progress = document.createElement('div');
    progress.className = 'scroll-progress';
    progress.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 0%;
        height: 3px;
        background: linear-gradient(90deg, #3B82F6, #8B5CF6);
        z-index: 10000;
        transition: width 0.1s ease;
    `;
    
    document.body.appendChild(progress);
    
    window.addEventListener('scroll', () => {
        const windowHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
        const scrolled = (window.pageYOffset / windowHeight) * 100;
        progress.style.width = scrolled + '%';
    });
}

// === Console Welcome Message ===
console.log(
    '%c Welcome to SharanyaVerse! 🚀 ',
    'background: linear-gradient(135deg, #3B82F6, #8B5CF6); color: #fff; font-size: 24px; padding: 15px 30px; border-radius: 10px; font-weight: bold;'
);
console.log(
    '%c Premium Portfolio Built with HTML, CSS & JavaScript ',
    'color: #3B82F6; font-size: 14px; padding: 5px 0;'
);
console.log(
    '%c Software Developer • Programmer • AI Enthusiast ',
    'color: #8B5CF6; font-size: 12px; padding: 5px 0;'
);

// === Initialize Everything ===
window.addEventListener('load', () => {
    createParticles();
    createBackToTopButton();
    createCursorGlow();
    createScrollProgress();
    highlightNav();
    
    console.log('✅ SharanyaVerse initialized successfully!');
});

// === Prevent Empty Link Clicks ===
document.querySelectorAll('a[href="#"]').forEach(link => {
    link.addEventListener('click', (e) => {
        if (link.getAttribute('href') === '#' && !link.closest('.scroll-indicator')) {
            e.preventDefault();
        }
    });
});

// === Performance: Reduce animations on low-end devices ===
if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    document.querySelectorAll('*').forEach(el => {
        el.style.animation = 'none !important';
        el.style.transition = 'none !important';
    });
}

// === Future: Terminal Command Interface (Phase 2) ===
// Placeholder for interactive terminal feature
window.sharanyaTerminal = {
    commands: {
        help: () => console.log('Available commands: about, skills, projects, contact'),
        about: () => console.log('Software Developer & AI Enthusiast'),
        skills: () => console.log('Python, C, C++, JavaScript, HTML, CSS, Git'),
        projects: () => console.log('Emotion Detection, Student Result Management'),
        contact: () => console.log('Check the contact section!')
    }
};

// === Export for external use ===
window.SharanyaVerse = {
    version: '1.0.0',
    theme: 'premium-futuristic',
    init: () => console.log('SharanyaVerse loaded')
};
