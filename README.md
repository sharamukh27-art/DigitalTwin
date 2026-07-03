# SharanyaVerse - Premium Portfolio

A **premium, futuristic portfolio** website inspired by Apple, Vercel, Linear, and Stripe. Designed to impress recruiters from top tech companies.

## ✨ Premium Features

- **🎨 Premium Design** - Apple-inspired minimalism with Vercel-style dark gradients
- **✨ Advanced Animations** - Typing effects, counters, particles, and smooth scroll reveals
- **🌌 Glassmorphism** - Frosted glass cards with backdrop blur
- **🎯 Interactive Elements** - Cursor glow, scroll progress, back-to-top, status badges
- **📊 Animated Statistics** - Real-time counters for projects, technologies, and commits
- **🚀 Project Showcase** - Dual-action overlay, status badges, and tech stack tags
- **💻 Skills Display** - Animated progress bars with icon-based cards
- **📱 Mobile Perfection** - Touch-optimized responsive design
- **⚡ Performance Optimized** - 60fps animations with Intersection Observer
- **🎭 Dynamic Hero** - Gradient blobs, floating particles, and typing animation

## 🛠️ Technologies Used

- **HTML5** - Semantic markup with accessibility
- **CSS3** - Grid, Flexbox, Custom Properties, Backdrop Filters, Gradients, Animations
- **JavaScript (ES6+)** - Intersection Observer API, RAF, DOM manipulation
- **Font Awesome 6** - Premium icons
- **Design Inspired By** - Apple, Vercel, Linear.app, Stripe

## 📁 Project Structure

```
SharanyaVerse/
│
├── index.html          # Main HTML file
├── style.css           # All styles and animations
├── script.js           # Interactive functionality
│
├── assets/
│   ├── images/         # Profile photo, project screenshots
│   ├── icons/          # Custom icons (if any)
│   └── resume/         # Your resume PDF
│
├── screenshots/        # Website screenshots for documentation
└── README.md          # This file
```

## 🚀 Getting Started

### Prerequisites

- A modern web browser (Chrome, Firefox, Safari, Edge)
- Basic understanding of HTML/CSS/JS (for customization)

### Installation

1. **Clone or download this repository**
   ```bash
   cd SharanyaVerse
   ```

2. **Add your assets**
   - Place your profile photo as `assets/images/profile.jpg`
   - Add project screenshots to `assets/images/`
   - Save your resume as `assets/resume/Sharanya_Mukherjee_Resume.pdf`

3. **Customize content**
   - Open `index.html` and update:
     - Your name, bio, and descriptions
     - Project details and GitHub links
     - Contact information (email, GitHub, LinkedIn)
   
4. **Open in browser**
   - Simply open `index.html` in your browser
   - Or use a local server:
     ```bash
     python -m http.server 8000
     # or
     npx serve
     ```

## 🎨 Customization Guide

### Colors

Edit CSS variables in `style.css`:

```css
:root {
    --primary-color: #3498db;      /* Main blue */
    --secondary-color: #2980b9;    /* Darker blue */
    --accent-color: #00d4ff;       /* Bright cyan */
    --bg-dark: #0a0a0f;            /* Background */
    --text-primary: #ffffff;       /* Main text */
}
```

### Content

1. **Personal Info** - Edit text in HTML sections
2. **Projects** - Update project cards with your work
3. **Skills** - Add/remove skill cards as needed
4. **Social Links** - Replace placeholder URLs with yours

### Adding New Projects

Copy and paste this structure in the projects section:

```html
<div class="project-card">
    <div class="project-image">
        <img src="assets/images/your-project.jpg" alt="Project Name">
        <div class="project-overlay">
            <a href="github-link" class="project-link" target="_blank">
                <i class="fab fa-github"></i>
            </a>
        </div>
    </div>
    <div class="project-content">
        <h3>Your Project Name</h3>
        <p>Project description goes here.</p>
        <div class="project-tags">
            <span class="tag">Tech 1</span>
            <span class="tag">Tech 2</span>
        </div>
        <a href="github-link" class="btn btn-small" target="_blank">View on GitHub</a>
    </div>
</div>
```

## 🌐 Deployment

### Deploy on Vercel (Recommended)

1. Push your code to GitHub
2. Go to [vercel.com](https://vercel.com)
3. Import your repository
4. Deploy with one click!

### Deploy on GitHub Pages

1. Push to GitHub
2. Go to repository Settings → Pages
3. Select main branch as source
4. Your site will be live at `https://yourusername.github.io/SharanyaVerse`

### Deploy on Netlify

1. Drag and drop the folder to [netlify.com](https://netlify.com)
2. Or connect your GitHub repository
3. Site deploys automatically!

## 📝 To-Do / Future Enhancements

- [ ] Add actual project screenshots
- [ ] Update GitHub repository links
- [ ] Create and add resume PDF
- [ ] Add LinkedIn profile URL
- [ ] Add contact form with backend
- [ ] Implement blog section
- [ ] Add project detail pages
- [ ] Integrate analytics (Google Analytics)
- [ ] Add dark/light mode toggle
- [ ] Create custom 404 page

## 🐛 Known Issues

- Profile image uses placeholder until you add your own
- Project links are placeholders until updated
- Resume download requires PDF in correct location

## 📄 Browser Support

- ✅ Chrome/Edge 90+ (Recommended)
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Mobile browsers (iOS Safari, Chrome Mobile)
- ⚠️ Glassmorphism effects require modern browser support

## 📧 Contact

Feel free to reach out if you have questions or suggestions!

- **Email**: your.email@example.com
- **GitHub**: [@yourusername](https://github.com/yourusername)
- **LinkedIn**: [Your Name](https://linkedin.com/in/yourusername)

## 📜 License

This project is open source and available under the [MIT License](LICENSE).

---

**Built with 💙 by Sharanya Mukherjee**

*Last updated: July 2026*
