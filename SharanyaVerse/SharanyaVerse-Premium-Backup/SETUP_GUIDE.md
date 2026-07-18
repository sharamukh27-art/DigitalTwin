# 🚀 SharanyaVerse Setup Guide

This guide will help you personalize and launch your portfolio website step by step.

## ✅ Step 1: Gather Your Assets

Before customizing, collect these files:

### Required:
- [ ] **Profile Photo** - Clear, professional photo (400x400px recommended)
- [ ] **Resume PDF** - Your latest resume
- [ ] **Project Screenshots** - Images of your completed projects

### Optional but Recommended:
- [ ] **Logo** - If you want a custom logo instead of text
- [ ] **Favicon** - Small icon for browser tab

---

## 📝 Step 2: Update Personal Information

### A. Hero Section (index.html, line ~35)

Replace:
```html
<p class="greeting">Hi, I'm</p>
<h1 class="hero-title">Sharanya Mukherjee</h1>
<p class="hero-subtitle">Computer Science Engineering Student</p>
<p class="hero-description">Building AI & Software Solutions</p>
```

With your actual info!

### B. About Section (index.html, line ~60)

Update the paragraphs with your story:
- Your background
- Your college/university
- Your interests and goals
- What makes you unique

### C. Contact Information (index.html, line ~180)

Replace these placeholders:
- `your.email@example.com` → Your actual email
- `@yourusername` → Your GitHub username
- LinkedIn URL → Your LinkedIn profile

---

## 🖼️ Step 3: Add Your Images

### Profile Photo
1. Name your photo `profile.jpg` (or .png)
2. Place it in `assets/images/`
3. Size: 400x400px works best
4. Format: JPG or PNG

### Project Screenshots
1. Take clear screenshots of your projects
2. Recommended size: 600x400px
3. Save as:
   - `emotion-detection.jpg`
   - `student-result.jpg`
4. Place in `assets/images/`

### Resume
1. Save your resume as `Sharanya_Mukherjee_Resume.pdf`
2. Place in `assets/resume/`

---

## 🚀 Step 4: Update Project Details

Find the projects section in `index.html` (around line ~145).

For each project card, update:

### Project 1: Emotion Detection
```html
<h3>Emotion Detection / Face Recognition</h3>
<p>Your actual project description here</p>
<div class="project-tags">
    <span class="tag">Python</span>
    <span class="tag">OpenCV</span>
    <!-- Add your actual tech stack -->
</div>
<a href="YOUR_GITHUB_LINK" class="btn btn-small">View on GitHub</a>
```

### Project 2: Student Result Management
Do the same for your second project.

---

## 🔗 Step 5: Add GitHub Repository Links

Replace all instances of `#` in project links with your actual GitHub URLs:

1. In `index.html` - project card links
2. In `script.js` (line ~165) - update the `projectLinks` object:

```javascript
const projectLinks = {
    'Emotion Detection / Face Recognition': 'https://github.com/YOUR_USERNAME/emotion-detection',
    'Student Result Management System': 'https://github.com/YOUR_USERNAME/student-result-system'
};
```

---

## 🎨 Step 6: Customize Colors (Optional)

If you want different colors, edit `style.css` (line ~2):

```css
:root {
    --primary-color: #3498db;      /* Change this for main color */
    --secondary-color: #2980b9;    /* Darker shade */
    --accent-color: #00d4ff;       /* Bright highlights */
}
```

Try these color schemes:

**Purple Theme:**
```css
--primary-color: #9b59b6;
--secondary-color: #8e44ad;
--accent-color: #e74c3c;
```

**Green Theme:**
```css
--primary-color: #27ae60;
--secondary-color: #229954;
--accent-color: #2ecc71;
```

**Red Theme:**
```css
--primary-color: #e74c3c;
--secondary-color: #c0392b;
--accent-color: #ff6b6b;
```

---

## 🧪 Step 7: Test Your Website

### Test Locally:

1. **Method 1: Direct Open**
   - Double-click `index.html`
   - Opens in default browser

2. **Method 2: Local Server** (Recommended)
   ```bash
   # Python
   python -m http.server 8000
   
   # Node.js
   npx serve
   
   # VS Code
   # Install "Live Server" extension, right-click index.html → "Open with Live Server"
   ```

### What to Test:

- [ ] All links work (especially GitHub and resume)
- [ ] Images load correctly
- [ ] Mobile responsiveness (use browser DevTools)
- [ ] Smooth scrolling between sections
- [ ] Hamburger menu works on mobile
- [ ] Resume downloads correctly

---

## 📤 Step 8: Deploy Your Website

### Option 1: GitHub Pages (Free)

1. Create a new repository called `SharanyaVerse`
2. Push your code:
   ```bash
   git init
   git add .
   git commit -m "Initial portfolio setup"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/SharanyaVerse.git
   git push -u origin main
   ```
3. Go to repository Settings → Pages
4. Select `main` branch → Save
5. Your site: `https://YOUR_USERNAME.github.io/SharanyaVerse`

### Option 2: Vercel (Recommended - Fastest)

1. Push code to GitHub first
2. Go to [vercel.com](https://vercel.com)
3. Sign in with GitHub
4. Click "New Project"
5. Import your repository
6. Click "Deploy"
7. Done! You get a URL like `sharanyaverse.vercel.app`

### Option 3: Netlify

1. Go to [netlify.com](https://netlify.com)
2. Drag and drop the `SharanyaVerse` folder
3. Or connect GitHub repository
4. Your site is live!

---

## 🎯 Step 9: Share Your Portfolio

Once deployed, add the link to:

- [ ] Your GitHub profile README
- [ ] Your resume
- [ ] LinkedIn profile
- [ ] Email signature
- [ ] Job applications

---

## ⚡ Quick Checklist

Before going live:

- [ ] Personal info updated
- [ ] Profile photo added
- [ ] Resume PDF uploaded
- [ ] Project screenshots added
- [ ] All GitHub links work
- [ ] Email and social links correct
- [ ] Tested on mobile
- [ ] All images load
- [ ] No broken links
- [ ] Resume downloads correctly

---

## 🆘 Troubleshooting

### Images not showing?
- Check file names match exactly (case-sensitive!)
- Ensure images are in correct folder
- Try clearing browser cache

### Resume not downloading?
- Verify PDF is in `assets/resume/`
- Check filename matches exactly
- Ensure file extension is `.pdf`

### Styling looks broken?
- Check if `style.css` is in same folder as `index.html`
- Look for typos in file names
- Open browser console (F12) for errors

### Mobile menu not working?
- Ensure `script.js` is loaded
- Check browser console for JavaScript errors

---

## 🎓 Next Steps (Phase 2 Ideas)

Once Phase 1 is complete, you can add:

- Contact form with EmailJS
- Blog section
- Project detail pages
- Testimonials section
- Dark/light mode toggle
- More projects as you build them
- Certifications section
- Awards/achievements

---

## 💡 Pro Tips

1. **SEO**: Add meta descriptions in `<head>` for better Google ranking
2. **Analytics**: Add Google Analytics to track visitors
3. **Performance**: Compress images before uploading
4. **Updates**: Keep adding projects as you complete them
5. **Backups**: Always keep a backup before major changes

---

## 📞 Need Help?

If you get stuck:
1. Check browser console (F12) for errors
2. Validate HTML at [validator.w3.org](https://validator.w3.org)
3. Review the main README.md
4. Check that all file paths are correct

---

**You're all set! 🎉**

Once everything is working, you'll have a professional portfolio that you can be proud to share with recruiters and on your resume!

Good luck with your portfolio! 🚀
