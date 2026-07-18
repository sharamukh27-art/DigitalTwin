# 📸 Assets Guide - What You Need

This guide explains exactly what images and files to add to make your portfolio complete.

---

## 📁 Assets Folder Structure

```
assets/
├── images/
│   ├── profile.jpg              ← Your profile photo
│   ├── emotion-detection.jpg    ← Project 1 screenshot
│   └── student-result.jpg       ← Project 2 screenshot
│
├── icons/
│   └── favicon.png              ← Browser tab icon (optional)
│
└── resume/
    └── Sharanya_Mukherjee_Resume.pdf  ← Your resume
```

---

## 1️⃣ Profile Photo

### 📸 What to Use:
- Clear photo of yourself
- Professional but approachable
- Good lighting
- Solid or blurred background
- Smiling or confident expression

### ✅ Specifications:
- **Filename**: `profile.jpg` or `profile.png`
- **Location**: `assets/images/profile.jpg`
- **Size**: 400x400 pixels (square)
- **File Size**: < 200KB
- **Format**: JPG or PNG

### 📷 How to Get It:
1. Use existing photo from phone/camera
2. Crop to square
3. Resize to 400x400px using:
   - Online: [tinypng.com](https://tinypng.com)
   - Mac: Preview → Tools → Adjust Size
   - Windows: Paint → Resize
   - Or any photo editor

### 💡 Don't Have One?
Use a placeholder for now:
- Canva: Create 400x400 design with your initials
- UI Avatars: `https://ui-avatars.com/api/?name=Your+Name&size=400`
- Update with real photo later

---

## 2️⃣ Project Screenshots

### 🖼️ Emotion Detection Project

**Filename**: `emotion-detection.jpg`
**Location**: `assets/images/emotion-detection.jpg`

#### What to Capture:
- Main interface of your project
- Live detection in action
- Result display screen
- Dashboard view
- Best representation of the project

#### Specifications:
- **Size**: 1200x800 pixels (3:2 ratio)
- **File Size**: < 500KB
- **Format**: JPG
- **Quality**: High, but compressed

#### How to Take Screenshot:
**Mac**:
- `Cmd + Shift + 4` → Drag to select area
- `Cmd + Shift + 3` → Full screen

**Windows**:
- `Win + Shift + S` → Snipping tool
- `PrtScn` → Full screen

**Tips**:
- Run your project
- Capture best view
- Include interesting output
- Make sure UI is clear
- No sensitive data visible

---

### 🖼️ Student Result Management Project

**Filename**: `student-result.jpg`
**Location**: `assets/images/student-result.jpg`

Same specifications as above.

#### What to Capture:
- Main dashboard
- Results display
- Data visualization
- Key features visible
- Clean, professional look

---

## 3️⃣ Resume PDF

### 📄 What You Need:

**Filename**: `Sharanya_Mukherjee_Resume.pdf`
**Location**: `assets/resume/Sharanya_Mukherjee_Resume.pdf`

### ✅ Specifications:
- **Format**: PDF only (not Word)
- **File Size**: < 2MB
- **Pages**: 1-2 pages
- **Filename**: Use your actual name

### 📝 Resume Content Should Include:
- Your name and contact
- Education
- Skills
- Projects (including these!)
- Experience (if any)
- **Portfolio URL** (add after deploying!)

### 💡 How to Create PDF:

**From Word/Google Docs**:
- File → Download → PDF
- Or File → Save As → PDF

**Don't Have Resume?**
Create one using:
- [resume.io](https://resume.io) (templates)
- Google Docs templates
- Canva resume templates
- LaTeX (for tech look)

### 🎯 Pro Tips:
- Update resume with portfolio URL after deployment
- Include GitHub profile
- List these two projects
- Keep it to 1 page if possible
- Use clean, readable format
- No typos!

---

## 4️⃣ Favicon (Optional)

### 🎨 Browser Tab Icon

**Filename**: `favicon.png` or `favicon.ico`
**Location**: `assets/icons/favicon.png`

### Specifications:
- **Size**: 32x32 or 64x64 pixels
- **Format**: PNG or ICO
- **Design**: Your initials or logo

### How to Create:
1. Use [favicon.io](https://favicon.io)
2. Upload image or use text
3. Download generated favicon
4. Place in `assets/icons/`

### Add to HTML:
```html
<link rel="icon" type="image/png" href="assets/icons/favicon.png">
```

---

## 5️⃣ Future Project Screenshots

As you add more projects, follow this pattern:

```
assets/images/
├── project-name-1.jpg
├── project-name-2.jpg
├── project-name-3.jpg
```

### Guidelines:
- Descriptive filenames
- Consistent size (1200x800)
- Under 500KB each
- JPG format
- Clear, professional captures

---

## 📊 Image Optimization

### Why Optimize?
- Faster loading
- Better SEO
- Smooth animations
- Better user experience

### How to Optimize:

**Online Tools** (Easiest):
1. [TinyPNG](https://tinypng.com) - Best for PNG/JPG
2. [Squoosh](https://squoosh.app) - Google's tool
3. [Compressor.io](https://compressor.io)

**Process**:
1. Upload your image
2. Download compressed version
3. Compare quality
4. Use compressed version

### Target File Sizes:
- Profile photo: < 200KB
- Project screenshots: < 500KB
- Resume PDF: < 2MB
- Favicon: < 50KB

---

## ✅ Asset Checklist

Before deploying, verify:

- [ ] Profile photo added (400x400px, < 200KB)
- [ ] Emotion detection screenshot (1200x800px, < 500KB)
- [ ] Student result screenshot (1200x800px, < 500KB)
- [ ] Resume PDF added (< 2MB)
- [ ] All images optimized
- [ ] Filenames match exactly
- [ ] Images in correct folders
- [ ] Test all images load locally

---

## 🎨 Design Tips for Screenshots

### Make Your Projects Look Good:

1. **Clean Interface**
   - Remove clutter
   - Hide unnecessary elements
   - Show best features

2. **Good Lighting**
   - Bright, clear display
   - No glare or reflections
   - Readable text

3. **Interesting Content**
   - Show project in action
   - Include results/output
   - Demonstrate functionality

4. **Professional Look**
   - Clean background
   - Organized layout
   - No debug messages

5. **Resolution**
   - High-quality capture
   - Not blurry or pixelated
   - Clear text and UI

---

## 🔧 Troubleshooting

### Image Not Showing?
- Check filename matches exactly (case-sensitive)
- Verify file is in correct folder
- Ensure file extension is correct (.jpg not .jpeg)
- Clear browser cache (Ctrl/Cmd + Shift + R)

### Image Too Large?
- Use TinyPNG to compress
- Resize to recommended dimensions
- Convert PNG to JPG if appropriate

### Resume Not Downloading?
- Ensure filename is exactly: `Sharanya_Mukherjee_Resume.pdf`
- Check file is in `assets/resume/` folder
- Verify it's a PDF (not Word doc)

### Wrong Image Displaying?
- Clear browser cache
- Check filename in HTML matches asset
- Verify file was uploaded/moved correctly

---

## 📱 Testing Your Assets

After adding all assets:

1. **Open Website Locally**
   ```bash
   open index.html
   ```

2. **Check Each Image**
   - Profile photo appears in hero
   - Project screenshots load
   - Hover effects work
   - Images are clear

3. **Test Resume**
   - Click resume buttons
   - Verify download works
   - Open downloaded PDF
   - Check it's readable

4. **Mobile Test**
   - Open on phone
   - Check images scale properly
   - Verify everything loads

---

## 🎯 Quick Reference

| Asset | Location | Size | Format |
|-------|----------|------|--------|
| Profile Photo | `assets/images/profile.jpg` | 400x400px | JPG/PNG |
| Project 1 | `assets/images/emotion-detection.jpg` | 1200x800px | JPG |
| Project 2 | `assets/images/student-result.jpg` | 1200x800px | JPG |
| Resume | `assets/resume/Sharanya_Mukherjee_Resume.pdf` | Any | PDF |
| Favicon | `assets/icons/favicon.png` | 32x32px | PNG |

---

## 💡 Pro Tips

1. **Take Multiple Screenshots**
   - Capture different views
   - Choose the best one
   - Keep backups

2. **Compress Everything**
   - Always optimize images
   - Faster site = better UX
   - Better SEO ranking

3. **Use Consistent Style**
   - Similar screenshot styles
   - Cohesive look
   - Professional appearance

4. **Update Regularly**
   - Better screenshots over time
   - Update resume quarterly
   - Refresh profile photo yearly

5. **Backup Assets**
   - Keep originals
   - Save high-res versions
   - Store in cloud

---

## 🎉 Ready?

Once you have all assets:

1. Add them to correct folders
2. Test website locally
3. Verify everything works
4. Proceed to deployment!

---

**Now you know exactly what assets you need and how to add them!** 📸✨

Next: Follow [DEPLOY.md](DEPLOY.md) to make it live! 🚀
