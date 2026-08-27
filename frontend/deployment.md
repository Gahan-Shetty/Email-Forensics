# 🚀 Deployment Guide — Email Forensic Analyzer (EFA) Frontend

> **Kage — ThreeUI Kyoto Night Experience**
> A static HTML/CSS/JS frontend for email header forensics with Three.js 3D visuals, Leaflet GeoIP mapping, and SHA-256 custody chain verification.

---

## 📁 Project Structure

```
frontend/
├── index.html              # Main entry point (single-page app)
├── css/
│   └── styles.css          # Kage design system stylesheet
├── js/
│   ├── api.js              # API module & offline demo fixtures
│   ├── app.js              # Core application logic & event binding
│   ├── render.js           # Dynamic results panel renderer
│   ├── map.js              # Leaflet GeoIP map visualization
│   ├── three-scene.js      # Three.js 3D Kyoto temple background
│   ├── bubble-cursor.js    # Interactive bubble cursor effect
│   └── button-physics.js   # Jelly/water button physics animation
├── fixtures/
│   └── sample_response.json  # Contract schema fixture
├── scripts/
│   └── run_frontend.sh     # Local dev server script
└── deployment.md           # ← This file
```

---

## 🖥️ Option 1: Local Development Server

### Using Python (Recommended)

```bash
# Navigate to the frontend folder
cd frontend

# Python 3
python -m http.server 5500

# OR Python 2
python -m SimpleHTTPServer 5500
```

Open **http://127.0.0.1:5500** in your browser.

### Using Node.js (npx)

```bash
cd frontend
npx -y serve -l 5500
```

### Using VS Code Live Server

1. Install the **Live Server** extension in VS Code.
2. Right-click `index.html` → **Open with Live Server**.

---

## 🌐 Option 2: GitHub Pages (Free Hosting)

GitHub Pages is the easiest way to deploy this static frontend for free.

### Steps

1. **Push the `frontend/` folder to GitHub** (already done — it's at [Gahan-Shetty/Email-Forensics](https://github.com/Gahan-Shetty/Email-Forensics)).

2. **Go to the repository Settings**:
   - Navigate to **Settings → Pages** (left sidebar).

3. **Configure the source**:
   - Under **Build and deployment**, set:
     - **Source**: `Deploy from a branch`
     - **Branch**: `main`
     - **Folder**: `/frontend` *(if the frontend is in a subfolder)* or `/ (root)` *(if it's at root level)*

4. **Save** and wait 1–2 minutes for deployment.

5. Your site will be live at:
   ```
   https://gahan-shetty.github.io/Email-Forensics/
   ```

> **⚠️ Note**: If the `frontend/` folder is a subfolder of the repo, GitHub Pages serves from root by default. You may need to adjust the base path or use a GitHub Actions workflow (see below).

### Using GitHub Actions (for subfolder deployment)

Create `.github/workflows/deploy.yml` in the repo root:

```yaml
name: Deploy Frontend to GitHub Pages

on:
  push:
    branches: [main]

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - uses: actions/checkout@v4

      - name: Setup Pages
        uses: actions/configure-pages@v4

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: './frontend'

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

---

## ▲ Option 3: Vercel (Recommended for Production)

[Vercel](https://vercel.com) offers free hosting with automatic HTTPS, CDN, and Git-based deploys.

### Steps

1. **Sign up** at [vercel.com](https://vercel.com) with your GitHub account.

2. **Import the repository**:
   - Click **"Add New" → "Project"**
   - Select **Gahan-Shetty/Email-Forensics**

3. **Configure build settings**:
   | Setting              | Value       |
   |----------------------|-------------|
   | Framework Preset     | Other       |
   | Root Directory       | `frontend`  |
   | Build Command        | *(leave empty — no build step needed)* |
   | Output Directory     | `.`         |

4. Click **Deploy**.

5. Your site will be live at:
   ```
   https://email-forensics.vercel.app
   ```

---

## 🔷 Option 4: Netlify

[Netlify](https://netlify.com) also offers free static hosting with CDN and continuous deployment.

### Steps

1. **Sign up** at [netlify.com](https://netlify.com) with GitHub.

2. **Add new site → Import from Git**:
   - Connect to **Gahan-Shetty/Email-Forensics**

3. **Configure build settings**:
   | Setting         | Value       |
   |-----------------|-------------|
   | Base directory   | `frontend`  |
   | Build command    | *(leave empty)* |
   | Publish directory| `frontend`  |

4. Click **Deploy site**.

### Drag & Drop (Quick Deploy)

Alternatively, just drag the entire `frontend/` folder onto [app.netlify.com/drop](https://app.netlify.com/drop) for instant deployment.

---

## 🖧 Option 5: Traditional Web Server (Apache/Nginx)

Since this is a static site (no build step), simply copy the `frontend/` folder contents to your web server's document root.

### Nginx

```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /var/www/email-forensics/frontend;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(css|js|json)$ {
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}
```

### Apache (.htaccess)

```apache
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.html [L]

# Cache static assets
<FilesMatch "\.(css|js|json)$">
    Header set Cache-Control "public, max-age=604800, immutable"
</FilesMatch>
```

---

## 🔌 Backend API Configuration

The frontend calls a backend API at the base URL defined in `js/api.js`:

```javascript
var API_BASE = "";  // defaults to same origin
```

### Connecting to a Backend

If the backend is hosted separately, update `API_BASE` in [api.js](js/api.js):

```javascript
var API_BASE = "https://your-backend-api.com";
```

### API Endpoints Used

| Endpoint          | Method | Description                        |
|-------------------|--------|------------------------------------|
| `/api/analyze`    | POST   | Submit raw email headers for analysis |
| `/health`         | GET    | Backend health check               |
| `/api/custody`    | GET    | Retrieve custody chain log         |

### Offline / Demo Mode

The frontend includes **built-in offline demo fixtures** in `api.js`, so it works without any backend. Toggle "Offline simulation mode" in the UI or click "Load Demo Response" to test locally without a server.

---

## 🔗 External Dependencies (CDN)

The following are loaded from CDN at runtime — **no npm install needed**:

| Library     | Version | CDN                                          | Purpose                    |
|-------------|---------|----------------------------------------------|----------------------------|
| Three.js    | r128    | cdnjs.cloudflare.com                         | 3D Kyoto temple background |
| Leaflet     | 1.9.4   | unpkg.com                                    | GeoIP map visualization    |
| JetBrains Mono | —   | fonts.googleapis.com                         | Kage signature typography  |

---

## ✅ Pre-Deployment Checklist

- [ ] Verify `API_BASE` in `js/api.js` points to the correct backend URL (or leave empty for same-origin)
- [ ] Test offline demo mode works without backend
- [ ] Confirm Three.js 3D scene loads correctly
- [ ] Confirm Leaflet map renders GeoIP markers
- [ ] Test all 5 sample scenarios from the dropdown
- [ ] Verify custody chain simulation works
- [ ] Test on mobile viewport (responsive layout)
- [ ] Confirm HTTPS is enabled on production host

---

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| Blank page / JS errors | Open browser DevTools (F12) → Console tab. Check for blocked CDN resources or CORS errors. |
| 3D scene not rendering | Ensure WebGL is supported in your browser. Try Chrome or Firefox. |
| Map tiles not loading | Check network connectivity. Leaflet tiles require internet access. |
| API calls failing | Verify `API_BASE` is correct. Check CORS headers on backend. Use offline mode for testing. |
| GitHub Pages 404 | Ensure the Pages source branch and folder are configured correctly in Settings → Pages. |

---

*Email Forensic Analyzer (EFA) · ThreeUI Kage Kyoto Experience · 2026*
