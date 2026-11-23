# AXION - Document & File Locker

> **Military-Grade File Encryption & Decryption Suite**  
> Silicon Rush Hackathon Project • Fully Eligible & Optimized for Vercel Deployment

![AXION Logo](public/logo2.png)

---

## 🚀 Overview

**AXION** is an encryption suite designed to secure sensitive documents, including:
- **Text Files** (`.txt`, `.md`, `.json`, `.csv`)
- **Word Documents** (`.docx`, `.doc`)
- **PowerPoint Presentations** (`.pptx`, `.ppt`)
- **PDF Documents** (`.pdf`)
- **Arbitrary Data & Files**
- **Text Vault** (Raw string encryption/decryption in-browser)

All encrypted files use the standardized **`.docenc`** container format, backed by **AES-256-CBC** and **PBKDF2 HMAC-SHA256** with **100,000 iterations**.

---

## 🌐 Dual Architecture: Web + Serverless

1. **Client-Side WebCrypto (Zero-Knowledge & Infinite Scale)**:
   - Cryptographic operations run in the browser using the native, hardware-accelerated `crypto.subtle` API.
   - **Zero Knowledge**: Passwords and document contents **never** touch external servers.
   - **No Payload Limits**: Large files are encrypted locally in memory without hitting Vercel's 4.5 MB serverless payload limits.
   - **100% Binary Interoperability**: Generates and decrypts `.docenc` files that match the Python desktop application (`medium.py`, `#merge org.py`) byte-for-byte.

2. **Vercel Serverless Functions (`api/index.py`)**:
   - Python-powered serverless endpoints running `cryptography>=41.0.0` for automated API integrations:
     - `GET /api/health` - Health check & crypto configuration
     - `POST /api/encrypt` - Base64 JSON encryption API
     - `POST /api/decrypt` - Base64 JSON decryption API

---

## 📦 Project Structure

```text
.
├── api/
│   └── index.py            # Vercel Python Serverless Handler
├── public/                 # Static Assets & Web Application
│   ├── index.html          # Web UI Interface
│   ├── style.css           # Dark Obsidian UI Styling
│   ├── crypto.js           # WebCrypto Encryption/Decryption Engine
│   ├── app.js              # UI controller, drag & drop, strength meter
│   ├── logo2.png           # Brand Logo
│   └── favicon.ico         # Favicon
├── index.html              # Root index for direct Vercel routing
├── vercel.json             # Vercel routing, rewrites & security headers
├── requirements.txt        # Python serverless dependencies
├── package.json            # Node project configuration & scripts
├── .vercelignore           # Excludes heavy local build binaries (dist, build, exe)
└── .gitignore              # Git ignore rules
```

---

## ⚡ Deployment to Vercel

### Option 1: Deploy with Vercel CLI (Recommended)

1. Open a terminal in this directory:
   ```bash
   cd "path/to/Silicon rush"
   ```

2. Run Vercel CLI (no prior global install required):
   ```bash
   npx vercel
   ```

3. Follow the interactive prompts:
   - **Set up and deploy?** `yes`
   - **Which scope?** (Select your Vercel account)
   - **Link to existing project?** `no`
   - **What's your project's name?** `axion-locker` (or press Enter)
   - **In which directory is your code located?** `./` (press Enter)
   - **Want to modify these settings?** `no`

4. For production deployment:
   ```bash
   npx vercel --prod
   ```

---

### Option 2: Deploy via GitHub / GitLab / Bitbucket

1. Initialize git and commit:
   ```bash
   git init
   git add .
   git commit -m "feat: AXION web app ready for Vercel"
   ```

2. Push to your GitHub repository.
3. In [Vercel Dashboard](https://vercel.com/new):
   - Click **Add New...** -> **Project**
   - Import your GitHub repository.
   - Framework Preset: **Other**
   - Click **Deploy**!

---

## 🔒 Cryptographic Specifications

- **Cipher**: AES-256 in CBC mode (Cipher Block Chaining)
- **Key Derivation**: PBKDF2 with HMAC-SHA256
- **Iterations**: 100,000 rounds
- **Salt**: 16 bytes (Cryptographically secure pseudo-random number generator)
- **IV (Initialization Vector)**: 16 bytes (CSPRNG)
- **Padding**: PKCS#7 standard padding
- **Container Format (`.docenc`)**:
  ```text
  +-------------------+------------------+-----------------------------+
  |  Salt (16 Bytes)  |  IV (16 Bytes)   |  Ciphertext (Padded Bytes)  |
  +-------------------+------------------+-----------------------------+
  ```

---

## 🧪 Local Testing

You can run a local test server using standard Node:

```bash
npm run dev
# or
npx serve public
```
Open `http://localhost:3000` in your browser.
