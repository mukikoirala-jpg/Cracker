# GharHash iPhone-only

This version runs entirely in Safari using HTML/CSS/JavaScript. No Python, Windows PC, server, or Hashcat installation is required.

## Features
- Modern mobile dashboard
- Automatic MD5/SHA-1/SHA-256/SHA-512 detection
- Local wordlist file import
- Dictionary and bounded mask candidate generation
- Live progress
- Stop control
- Local history using localStorage
- PWA manifest for Home Screen installation

## Important limitation
iOS browser security and platform restrictions mean this is not a replacement for native Hashcat/GPU cracking. It is intentionally a bounded browser-based lab/CTF tool.

## Install on iPhone
The files need to be served by a static HTTPS host for the most reliable PWA installation. Open the hosted page in Safari, tap Share → Add to Home Screen.

For a quick local test, any static file server can serve this folder, but the browser still needs a reachable URL.

Use only hashes and wordlists you own or are authorized to test.
