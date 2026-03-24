# Pyth3rEx.github.io

Personal blog built with Jekyll. Dark theme, monospace, minimal.

## Local development

```bash
# Install dependencies (first time)
bundle install

# Serve locally with live reload
bundle exec jekyll serve --livereload

# Visit http://localhost:4000 → auto-redirects to /blog
```

Requires Ruby ≥ 3.0 and Bundler (`gem install bundler`).

## Writing a post

Create a file in `_posts/` named `YYYY-MM-DD-title-slug.md`:

```markdown
---
layout: post
title: "Post Title"
date: 2026-01-01
---

Post content here. Markdown supported.
```

The post will be available at `/blog/YYYY/MM/DD/title-slug/`.

## Deploy

Push to `main` — the GitHub Actions workflow (`.github/workflows/jekyll.yml`) builds and deploys automatically.

**One-time setup:** In the repo settings → Pages → Source → select **GitHub Actions**.

## Structure

```
_layouts/       Layout overrides (default.html, post.html)
_sass/          Custom SCSS (dark theme)
assets/css/     Stylesheet entry point
_posts/         Blog posts (YYYY-MM-DD-title.md)
blog/           Blog listing page
```
