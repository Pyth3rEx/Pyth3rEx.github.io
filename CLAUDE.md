# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Jekyll-based personal blog ([Pyth3rEx.github.io](https://Pyth3rEx.github.io)) with a dark monospace aesthetic.
It uses the Minima theme with extensive SCSS customizations.
Deployment is automated via GitHub Actions on push to `main`.

## Commands

### Local Development

```bash
bundle exec jekyll serve --livereload   # serve with live reload at http://localhost:4000
bundle exec jekyll build                # build to _site/
```

### Linting

```bash
npm run lint:md        # markdownlint on all .md files
npm run lint:scss      # stylelint on _sass/ and assets/css/
npm run lint:yaml      # yamllint on all .yml files
npx commitlint --edit  # validate last commit message
```

Check `package.json` for the full list of npm scripts.

### Testing

```bash
bundle exec htmlproofer _site/ --disable-external   # HTML proof after build
```

The CI pipeline (`ci.yml`) runs all lints plus Jekyll build + htmlproofer on every push/PR.

## Commit Convention

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/).
Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `revert`.
Header max: 100 chars.

## Architecture

### Content

- **`_posts/`** — Blog posts in Markdown, named `YYYY-MM-DD-title.md`. Front matter requires
  `layout: post`, `title`, and `date`. Posts are served at `/blog/:year/:month/:day/:title/`.
- **`blog/index.html`** — Lists all posts; shows `// no posts yet` when empty.
- **`index.html`** — Root redirects to `/blog/` via meta refresh + JS fallback.

### Layouts

- **`_layouts/default.html`** — Base layout with header nav (links to `/blog` and `/about`),
  sticky header, footer with dynamic copyright year, and Jekyll SEO tag integration.
- **`_layouts/post.html`** — Extends `default`, adds post article structure with previous/next navigation.

### Styling

- **`_sass/custom.scss`** — All custom styles. Dark theme: `#0f0f0f` bg, `#d4d4d4` text,
  `#cc2200` red-orange accent. Font: JetBrains Mono 15px via Google Fonts. Max content width: 720px.
- **`assets/css/style.scss`** — Entry point; imports Minima then `custom.scss`.

The SCSS overrides Minima's defaults entirely — the theme provides structure
but all visual styling comes from `custom.scss`.

### CI/CD

- **`.github/workflows/ci.yml`** — Runs on all branches: commitlint, markdownlint, stylelint,
  yamllint, then Jekyll build + htmlproofer.
- **`.github/workflows/jekyll.yml`** — Deploys to GitHub Pages on push to `main` only.
