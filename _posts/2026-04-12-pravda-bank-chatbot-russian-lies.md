---
layout: post
title: "PRAVDA - Your Bank's Chatbot Is Repeating Kremlin Lies"
date: 2026-04-12
toc: true
series: "Social Engineering & Manipulation"
series_part: 1
tags: []
---

You've never visited a Russian propaganda site. You've never clicked a suspicious link. But every time you chat with your bank's AI assistant, you might be getting served Kremlin talking points — and neither you nor the bank has any idea.

---

# The weight of truth

We all use AI today. On ChatGPT, Gemini or DeepSeek; but also in our cars, banking apps, or even microwaves. Yet we rarely stop to ask: what does it consider true?

AI makes mistakes — anyone who has spent a night wrestling with a hallucinating model knows the struggle. But the deeper question isn't about accuracy. It's about how AI *values* truth.

From a young age, we learn to distrust liars and conmen. We quickly grasp that a fact doesn't carry the same weight depending on its origin, context, and consistency. We learn to fact-check, cross-reference, and challenge. In short, we learn to judge the worth of information.

A Large Language Model has none of that. It has no understanding of the facts it processes — it doesn't even perceive them as facts. It cannot pass any judgement on their value. What it can do is count. And that's where repetition comes into play.

---

# How to train your AI

Large Language Models (LLMs) — a subset of Artificial Intelligence — are most commonly encountered as chatbots. They generate text by predicting the most probable next word given a sequence, much like the autocomplete on your phone's keyboard, but operating at a vastly larger scale.

They learn this by ingesting enormous *quantities* of data, almost entirely text, in the form of training datasets. These used to be carefully hand-crafted by research teams. Today, they are effectively the entire internet — assembled by giving the training pipeline near-unfiltered access to search engines and every website they can reach.

## How artists paved the way for Russian propaganda to spread

Flooding AI with the raw internet quickly created problems. Artists and creators began raising copyright claims, arguing that their work was being scraped and used for training without consent. At the same time, some websites started deliberately engineering their content to attract AI crawlers and get indexed by them.

Both pressures led to the emergence of a set of techniques now broadly called AI Search Engine Optimization (AI SEO). Two tools sit at the centre of this: `robots.txt` — a decades-old standard that tells crawlers which pages to skip — and the more recent `agents.txt`, a proposed convention designed specifically to signal AI scrapers (still emerging and not yet universally adopted). Paired with content strategies tuned to how LLMs rank and retrieve information, these files give anyone with a web server a lever to influence what AI learns.

Which raises an uncomfortable question: what exactly does an AI consider worth knowing?

---

# What matters to an AI

Web crawling and indexing have been researched and refined for decades. As a result, much of how AI scrapers evaluate pages borrows heavily from the playbook that *Google*, *Bing* or *Yandex* developed. The key difference: search engines maintain a live, continuously updated index, while an LLM trains on a static snapshot of the web taken at a point in time. Once training ends, that snapshot is frozen.

## Web structure

One of the most important signals — for both search engines and AI crawlers — is page structure. Proper use of semantic HTML tags (`<h1>`, `<h2>`, `<p>`) establishes an information hierarchy that crawlers can parse. Alternative text on images, canonical URLs, and schema markup all contribute to how content gets categorized and weighted.

Some systems even allow web owners to integrate SEO metadata directly into their pages. Here, for example, is the SEO block generated automatically for my latest post.

```html
<!-- Begin Jekyll SEO tag v2.8.0 -->
<title>The web inside FiveM: From browser to full remote control | Pyth3rEx</title>
<meta name="generator" content="Jekyll v4.4.1" />
<meta property="og:title" content="The web inside FiveM: From browser to full remote control" />
<meta name="author" content="Pyth3rEx" />
<meta property="og:locale" content="en_US" />
<meta name="description" content="A player typed something into a text field. Now an attacker is reading files on another player’s computer. Your server didn’t get hacked. You were never the target. But you are the one who let it happen." />
<meta property="og:description" content="A player typed something into a text field. Now an attacker is reading files on another player’s computer. Your server didn’t get hacked. You were never the target. But you are the one who let it happen." />
<link rel="canonical" href="https://pyth3rex.github.io/blog/2026/03/26/fivem-web-surface/" />
<meta property="og:url" content="https://pyth3rex.github.io/blog/2026/03/26/fivem-web-surface/" />
<meta property="og:site_name" content="Pyth3rEx" />
<meta property="og:type" content="article" />
<meta property="article:published_time" content="2026-03-26T00:00:00+00:00" />
<meta name="twitter:card" content="summary" />
<meta property="twitter:title" content="The web inside FiveM: From browser to full remote control" />
<script type="application/ld+json">
    {"@context":"https://schema.org","@type":"BlogPosting","author":{"@type":"Person","name":"Pyth3rEx"},"dateModified":"2026-03-26T00:00:00+00:00","datePublished":"2026-03-26T00:00:00+00:00","description":"A player typed something into a text field. Now an attacker is reading files on another player’s computer. Your server didn’t get hacked. You were never the target. But you are the one who let it happen.","headline":"The web inside FiveM: From browser to full remote control","mainEntityOfPage":{"@type":"WebPage","@id":"https://pyth3rex.github.io/blog/2026/03/26/fivem-web-surface/"},"url":"https://pyth3rex.github.io/blog/2026/03/26/fivem-web-surface/"}</script>
<!-- End Jekyll SEO tag -->
```

## Conversational Queries

AI models are particularly receptive to conversational text — content that directly answers questions using the full 5Ws: who, what, where, when, and why. This matters most during the fine-tuning phase, where models are shaped to respond helpfully to user prompts. Text that maps naturally onto a question-and-answer format gets absorbed with minimal friction, feeding almost directly into how the model learns to respond. A site that phrases its content as answers to common questions isn't just optimizing for search engines — it's optimizing for AI.

## Multimodal searching

Multimodal content — text paired with images, video, or audio covering the same subject — reinforces the same semantic content through multiple channels. A training pipeline will collect the text on a page alongside its associated media. These aren't necessarily processed together, but each one registers as another data point pointing at the same concept, compounding its weight in the model's understanding.

## Trust & Authority

E-E-A-T (Experience, Expertise, Authoritativeness, and Trustworthiness) is a framework from Google's Search Quality Rater Guidelines, used by human evaluators to assess content quality and inform ranking decisions. It is not a direct algorithmic signal, but it shapes what gets rated as high-quality — and therefore what ends up heavily indexed. Similarly to multimodal reinforcement, the underlying mechanism is repetition and cross-referencing.

### Experience (E)

- Is this source established in the domain?
- Is it a brand-new website?
- Fresh WHOIS records?
- No post history?

### Expertise (E)

- Is the author qualified?
- Does the author display certifications, experience, or deep subject-matter knowledge?
- Does the author claim published works in the field?

### Authoritativeness (A)

- Is the author reputable amongst peers?
- Is the author's work referenced across the field?
- Is the content cited or reused by other high-ranking E-E-A-T sources?

### Trustworthiness (T)

- Are claims backed by citations or primary sources?
- Is authorship transparent?
- Is the site served over HTTPS?
- Is the content kept up to date?

---

# The Truth Network