<p align="center">
  <img src="static/koffan-logo.webp" alt="Koffan Logo" width="400">
</p>

<h1 align="center">Koffan</h1>

<p align="center">
  <strong>Free shopping assistant</strong><br>
  A fast and simple app for managing your shopping list together
</p>

<p align="center">
  <a href="https://railway.app/new/template?template=https://github.com/PanSalut/Koffan"><img src="https://railway.app/button.svg" alt="Deploy on Railway" height="32"></a>
  &nbsp;
  <a href="https://render.com/deploy?repo=https://github.com/PanSalut/Koffan"><img src="https://render.com/images/deploy-to-render-button.svg" alt="Deploy to Render" height="32"></a>
  &nbsp;
  <a href="https://cloud.digitalocean.com/apps/new?repo=https://github.com/PanSalut/Koffan/tree/main"><img src="https://www.deploytodo.com/do-btn-blue.svg" alt="Deploy to DigitalOcean" height="32"></a>
  &nbsp;
  <a href="https://heroku.com/deploy?template=https://github.com/PanSalut/Koffan"><img src="https://www.herokucdn.com/deploy/button.svg" alt="Deploy to Heroku" height="32"></a>
</p>

---

## Screenshots

<p align="center">
  <img src="screenshots/hero.png" alt="Koffan" width="700">
</p>

---

## What does "Koffan" mean?

Pronounced **KOF-fan** (rhymes with "coffin" but with an "a" at the end). The name comes from the Polish word *"kochanie"* (meaning "darling" or "sweetheart"), which evolved into a playful nickname. It's a long story, but let's just say the name stuck! :D

## What is Koffan?

Koffan is a lightweight web application for managing shopping lists, designed for couples and families. It allows real-time synchronization between multiple devices, so everyone knows what to buy and what's already in the cart.

The app works in any browser on both mobile and desktop. Just one password to log in - no complicated registration required.

## Why did I build this?

I needed an app that would let me and my wife create a shopping list together and do grocery shopping quickly and efficiently. I tested various solutions, but none of them were simple and fast enough.

I built the first version in **Next.js**, but it turned out to be very resource-heavy. I have a lot of other things running on my server, so I decided to optimize. I rewrote the app in **Go** and now it uses only **~2.5 MB RAM** instead of hundreds of megabytes!

## Features

- **Ultra-lightweight** - ~16 MB on disk, ~2.5 MB RAM
- **Multiple lists** - Create separate lists for different stores or purposes, with custom icons
- **PWA** - Install on your phone like a native app
- **Offline mode** - Add, edit, check/uncheck products without internet (auto-sync when back online)
- **Auto-completion** - Fuzzy search suggestions from your history, remembers sections
- Organize products into sections (e.g., Dairy, Vegetables, Cleaning)
- Mark products as purchased
- Mark products as "uncertain" (can't find it in the store)
- Real-time synchronization (WebSocket)
- Responsive interface (mobile-first)
- **Dark mode** - Automatic theme based on system preferences
- Multi-language support (PL, EN, DE, ES, FR, PT, UK, NO, LT, EL, SK, SV, RU)
- Simple login system
- Rate limiting protection against brute-force attacks
- **REST API** - Programmatic access for integrations and migrations ([docs](https://github.com/PanSalut/Koffan/wiki/REST-API))
- **Outbound webhooks** - Signed item events for automation tools such as n8n, Node-RED, and Zapier ([docs](https://github.com/PanSalut/Koffan/wiki/Webhooks))

## Tech Stack

- **Backend:** Go 1.21 + Fiber
- **Frontend:** HTMX + Alpine.js + Tailwind CSS
- **Database:** SQLite

## Local Setup (without Docker)

You can run Koffan directly on your machine using Go. This works on any system (macOS, Linux, Windows).

### 1. Install Go

**macOS (Homebrew):**
```bash
brew install go
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install golang-go
```

**Windows:**
Download from [go.dev/dl](https://go.dev/dl/)

### 2. Clone and Run

```bash
git clone https://github.com/PanSalut/Koffan.git
cd Koffan
go run main.go
```

App available at http://localhost:3000

Default password: `shopping123`

To set a custom password:
```bash
APP_PASSWORD=yourpassword go run main.go
```

## Arch Linux (AUR)

Arch Linux users can install Koffan from the [AUR](https://aur.archlinux.org/packages/koffan) using an AUR helper:

```bash
yay -S koffan
```

> The AUR package is community-maintained by [@SergeantBiggs](https://github.com/SergeantBiggs), not by the Koffan project.

## Docker

> **Upgrading from 2.9.x or earlier?** The default container port changed from `80` to `8080` in 2.10.0 so the image can run as a non-root user. If you are upgrading, update your port mappings and any reverse proxy upstreams accordingly:
>
> - `docker run -p 80:80` → `docker run -p 80:8080`
> - `docker run -p 3000:80` → `docker run -p 3000:8080`
> - Reverse proxies (nginx / Caddy / Traefik): point the upstream to the container's port `8080`
> - If you previously overrode `PORT` via env to work around the privileged port, you can drop that override
>
> Coolify and other auto-discovery setups that read the image's `EXPOSE` will pick up the new port on redeploy without any manual change.

### Quick Start (recommended)

```bash
docker run -d -p 3000:8080 -e APP_PASSWORD=yourpassword -v koffan-data:/data ghcr.io/pansalut/koffan:latest
```

App available at http://localhost:3000

### Build from source

```bash
docker-compose up -d
# App available at http://localhost:8080
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Set to `production` for secure cookies |
| `APP_PASSWORD` | `shopping123` | Login password |
| `DISABLE_AUTH` | `false` | Set to `true` to disable authentication (for reverse proxy setups) |
| `PORT` | `8080` (Docker) / `3000` (local) | Server port |
| `DB_PATH` | `./shopping.db` | Database file path |
| `DEFAULT_LANG` | `en` | Default UI language (pl, en, de, es, fr, pt, uk, no, lt, el, sk, ru) |
| `LOGIN_MAX_ATTEMPTS` | `5` | Max login attempts before lockout |
| `LOGIN_WINDOW_MINUTES` | `15` | Time window for counting attempts |
| `LOGIN_LOCKOUT_MINUTES` | `30` | Lockout duration after exceeding limit |
| `API_TOKEN` | *(disabled)* | Enable REST API with this token ([docs](https://github.com/PanSalut/Koffan/wiki/REST-API)) |
| `WEBHOOK_URL` | *(disabled)* | HTTP or HTTPS endpoint for outbound item events |
| `WEBHOOK_SECRET` | *(none)* | Secret used to sign webhook payloads with HMAC-SHA256 |
| `WEBHOOK_EVENTS` | *(all item events)* | Comma-separated filter: `item.created`, `item.updated`, `item.completed`, `item.deleted` |
| `DISABLE_PASSWORD_AUTH` | `false` | Hide password login once at least one OAuth provider below is configured (ignored, with a warning, if none are) |
| `OAUTH_REDIRECT_BASE_URL` | *(derived from request)* | Public base URL used to build OAuth callback URLs, e.g. `https://koffan.example.com`. Recommended in production |
| `OAUTH_GENERIC_ISSUER_URL` | *(disabled)* | Enables a generic OIDC sign-in button. Issuer URL of any standards-compliant OIDC provider (discovery is fetched from `{issuer}/.well-known/openid-configuration`) |
| `OAUTH_GENERIC_CLIENT_ID` | *(disabled)* | Client ID for the generic OIDC provider |
| `OAUTH_GENERIC_CLIENT_SECRET` | *(disabled)* | Client secret for the generic OIDC provider |
| `OAUTH_GENERIC_SCOPES` | `openid profile email` | Space-separated scopes requested from the generic OIDC provider |
| `OAUTH_GENERIC_BUTTON_LABEL` | `Sign in with SSO` | Label shown on the generic provider's sign-in button |
| `OAUTH_GOOGLE_CLIENT_ID` | *(disabled)* | Enables "Sign in with Google". Client ID from Google Cloud Console |
| `OAUTH_GOOGLE_CLIENT_SECRET` | *(disabled)* | Client secret from Google Cloud Console |
| `OAUTH_APPLE_CLIENT_ID` | *(disabled)* | Enables "Sign in with Apple". Your Apple Services ID |
| `OAUTH_APPLE_CLIENT_SECRET` | *(disabled)* | Pre-generated Apple client-secret JWT (signed with your key/Team ID/Key ID out-of-band; Koffan does not generate or rotate it - regenerate before it expires, up to every 6 months) |
| `OAUTH_FACEBOOK_APP_ID` | *(disabled)* | Enables "Sign in with Facebook". App ID from Facebook Developer |
| `OAUTH_FACEBOOK_APP_SECRET` | *(disabled)* | App secret from Facebook Developer |

### Outbound Webhooks

Set `WEBHOOK_URL` to receive signed, asynchronous item events. Koffan supports event filtering, HMAC-SHA256 signatures, and durable SQLite-backed retries that survive restarts.

```bash
WEBHOOK_URL=https://automation.example.com/webhook/koffan \
WEBHOOK_SECRET=replace-with-a-random-secret \
WEBHOOK_EVENTS=item.created,item.completed,item.deleted \
go run .
```

See the [Webhook documentation](https://github.com/PanSalut/Koffan/wiki/Webhooks) for events, payloads, signature verification, retry behavior, and integration guidance.

### OAuth Login

Koffan can authenticate users via Google, Apple, Facebook, or a generic OIDC provider (any standards-compliant identity provider, e.g. Authelia, Keycloak, Authentik, PocketID), in addition to the default shared password. Set the env vars for whichever provider(s) you want - each one activates independently as soon as its required vars are set. There is no per-user permission model yet: any account that signs in, by password or OAuth, can do anything.

```bash
OAUTH_REDIRECT_BASE_URL=https://koffan.example.com \
OAUTH_GENERIC_ISSUER_URL=https://idp.example.com \
OAUTH_GENERIC_CLIENT_ID=koffan \
OAUTH_GENERIC_CLIENT_SECRET=replace-with-your-client-secret \
OAUTH_GENERIC_BUTTON_LABEL="Sign in with SSO" \
go run .
```

Register the callback URL with your provider as `{OAUTH_REDIRECT_BASE_URL}/auth/{provider}/callback`, e.g. `https://koffan.example.com/auth/generic/callback` (or `/auth/google/callback`, `/auth/apple/callback`, `/auth/facebook/callback`).

If someone signs in via two different providers using the same email address, both sign-ins resolve to the same Koffan account. Once at least one OAuth provider is working, set `DISABLE_PASSWORD_AUTH=true` to hide the password form entirely.

## Deploy to Your Server

### Docker

```bash
git clone https://github.com/PanSalut/Koffan.git
cd Koffan
docker build -t koffan .
docker run -d -p 80:8080 -e APP_PASSWORD=your-password -v koffan-data:/data koffan
```

### Coolify

1. Add new resource → **Docker Compose** → Select your Git repository or use `https://github.com/PanSalut/Koffan`
2. Set domain in **Domains** section
3. Enable **Connect to Predefined Network** in Advanced settings
4. Add environment variable `APP_PASSWORD` with your password
5. Deploy

### Persistent Storage

Data is stored in `/data/shopping.db`. The volume ensures your data persists across deployments.

## Documentation

For more information, check the **[Wiki](https://github.com/PanSalut/Koffan/wiki)**:

- [REST API](https://github.com/PanSalut/Koffan/wiki/REST-API) - Programmatic access, migrations, integrations
- [Webhooks](https://github.com/PanSalut/Koffan/wiki/Webhooks) - Outbound item events for automation and notifications
- [Multiple Instances](https://github.com/PanSalut/Koffan/wiki/Multiple-Instances) - Running separate instances for different households

## Feature Requests

Have an idea? Check [open feature requests](https://github.com/PanSalut/Koffan/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement) and vote with 👍 on the ones you want most.

Want to suggest something new? [Create an issue](https://github.com/PanSalut/Koffan/issues/new).

## Sponsors

I love and admire the open source philosophy. That's why I created Koffan - to give back to the community that has given me so much over the years.

If you find this project useful and want to support my work (completely optional!), you can become a sponsor:

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-pink?style=for-the-badge)](https://github.com/sponsors/PanSalut)

### Thank You

I'm incredibly grateful to these amazing people for supporting Koffan:

- [@chip-well](https://github.com/chip-well)
- [@Pffeffi](https://github.com/Pffeffi)
- [@nathan-synfo](https://github.com/nathan-synfo)
- [@van-nutno](https://github.com/van-nutno)
- [@kazoob](https://github.com/kazoob)
- [@monkyOfTheSCC](https://github.com/monkyOfTheSCC)

## License

MIT License with [Commons Clause](https://commonsclause.com/).

You are free to use, modify, and share this software for any purpose, including commercial use within your organization. However, you may not sell the software or offer it as a paid service.
