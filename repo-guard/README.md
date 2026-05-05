# RepoGuard Frontend

Static frontend for the RepoGuard local dashboard. It connects to the Python scanning API served by `dashboard.py`.

## Run Locally

From the project root, start the integrated frontend/API server:

```powershell
python dashboard.py --serve
```

Then open:

```text
http://127.0.0.1:8765
```

The interface sends repository sources to the `/api/scan` endpoint. The backend accepts demo repository names, local folders, or public GitHub repository URLs.

Useful demo inputs:

- `secure-demo-repo`
- `vulnerable-demo-repo`

## File Structure

- `index.html` - Search, loading, result, attack simulation, and detailed report views.
- `css/variables.css` - Color, typography, shadow, radius, and transition tokens.
- `css/base.css` - Reset rules and page typography.
- `css/layout.css` - Main application layout and view structure.
- `css/components.css` - Forms, buttons, mascot scenes, result cards, report panels, findings, and actions.
- `css/responsive.css` - Tablet and mobile layout rules.
- `js/app.js` - API integration, scan flow, result rendering, report rendering, and attack simulation UI logic.
- `assets/` - Icons and presentation mascot images used by the interface.
