package api

import (
	"html/template"
	"net/http"
)

// pageShell is the one frame for every HTML page mctl-api renders itself
// (mctl-api#654): the OAuth chooser and refusals and the identity-link
// pages. It carries the MCTL logo and the palette of the ZITADEL label
// policy (mctl-gitops zitadel-iac/iac/branding.tf), so a sign-in that
// passes through auth.mctl.ai keeps one look.
//
// Everything is inline: the pages are served with default-src 'none' and
// style-src 'unsafe-inline' only. The logo is inline SVG markup, which is
// part of the document, not a fetched image, so it needs no img-src. It is
// zitadel-iac/iac/branding-sidebar-{light,dark}.svg with the two baked
// colors replaced by the palette variables.
//
// A page adds only its "actions" template; title and lines are drawn here.
var pageShell = template.Must(template.New("shell").Parse(`{{define "page"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Title}} · MCTL</title>
<style>
:root{--primary:#b83d28;--bg:#f1ede4;--font:#15181d;--warn:#c23b3b;--card:#fff;--muted:#5c6068;--line:rgba(21,24,29,.12);--on-primary:#fff}
@media (prefers-color-scheme:dark){:root{--primary:#e25a3c;--bg:#0a0b0d;--font:#e6e7e9;--warn:#ff6b6b;--card:#15171b;--muted:#9a9ea6;--line:rgba(230,231,233,.14);--on-primary:#0a0b0d}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;background:var(--bg);color:var(--font);font:1rem/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.card{width:100%;max-width:27rem;background:var(--card);border:1px solid var(--line);border-radius:.75rem;padding:2rem 1.75rem}
.card.warn{border-top:.25rem solid var(--warn)}
.logo{display:block;width:110px;height:32px}
.logo path{stroke:var(--primary)}.logo circle{fill:var(--primary)}.logo text{fill:var(--font)}
h1{font-size:1.375rem;line-height:1.3;margin:1.5rem 0 .75rem}
p{margin:0 0 .75rem;overflow-wrap:anywhere}
.actions{display:flex;flex-direction:column;gap:.625rem;margin:1.5rem 0 0}
.actions a,.actions button{display:block;width:100%;padding:.75rem 1rem;border:1px solid var(--primary);border-radius:.5rem;background:var(--primary);color:var(--on-primary);font:inherit;font-weight:600;text-align:center;text-decoration:none;cursor:pointer}
.actions a.secondary{background:transparent;color:var(--primary)}
.actions a:focus-visible,.actions button:focus-visible{outline:2px solid var(--primary);outline-offset:2px}
.legacy{margin:1.25rem 0 0;text-align:center;font-size:.875rem}.legacy a{color:var(--muted)}
@media (max-width:30rem){body{align-items:flex-start;padding:1rem 1rem 2rem}.card{padding:1.5rem 1.25rem}}
</style></head>
<body><main class="card{{if .Warn}} warn{{end}}" data-shell="mctl">
<svg class="logo" role="img" aria-label="MCTL" xmlns="http://www.w3.org/2000/svg" width="110" height="32" viewBox="0 0 110 32" fill="none"><g transform="scale(0.0625)"><path d="M256 60L435.263 158V354L256 452L76.7372 354V158L256 60Z" stroke-width="48" stroke-linejoin="round"/><circle cx="256" cy="256" r="64"/></g><text x="40" y="22" font-family="system-ui, -apple-system, sans-serif" font-size="18" font-weight="700" letter-spacing="1.5">MCTL</text></svg>
<h1>{{.Title}}</h1>{{range .Lines}}<p>{{.}}</p>{{end}}
{{template "actions" .Page}}
</main></body></html>{{end}}`))

// shellPage is a page drawn in pageShell; actions is its "actions"
// template, executed with the page's own data.
func shellPage(name, actions string) *template.Template {
	return template.Must(template.Must(pageShell.Clone()).New(name).Parse(`{{define "actions"}}` + actions + `{{end}}`))
}

type shellData struct {
	Title string
	Lines []string
	// Warn marks a refusal or failure, any status from 400 up.
	Warn bool
	Page any
}

// renderShellPage writes page with the headers every shell page shares;
// csp differs only where a page posts a form.
func renderShellPage(w http.ResponseWriter, status int, csp string, page *template.Template, d shellData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", csp)
	w.WriteHeader(status)
	d.Warn = status >= http.StatusBadRequest
	_ = page.ExecuteTemplate(w, "page", d)
}
