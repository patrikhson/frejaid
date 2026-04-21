package layout

import "fmt"

func head(title string) string {
	return fmt.Sprintf(`<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>%s — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>`, title)
}

func footer() string {
	return `<footer class="site-footer">
  <p>FrejaID Demo</p>
</footer>`
}

// Nav returns the site header for authenticated users.
func Nav(role string) string {
	adminLink := ""
	if role == "admin" {
		adminLink = `<span class="nav-sep">·</span><a href="/admin">Admin</a>`
	}
	return fmt.Sprintf(`<header class="site-header">
  <div class="site-header__inner">
    <a href="/" class="site-logo">FrejaID Demo</a>
    <nav class="site-nav">
      <a href="/settings/account">Account</a>
      <span class="nav-sep">·</span>
      <a href="/settings/passkeys">Passkeys</a>
      %s
      <span class="nav-sep">·</span>
      <form method="POST" action="/auth/logout" style="display:inline">
        <button type="submit" style="background:none;border:none;cursor:pointer;padding:0;color:inherit;font:inherit">Log out</button>
      </form>
    </nav>
  </div>
</header>`, adminLink)
}

// PageStart returns the opening HTML for an authenticated page.
func PageStart(title, role string, extraHead string) string {
	h := head(title)
	if extraHead != "" {
		h = fmt.Sprintf(`<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>%s — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
  %s
</head>`, title, extraHead)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
%s
<body>
%s
<main class="site-main">`, h, Nav(role))
}

// PageEnd returns the closing HTML for pages opened with PageStart.
func PageEnd() string {
	return footer() + "\n</body></html>"
}

// AdminPageStart returns the opening HTML for an admin page.
func AdminPageStart(title string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
%s
<body>
<header class="site-header wide">
  <div class="site-header__inner">
    <a href="/admin" class="site-logo">FrejaID Demo — Admin</a>
  </div>
</header>
<div class="admin-bar">
  <div class="admin-bar__inner">
    <a href="/admin">Dashboard</a>
    <a href="/admin/registrations">Registrations</a>
    <a href="/admin/users">Users</a>
    <a href="/">← Back to site</a>
  </div>
</div>
<main class="site-main wide">
<h2>%s</h2>
`, head(title+" — Admin"), title)
}

// AdminPageEnd returns the closing HTML for admin pages.
func AdminPageEnd() string {
	return footer() + "\n</body></html>"
}
