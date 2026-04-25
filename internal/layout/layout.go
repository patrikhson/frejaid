// Package layout provides reusable HTML page wrappers for authenticated pages.
package layout

import "fmt"

func head(title, csrfToken string) string {
	return fmt.Sprintf(`<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="csrf-token" content="%s">
  <title>%s — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>`, csrfToken, title)
}

func footer() string {
	return `<footer class="site-footer">
  <p>FrejaID Demo</p>
</footer>`
}

// csrfScript auto-injects the CSRF token (from the meta tag) into every
// POST form on the page as a hidden field.  This means individual form
// templates do not need to include the token explicitly.
// JS fetch calls on authenticated pages should read the token from the meta
// tag and send it as the X-CSRF-Token request header.
const csrfScript = `<script>
(function() {
  var m = document.querySelector('meta[name="csrf-token"]');
  if (!m) return;
  var t = m.content;
  [].forEach.call(document.querySelectorAll('form'), function(f) {
    if ((f.method || '').toUpperCase() === 'POST') {
      var i = document.createElement('input');
      i.type = 'hidden'; i.name = 'csrf_token'; i.value = t;
      f.appendChild(i);
    }
  });
})();
</script>`

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
// csrfToken is embedded in a meta tag and auto-injected into all POST forms.
func PageStart(title, role, csrfToken string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
%s
<body>
%s
<main class="site-main">`, head(title, csrfToken), Nav(role))
}

// PageEnd returns the closing HTML for pages opened with PageStart.
func PageEnd() string {
	return fmt.Sprintf("%s\n%s\n</body></html>", footer(), csrfScript)
}

// AdminPageStart returns the opening HTML for an admin page.
func AdminPageStart(title, csrfToken string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
%s
<body>
<header class="site-header wide">
  <div class="site-header__inner">
    <a href="/" class="site-logo">FrejaID Demo — Admin</a>
  </div>
</header>
<div class="admin-bar">
  <div class="admin-bar__inner">
    <a href="/admin">Admin</a>
    <a href="/admin/registrations">Registrations</a>
    <a href="/admin/users">Users</a>
  </div>
</div>
<main class="site-main wide">
<h2>%s</h2>
`, head(title+" — Admin", csrfToken), title)
}

// AdminPageEnd returns the closing HTML for admin pages.
func AdminPageEnd() string {
	return fmt.Sprintf("%s\n%s\n</body></html>", footer(), csrfScript)
}
