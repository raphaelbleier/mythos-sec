"""Active vulnerability checks. Each check is a function taking an HttpClient
and an injection point (or a URL) and yielding Finding objects. Checks are
safe and bounded: they probe for a class of bug, they do not weaponize it."""
