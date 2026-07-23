"""fettle web UI (``fettle web``) — optional, needs the ``web`` extra (nicegui).

Nothing in this package is imported by the core CLI unless the user actually runs
``fettle web``; the core stays pure-stdlib (``dependencies = []``) so the remote
zipapp keeps working under any bare ``python3``. Only modules under ``fettle/web/``
may import nicegui — a test enforces that.
"""
