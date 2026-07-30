"""SmartHunt — a GUI-driven reconnaissance and bug-hunting toolkit.

The package is split into:

* :mod:`smarthunt.tools`     — external tool detection and safe subprocess execution
* :mod:`smarthunt.wordlists` — small embedded wordlists used by the pure-Python fallbacks
* :mod:`smarthunt.modules`   — the individual recon stages (subdomains, dns, http, ports, tech, content, vulns)
* :mod:`smarthunt.engine`    — the :class:`Scanner` that wires the stages into a pipeline
* :mod:`smarthunt.gui`       — the Tkinter desktop front-end
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
