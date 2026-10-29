"""Cyber Security Paradox Detector.

Queries fast-updating and slow-updating threat-intel beacons for an IP and
scores how much they disagree. A high paradox score means the fast beacons
(live community pulses, sensor networks, botnet trackers) see a threat that the
slow beacons (curated blocklists, vendor reputation, weekly scan data) have not
caught up with yet.
"""

__version__ = "0.1.0"
