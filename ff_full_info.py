"""
ff_full_info.py
================
Single-file Free Fire UID information gatherer.

Merges what the multiple folders/files in this workspace expose:
    - 03_Repos/FreeFire-Api/Api/Account.py     (oauth + MajorLogin)
    - 03_Repos/FreeFire-Api/Api/InGame.py      (PersonalShow / Stats / Search)
    - 03_Repos/FreeFire-Api/Configuration/*    (AES key/iv, release version, region accounts)
    - 03_Repos/FreeFire-Api/Proto/compiled/*   (compiled protobufs)
    - ff_unified_info_gatherer.py / ff_master_info_gatherer.py (formatting ideas)

Usage:
    python ff_full_info.py
    -> Enter Free Fire UID: 1234567890
    -> (Optional) Region [IND]: IND

It will print and save a JSON report containing:
    * Basic profile (nickname, level, exp, region, banner, head pic, last login,
      account creation, title, account type, badge count, liked count, ...)
    * Avatar / profile skin (avatarid, equipped clothes/skins, profile skin endtime,
      weapon-skin shower list)
    * Pet info (id, name, level, skin, skills)
    * Clan / Guild info (id, name, level, members, captain, honor)
    * Battle Royale rank + Clash Squad rank, peak ranks, points
    * Prime privilege detail (Prime level, privilege id list, monthly/annual points)
    * Spark / "Evo" info (state, level, exp, login streak, appearance items, stage)
    * EP / Elite-pass history (per-event id, owned-pass flag, badge count)
    * Mode-stats summary, MMR list, credit-score block
    * Career / Ranked stats for BR (solo/duo/squad) and CS
    * Fuzzy search result (extra public-facing fields)
    * Derived counters: total_skins (clothes), weapon_skin_count, badge_count,
      bundle_count (heuristic from selecteditemslots/clothes), pet_count,
      privilege_count, ep_pass_count

Prime + Evo (Spark) + skin/bundle counts are surfaced as a dedicated summary
block at the top of the report.

Requires:
    pip install requests pycryptodome protobuf
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import timezone
from Crypto.Cipher import AES

# Shared HTTP session for connection-pooling / TLS reuse across endpoints.
SESSION = requests.Session()

# ---------------------------------------------------------------------------
# Embedded compiled-protobuf modules (previously 03_Repos/FreeFire-Api/Proto/compiled).
# Each entry is the base64-encoded source of the auto-generated *_pb2.py file.
# At import time we exec each into its own ModuleType so that duplicate top-level
# names like `request` / `response` don't collide.
# ---------------------------------------------------------------------------
import types as _types

_PB2_BLOBS = {
  "MajorLogin_pb2": (
    "IyAtKi0gY29kaW5nOiB1dGYtOCAtKi0NCiMgR2VuZXJhdGVkIGJ5IHRoZSBwcm90b2NvbCBidWZm"
    "ZXIgY29tcGlsZXIuICBETyBOT1QgRURJVCENCiMgTk8gQ0hFQ0tFRC1JTiBQUk9UT0JVRiBHRU5D"
    "T0RFDQojIHNvdXJjZTogTWFqb3JMb2dpbi5wcm90bw0KIyBQcm90b2J1ZiBQeXRob24gVmVyc2lv"
    "bjogNi4zMy4xDQoiIiJHZW5lcmF0ZWQgcHJvdG9jb2wgYnVmZmVyIGNvZGUuIiIiDQpmcm9tIGdv"
    "b2dsZS5wcm90b2J1ZiBpbXBvcnQgZGVzY3JpcHRvciBhcyBfZGVzY3JpcHRvcg0KZnJvbSBnb29n"
    "bGUucHJvdG9idWYgaW1wb3J0IGRlc2NyaXB0b3JfcG9vbCBhcyBfZGVzY3JpcHRvcl9wb29sDQpm"
    "cm9tIGdvb2dsZS5wcm90b2J1ZiBpbXBvcnQgcnVudGltZV92ZXJzaW9uIGFzIF9ydW50aW1lX3Zl"
    "cnNpb24NCmZyb20gZ29vZ2xlLnByb3RvYnVmIGltcG9ydCBzeW1ib2xfZGF0YWJhc2UgYXMgX3N5"
    "bWJvbF9kYXRhYmFzZQ0KZnJvbSBnb29nbGUucHJvdG9idWYuaW50ZXJuYWwgaW1wb3J0IGJ1aWxk"
    "ZXIgYXMgX2J1aWxkZXINCl9ydW50aW1lX3ZlcnNpb24uVmFsaWRhdGVQcm90b2J1ZlJ1bnRpbWVW"
    "ZXJzaW9uKA0KICAgIF9ydW50aW1lX3ZlcnNpb24uRG9tYWluLlBVQkxJQywNCiAgICA2LA0KICAg"
    "IDMzLA0KICAgIDEsDQogICAgJycsDQogICAgJ01ham9yTG9naW4ucHJvdG8nDQopDQojIEBAcHJv"
    "dG9jX2luc2VydGlvbl9wb2ludChpbXBvcnRzKQ0KDQpfc3ltX2RiID0gX3N5bWJvbF9kYXRhYmFz"
    "ZS5EZWZhdWx0KCkNCg0KDQoNCg0KREVTQ1JJUFRPUiA9IF9kZXNjcmlwdG9yX3Bvb2wuRGVmYXVs"
    "dCgpLkFkZFNlcmlhbGl6ZWRGaWxlKGInXG5ceDEwTWFqb3JMb2dpbi5wcm90b1x4MTJcbk1ham9y"
    "TG9naW5cIlx4YzhceDEwXG5ceDA3cmVxdWVzdFx4MTJceDExXG5cdGFjY291bnRpZFx4MThceDAx"
    "IFx4MDEoXHgwNFx4MTJceDE0XG5ceDBjZ2FtZXNlcnZlcmlkXHgxOFx4MDIgXHgwMShcdFx4MTJc"
    "eDExXG5cdGV2ZW50dGltZVx4MThceDAzIFx4MDEoXHRceDEyXHgwZVxuXHgwNmdhbWVpZFx4MThc"
    "eDA0IFx4MDEoXHRceDEyXHgwZVxuXHgwNnBsYXRpZFx4MThceDA1IFx4MDEoXHJceDEyXHgxMlxu"
    "XG56b25lYXJlYWlkXHgxOFx4MDYgXHgwMShcclx4MTJceDE1XG5ccmNsaWVudHZlcnNpb25ceDE4"
    "XHgwNyBceDAxKFx0XHgxMlx4MTZcblx4MGVzeXN0ZW1zb2Z0d2FyZVx4MThceDA4IFx4MDEoXHRc"
    "eDEyXHgxNlxuXHgwZXN5c3RlbWhhcmR3YXJlXHgxOFx0IFx4MDEoXHRceDEyXHgxM1xuXHgwYnRl"
    "bGVjb21vcGVyXHgxOFxuIFx4MDEoXHRceDEyXHgwZlxuXHgwN25ldHdvcmtceDE4XHgwYiBceDAx"
    "KFx0XHgxMlx4MTNcblx4MGJzY3JlZW53aWR0aFx4MThceDBjIFx4MDEoXHJceDEyXHgxM1xuXHgw"
    "YnNjcmVlbmhpZ2h0XHgxOFxyIFx4MDEoXHJceDEyXHgwYlxuXHgwM1x4NjRwaVx4MThceDBlIFx4"
    "MDEoXHRceDEyXHgxM1xuXHgwYlx4NjNwdWhhcmR3YXJlXHgxOFx4MGYgXHgwMShcdFx4MTJceDBl"
    "XG5ceDA2bWVtb3J5XHgxOFx4MTAgXHgwMShcclx4MTJceDEwXG5ceDA4Z2xyZW5kZXJceDE4XHgx"
    "MSBceDAxKFx0XHgxMlx4MTFcblx0Z2x2ZXJzaW9uXHgxOFx4MTIgXHgwMShcdFx4MTJceDEwXG5c"
    "eDA4XHg2NFx4NjV2aWNlaWRceDE4XHgxMyBceDAxKFx0XHgxMlx4MTBcblx4MDhceDYzbGllbnRp"
    "cFx4MThceDE0IFx4MDEoXHRceDEyXHgxMFxuXHgwOGxhbmd1YWdlXHgxOFx4MTUgXHgwMShcdFx4"
    "MTJceDBlXG5ceDA2b3BlbmlkXHgxOFx4MTYgXHgwMShcdFx4MTJceDEyXG5cbm9wZW5pZHR5cGVc"
    "eDE4XHgxNyBceDAxKFx0XHgxMlx4MTJcblxuZGV2aWNldHlwZVx4MThceDE4IFx4MDEoXHRceDEy"
    "XHgxM1xuXHgwYlx4NjRceDY1dmljZW1vZGVsXHgxOFx4MTkgXHgwMShcdFx4MTJceDBlXG5ceDA2"
    "cmVnaW9uXHgxOFx4MWEgXHgwMShcdFx4MTJceDEwXG5ceDA4aXByZWdpb25ceDE4XHgxYiBceDAx"
    "KFx0XHgxMlx4MGVcblx4MDZvdGhlcnNceDE4XHgxYyBceDAxKFx0XHgxMlx4MTJcblxubG9naW50"
    "b2tlblx4MThceDFkIFx4MDEoXHRceDEyXHgxNVxuXHJwbGF0Zm9ybXNka2lkXHgxOFx4MWUgXHgw"
    "MShcclx4MTJcclxuXHgwNWxldmVsXHgxOFx4MWYgXHgwMShcclx4MTJceDBlXG5ceDA2XHg2M2xh"
    "bmlkXHgxOCAgXHgwMShceDA0XHgxMlx4MTNcblx4MGJwbGF0Zm9ybXVpZFx4MTghIFx4MDEoXHgw"
    "NFx4MTJceDEwXG5ceDA4bmlja25hbWVceDE4XCIgXHgwMShcdFx4MTJceDE4XG5ceDEwbmV0d29y"
    "a29wZXJhdG9yYVx4MTgjIFx4MDEoXHRceDEyXHgxNFxuXHgwY25ldHdvcmt0eXBlYVx4MTgkIFx4"
    "MDEoXHRceDEyXHgxMVxuXHRsaW5lMW51bWFceDE4JSBceDAxKFx0XHgxMlx4MTJcblxuaXNlbXVs"
    "YXRvclx4MTgmIFx4MDEoXHgwOFx4MTJceDExXG5cdGlwYWRkcmVzc1x4MThcJyBceDAxKFx0XHgx"
    "Mlx4MTRcblx4MGNzaWduYXR1cmVtZDVceDE4KCBceDAxKFx0XHgxMlx4MTVcblxyZW11bGF0b3Jz"
    "Y29yZVx4MTgpIFx4MDEoXHJceDEyXHgxYVxuXHgxMnNkY2FyZHRvdGFsc3RvcmFnZVx4MTgqIFx4"
    "MDEoXHgwNVx4MTJceDFhXG5ceDEyc2RjYXJkYXZhaWxzdG9yYWdlXHgxOCsgXHgwMShceDA1XHgx"
    "Mlx4MTlcblx4MTFpbm5lcnRvdGFsc3RvcmFnZVx4MTgsIFx4MDEoXHgwNVx4MTJceDE5XG5ceDEx"
    "aW5uZXJhdmFpbHN0b3JhZ2VceDE4LSBceDAxKFx4MDVceDEyJVxuXHgxZGdhbWVpbnN0YWxsZWRk"
    "aXNrYXZhaWxzdG9yYWdlXHgxOC4gXHgwMShceDA1XHgxMiVcblx4MWRnYW1laW5zdGFsbGVkZGlz"
    "a3RvdGFsc3RvcmFnZVx4MTgvIFx4MDEoXHgwNVx4MTJcIlxuXHgxYVx4NjV4dGVybmFsc2RjYXJk"
    "YXZhaWxzdG9yYWdlXHgxOFx4MzAgXHgwMShceDA1XHgxMlwiXG5ceDFhXHg2NXh0ZXJuYWxzZGNh"
    "cmR0b3RhbHN0b3JhZ2VceDE4XHgzMSBceDAxKFx4MDVceDEyXHgwZlxuXHgwN2xvZ2luYnlceDE4"
    "XHgzMiBceDAxKFxyXHgxMlx4MTJcblxubm90aXJlZ2lvblx4MThceDMzIFx4MDEoXHRceDEyL1xu"
    "XHgwNnNvdXJjZVx4MThceDM0IFx4MDEoXHgwZVx4MzJceDFmLk1ham9yTG9naW4uQWNjb3VudERv"
    "d25sb2FkVHlwZVx4MTJceDExXG5cdHJlZ2F2YXRhclx4MThceDM1IFx4MDEoXHJceDEyXHgxNlxu"
    "XHgwZWxvY2tyZWdpb250aW1lXHgxOFx4MzYgXHgwMShcclx4MTJceDBmXG5ceDA3cXVhbGl0eVx4"
    "MThceDM3IFx4MDEoXHJceDEyXHgwZlxuXHgwN2xpYnBhdGhceDE4XHgzOCBceDAxKFx0XHgxMlx4"
    "Mzhcblx4MGN1c2luZ3ZlcnNpb25ceDE4XHgzOSBceDAxKFx4MGVceDMyXCIuTWFqb3JMb2dpbi5B"
    "dXRoQ2xpZW50VXNpbmdWZXJzaW9uXHgxMlx4MTBcblx4MDhsaWJ0b2tlblx4MTg6IFx4MDEoXHRc"
    "eDEyXHgxM1xuXHgwYlx4NjNoYW5uZWx0eXBlXHgxODsgXHgwMShcclx4MTJceDBmXG5ceDA3XHg2"
    "M3B1dHlwZVx4MTg8IFx4MDEoXHJceDEyXHgxN1xuXHgwZlx4NjNwdWFyY2hpdGVjdHVyZVx4MTg9"
    "IFx4MDEoXHRceDEyXHgxOVxuXHgxMVx4NjNsaWVudHZlcnNpb25jb2RlXHgxOD4gXHgwMShcdFx4"
    "MTJceDE2XG5ceDBldG9rZW5leHBpcmVzYXRceDE4PyBceDAxKFx4MDNceDEyXHgzNVxuXHgwY25l"
    "d2JpZWNob2ljZVx4MThAIFx4MDEoXHgwZVx4MzJceDFmLk1ham9yTG9naW4uQWNjb3VudE5ld2Jp"
    "ZUNob2ljZVx4MTJceDE5XG5ceDExc3lzdGVtZ3JhcGhpY3NhcGlceDE4XHg0MSBceDAxKFx0XHgx"
    "Mlx4MWJcblx4MTNzdXBwb3J0ZWRhc3RjYml0c2V0XHgxOFx4NDIgXHgwMShcclx4MTJceDE3XG5c"
    "eDBmbG9naW5vcGVuaWR0eXBlXHgxOFx4NDMgXHgwMShcclx4MTJceDBlXG5ceDA2aXBjaXR5XHgx"
    "OFx4NDQgXHgwMShcdFx4MTJceDE1XG5ccmlwc3ViZGl2aXNpb25ceDE4XHg0NSBceDAxKFx0XHgx"
    "Mlx4MTNcblx4MGJsb2FkaW5ndGltZVx4MThceDQ2IFx4MDEoXHJceDEyXHgxNlxuXHgwZXJlbGVh"
    "c2VjaGFubmVsXHgxOEcgXHgwMShcdFx4MTJceDExXG5cdGdpbmRldGFpbFx4MThIIFx4MDEoXHgw"
    "Y1x4MTJceDFkXG5ceDE1XHg2MW5kcm9pZGVuZ2luZWluaXRmbGFnXHgxOEkgXHgwMShcclx4MTJc"
    "eDExXG5cdGV4dHJhaW5mb1x4MThKIFx4MDEoXHRceDEyXHgwZVxuXHgwNmlmcHVzaFx4MThLIFx4"
    "MDEoXHgwOFx4MTJcclxuXHgwNWlzdnBuXHgxOEwgXHgwMShceDA4XHgxMlx4MTlcblx4MTFvcmln"
    "bnBsYXRmb3JtdHlwZVx4MThNIFx4MDEoXHRceDEyXHgxYlxuXHgxM3ByaW1hcnlwbGF0Zm9ybXR5"
    "cGVceDE4TiBceDAxKFx0XHgxMlx4MTZcblx4MGVceDYzbGllbnRyZXBvcnRpcFx4MThPIFx4MDEo"
    "XHRceDEyXHgxNFxuXHgwY1x4NjZceDY2XHg2MW50aWRldGFpbFx4MThQIFx4MDEoXHgwY1x4MTJc"
    "eDBmXG5ceDA3XHg2MXJtdHlwZVx4MThRIFx4MDEoXHRceDEyXHgxM1xuXHgwYlx4NjJ1aWxkTnVt"
    "YmVyXHgxOFMgXHgwMShceDA0XHgxMlx4MTNcblx4MGJncmFwaGljc0FwaVx4MThWIFx4MDEoXHRc"
    "eDEyXHgxNVxuXHJncmFwaGljc0ZsYWdzXHgxOFcgXHgwMShcclx4MTJceDE1XG5ccmdyYXBoaWNz"
    "TGV2ZWxceDE4WCBceDAxKFxyXHgxMlx4MThcblx4MTBwZXJmb3JtYW5jZVNjb3JlXHgxOFxcIFx4"
    "MDEoXHJceDEyXHgxM1xuXHgwYnByb2ZpbGVOYW1lXHgxOF0gXHgwMShcdFx4MTJceDEzXG5ceDBi"
    "c2VjdXJlVG9rZW5ceDE4XiBceDAxKFx0XHgxMlx4MTFcblx0c2Vzc2lvbklkXHgxOF8gXHgwMShc"
    "clx4MTJceDE0XG5ceDBjcmVmcmVzaFJhdGVzXHgxOGAgXHgwMShcdFx4MTJceDEzXG5ceDBiXHg2"
    "Nlx4NjVceDYxdHVyZUZsYWdceDE4XHg2MiBceDAxKFxyXHgxMlx4MTBcblx4MDhwbGF0Zm9ybVx4"
    "MThceDYzIFx4MDEoXHRceDEyXHgxYVxuXHgxMm1haW5hY3RpdmVwbGF0Zm9ybVx4MThceDY0IFx4"
    "MDEoXHRcIlx4Y2VceDAzXG5ceDA4cmVzcG9uc2VceDEyXHgxMVxuXHRhY2NvdW50SWRceDE4XHgw"
    "MSBceDAxKFx4MDRceDEyXHgxMlxuXG5sb2NrUmVnaW9uXHgxOFx4MDIgXHgwMShcdFx4MTJceDEy"
    "XG5cbm5vdGlSZWdpb25ceDE4XHgwMyBceDAxKFx0XHgxMlx4MTBcblx4MDhpcFJlZ2lvblx4MThc"
    "eDA0IFx4MDEoXHRceDEyXHgxOFxuXHgxMFx4NjFnb3JhRW52aXJvbm1lbnRceDE4XHgwNSBceDAx"
    "KFx0XHgxMlx4MTdcblx4MGZuZXdBY3RpdmVSZWdpb25ceDE4XHgwNiBceDAxKFx0XHgxMlx4MThc"
    "blx4MTByZWNvbW1lbmRSZWdpb25zXHgxOFx4MDcgXHgwMyhcdFx4MTJcclxuXHgwNXRva2VuXHgx"
    "OFx4MDggXHgwMShcdFx4MTJceDBiXG5ceDAzdHRsXHgxOFx0IFx4MDEoXHJceDEyXHgxMVxuXHRz"
    "ZXJ2ZXJVcmxceDE4XG4gXHgwMShcdFx4MTJceDE1XG5ccmVtdWxhdG9yU2NvcmVceDE4XHgwYiBc"
    "eDAxKFxyXHgxMi9cblx0YmxhY2tsaXN0XHgxOFx4MGMgXHgwMShceDBiXHgzMlx4MWMuTWFqb3JM"
    "b2dpbi5CbGFja2xpc3RJbmZvUmVzXHgxMi1cblx0cXVldWVJbmZvXHgxOFxyIFx4MDEoXHgwYlx4"
    "MzJceDFhLk1ham9yTG9naW4uTG9naW5RdWV1ZUluZm9ceDEyXHJcblx4MDV0cFVybFx4MThceDBl"
    "IFx4MDEoXHRceDEyXHgxM1xuXHgwYlx4NjFwcFNlcnZlcklkXHgxOFx4MGYgXHgwMShcclx4MTJc"
    "eDBlXG5ceDA2aXBDaXR5XHgxOFx4MTAgXHgwMShcdFx4MTJceDE1XG5ccmlwU3ViZGl2aXNpb25c"
    "eDE4XHgxMSBceDAxKFx0XHgxMlx4MGJcblx4MDNrdHNceDE4XHgxMiBceDAxKFxyXHgxMlxuXG5c"
    "eDAyXHg2MWtceDE4XHgxMyBceDAxKFx4MGNceDEyXHgwYlxuXHgwM1x4NjFpdlx4MThceDE0IFx4"
    "MDEoXHgwY1x4MTJceDExXG5cdGZmYW50aVVybFx4MThceDE1IFx4MDEoXHRcIlx4YTBceDAxXG5c"
    "eDEwXHg0Nlx4NDZceDQxbnRpQ29uZmlnRGVzY1x4MTJceDBlXG5ceDA2cmVnaW9uXHgxOFx4MDEg"
    "XHgwMShcdFx4MTJceDBlXG5ceDA2XHg2NW5hYmxlXHgxOFx4MDIgXHgwMShceDA4XHgxMlx4MTJc"
    "blxuaHBlX2VuYWJsZVx4MThceDAzIFx4MDEoXHgwOFx4MTJceDEyXG5cbmZmaV9lbmFibGVceDE4"
    "XHgwNCBceDAxKFx4MDhceDEyXHgxY1xuXHgxNG10cF9saXRlX2RhdGFfZW5hYmxlXHgxOFx4MDUg"
    "XHgwMShceDA4XHgxMlx4MTJcblxuZmZtX2VuYWJsZVx4MThceDA2IFx4MDEoXHgwOFx4MTJceDEy"
    "XG5cbmZmb19lbmFibGVceDE4XHgwNyBceDAxKFx4MDhcImFcblx4MGVMb2dpblF1ZXVlSW5mb1x4"
    "MTJcclxuXHgwNVx4NjFsbG93XHgxOFx4MDEgXHgwMShceDA4XHgxMlx4MTVcblxycXVldWVQb3Np"
    "dGlvblx4MThceDAyIFx4MDEoXHJceDEyXHgxNFxuXHgwY25lZWRXYWl0U2Vjc1x4MThceDAzIFx4"
    "MDEoXHJceDEyXHgxM1xuXHgwYnF1ZXVlSXNGdWxsXHgxOFx4MDQgXHgwMShceDA4XCJsXG5ceDEw"
    "XHg0MmxhY2tsaXN0SW5mb1Jlc1x4MTIvXG5cdGJhblJlYXNvblx4MThceDAxIFx4MDEoXHgwZVx4"
    "MzJceDFjLk1ham9yTG9naW4uQWNjb3VudEJhblJlYXNvblx4MTJceDE2XG5ceDBlXHg2NXhwaXJl"
    "RHVyYXRpb25ceDE4XHgwMiBceDAxKFxyXHgxMlx4MGZcblx4MDdceDYyXHg2MW5UaW1lXHgxOFx4"
    "MDMgXHgwMShccipxXG5ceDEzXHg0MVx4NjNceDYzb3VudERvd25sb2FkVHlwZVx4MTJceDFiXG5c"
    "eDE3XHg0MVx4NjNceDYzb3VudERvd25sb2FkVHlwZU5PTkVceDEwXHgwMFx4MTJceDBmXG5ceDBi"
    "SU5TVEFOVEdBTUVceDEwXHgwMVx4MTJceDA3XG5ceDAzSU9TXHgxMFx4MDJceDEyXG5cblx4MDZI"
    "VUFXRUlceDEwXHgwM1x4MTJcblxuXHgwNlhJQU9NSVx4MTBceDA0XHgxMlx4MGJcblx4MDdTQU1T"
    "VU5HXHgxMFx4MDUqYlxuXHgxNlx4NDF1dGhDbGllbnRVc2luZ1ZlcnNpb25ceDEyXHgxZVxuXHgx"
    "YVx4NDF1dGhDbGllbnRVc2luZ1ZlcnNpb25OT05FXHgxMFx4MDBceDEyXG5cblx4MDZOT1JNQUxc"
    "eDEwXHgwMVx4MTJceDA3XG5ceDAzTUFYXHgxMFx4MDJceDEyXHgwN1xuXHgwM1x4NDZceDQ2SVx4"
    "MTBceDAzXHgxMlxuXG5ceDA2TUFYSFBFXHgxMFx4MDQqb1xuXHgxM1x4NDFceDYzXHg2M291bnRO"
    "ZXdiaWVDaG9pY2VceDEyXHgxYlxuXHgxN1x4NDFceDYzXHg2M291bnROZXdiaWVDaG9pY2VOT05F"
    "XHgxMFx4MDBceDEyXHJcblx0TkVXUExBWUVSXHgxMFx4MDFceDEyXHJcblx0RlBTUExBWUVSXHgx"
    "MFx4MDJceDEyXHgwYlxuXHgwN1ZFVEVSQU5ceDEwXHgwM1x4MTJceDEwXG5ceDBjTkVFRE1PUkVJ"
    "TkZPXHgxMFx4NjMqaFxuXHgxMFx4NDFceDYzXHg2M291bnRCYW5SZWFzb25ceDEyXHgwYlxuXHgw"
    "N1Vua25vd25ceDEwXHgwMFx4MTJceDBlXG5cbkluR2FtZUF1dG9ceDEwXHgwMVx4MTJcblxuXHgw"
    "NlJlZnVuZFx4MTBceDAyXHgxMlxuXG5ceDA2T3RoZXJzXHgxMFx4MDNceDEyXHgwYlxuXHgwN1Nr"
    "aW5tb2RceDEwXHgwNFx4MTJceDEyXG5cckluR2FtZUF1dG9OZXdceDEwXHhmNlx4MDdceDYyXHgw"
    "NnByb3RvMycpDQoNCl9nbG9iYWxzID0gZ2xvYmFscygpDQpfYnVpbGRlci5CdWlsZE1lc3NhZ2VB"
    "bmRFbnVtRGVzY3JpcHRvcnMoREVTQ1JJUFRPUiwgX2dsb2JhbHMpDQpfYnVpbGRlci5CdWlsZFRv"
    "cERlc2NyaXB0b3JzQW5kTWVzc2FnZXMoREVTQ1JJUFRPUiwgJ01ham9yTG9naW5fcGIyJywgX2ds"
    "b2JhbHMpDQppZiBub3QgX2Rlc2NyaXB0b3IuX1VTRV9DX0RFU0NSSVBUT1JTOg0KICBERVNDUklQ"
    "VE9SLl9sb2FkZWRfb3B0aW9ucyA9IE5vbmUNCiAgX2dsb2JhbHNbJ19BQ0NPVU5URE9XTkxPQURU"
    "WVBFJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9Mjk5Mg0KICBfZ2xvYmFsc1snX0FDQ09VTlRET1dOTE9B"
    "RFRZUEUnXS5fc2VyaWFsaXplZF9lbmQ9MzEwNQ0KICBfZ2xvYmFsc1snX0FVVEhDTElFTlRVU0lO"
    "R1ZFUlNJT04nXS5fc2VyaWFsaXplZF9zdGFydD0zMTA3DQogIF9nbG9iYWxzWydfQVVUSENMSUVO"
    "VFVTSU5HVkVSU0lPTiddLl9zZXJpYWxpemVkX2VuZD0zMjA1DQogIF9nbG9iYWxzWydfQUNDT1VO"
    "VE5FV0JJRUNIT0lDRSddLl9zZXJpYWxpemVkX3N0YXJ0PTMyMDcNCiAgX2dsb2JhbHNbJ19BQ0NP"
    "VU5UTkVXQklFQ0hPSUNFJ10uX3NlcmlhbGl6ZWRfZW5kPTMzMTgNCiAgX2dsb2JhbHNbJ19BQ0NP"
    "VU5UQkFOUkVBU09OJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MzMyMA0KICBfZ2xvYmFsc1snX0FDQ09V"
    "TlRCQU5SRUFTT04nXS5fc2VyaWFsaXplZF9lbmQ9MzQyNA0KICBfZ2xvYmFsc1snX1JFUVVFU1Qn"
    "XS5fc2VyaWFsaXplZF9zdGFydD0zMw0KICBfZ2xvYmFsc1snX1JFUVVFU1QnXS5fc2VyaWFsaXpl"
    "ZF9lbmQ9MjE1Mw0KICBfZ2xvYmFsc1snX1JFU1BPTlNFJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MjE1"
    "Ng0KICBfZ2xvYmFsc1snX1JFU1BPTlNFJ10uX3NlcmlhbGl6ZWRfZW5kPTI2MTgNCiAgX2dsb2Jh"
    "bHNbJ19GRkFOVElDT05GSUdERVNDJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MjYyMQ0KICBfZ2xvYmFs"
    "c1snX0ZGQU5USUNPTkZJR0RFU0MnXS5fc2VyaWFsaXplZF9lbmQ9Mjc4MQ0KICBfZ2xvYmFsc1sn"
    "X0xPR0lOUVVFVUVJTkZPJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9Mjc4Mw0KICBfZ2xvYmFsc1snX0xP"
    "R0lOUVVFVUVJTkZPJ10uX3NlcmlhbGl6ZWRfZW5kPTI4ODANCiAgX2dsb2JhbHNbJ19CTEFDS0xJ"
    "U1RJTkZPUkVTJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9Mjg4Mg0KICBfZ2xvYmFsc1snX0JMQUNLTElT"
    "VElORk9SRVMnXS5fc2VyaWFsaXplZF9lbmQ9Mjk5MA0KIyBAQHByb3RvY19pbnNlcnRpb25fcG9p"
    "bnQobW9kdWxlX3Njb3BlKQ0K"
  ),
  "PlayerPersonalShow_pb2": (
    "IyAtKi0gY29kaW5nOiB1dGYtOCAtKi0NCiMgR2VuZXJhdGVkIGJ5IHRoZSBwcm90b2NvbCBidWZm"
    "ZXIgY29tcGlsZXIuICBETyBOT1QgRURJVCENCiMgTk8gQ0hFQ0tFRC1JTiBQUk9UT0JVRiBHRU5D"
    "T0RFDQojIHNvdXJjZTogUGxheWVyUGVyc29uYWxTaG93LnByb3RvDQojIFByb3RvYnVmIFB5dGhv"
    "biBWZXJzaW9uOiA2LjMzLjENCiIiIkdlbmVyYXRlZCBwcm90b2NvbCBidWZmZXIgY29kZS4iIiIN"
    "CmZyb20gZ29vZ2xlLnByb3RvYnVmIGltcG9ydCBkZXNjcmlwdG9yIGFzIF9kZXNjcmlwdG9yDQpm"
    "cm9tIGdvb2dsZS5wcm90b2J1ZiBpbXBvcnQgZGVzY3JpcHRvcl9wb29sIGFzIF9kZXNjcmlwdG9y"
    "X3Bvb2wNCmZyb20gZ29vZ2xlLnByb3RvYnVmIGltcG9ydCBydW50aW1lX3ZlcnNpb24gYXMgX3J1"
    "bnRpbWVfdmVyc2lvbg0KZnJvbSBnb29nbGUucHJvdG9idWYgaW1wb3J0IHN5bWJvbF9kYXRhYmFz"
    "ZSBhcyBfc3ltYm9sX2RhdGFiYXNlDQpmcm9tIGdvb2dsZS5wcm90b2J1Zi5pbnRlcm5hbCBpbXBv"
    "cnQgYnVpbGRlciBhcyBfYnVpbGRlcg0KX3J1bnRpbWVfdmVyc2lvbi5WYWxpZGF0ZVByb3RvYnVm"
    "UnVudGltZVZlcnNpb24oDQogICAgX3J1bnRpbWVfdmVyc2lvbi5Eb21haW4uUFVCTElDLA0KICAg"
    "IDYsDQogICAgMzMsDQogICAgMSwNCiAgICAnJywNCiAgICAnUGxheWVyUGVyc29uYWxTaG93LnBy"
    "b3RvJw0KKQ0KIyBAQHByb3RvY19pbnNlcnRpb25fcG9pbnQoaW1wb3J0cykNCg0KX3N5bV9kYiA9"
    "IF9zeW1ib2xfZGF0YWJhc2UuRGVmYXVsdCgpDQoNCg0KDQoNCkRFU0NSSVBUT1IgPSBfZGVzY3Jp"
    "cHRvcl9wb29sLkRlZmF1bHQoKS5BZGRTZXJpYWxpemVkRmlsZShiJ1xuXHgxOFBsYXllclBlcnNv"
    "bmFsU2hvdy5wcm90b1x4MTJceDEyUGxheWVyUGVyc29uYWxTaG93XCJceGU0XHgwMVxuXHgwN3Jl"
    "cXVlc3RceDEyXHgxMVxuXHRhY2NvdW50SWRceDE4XHgwMSBceDAxKFx4MDRceDEyXHgzOFxuXHgw"
    "Ylx4NjNceDYxbGxTaWduU3JjXHgxOFx4MDIgXHgwMShceDBlXHgzMiMuUGxheWVyUGVyc29uYWxT"
    "aG93LkNhbGxTaWduU3JjVHlwZVx4MTJceDFjXG5ceDBmbmVlZEdhbGxlcnlJbmZvXHgxOFx4MDMg"
    "XHgwMShceDA4SFx4MDBceDg4XHgwMVx4MDFceDEyXHgxYVxuXHJuZWVkQmxhY2tsaXN0XHgxOFx4"
    "MDQgXHgwMShceDA4SFx4MDFceDg4XHgwMVx4MDFceDEyXHgxYVxuXHJuZWVkU3BhcmtJbmZvXHgx"
    "OFx4MDUgXHgwMShceDA4SFx4MDJceDg4XHgwMVx4MDFceDQyXHgxMlxuXHgxMF9uZWVkR2FsbGVy"
    "eUluZm9CXHgxMFxuXHgwZV9uZWVkQmxhY2tsaXN0Qlx4MTBcblx4MGVfbmVlZFNwYXJrSW5mb1wi"
    "XHhmMlx4MDdcblx4MDhyZXNwb25zZVx4MTJceDM3XG5cdGJhc2ljaW5mb1x4MThceDAxIFx4MDEo"
    "XHgwYlx4MzIkLlBsYXllclBlcnNvbmFsU2hvdy5BY2NvdW50SW5mb0Jhc2ljXHgxMlx4MzZcblx4"
    "MGJwcm9maWxlaW5mb1x4MThceDAyIFx4MDEoXHgwYlx4MzIhLlBsYXllclBlcnNvbmFsU2hvdy5B"
    "dmF0YXJQcm9maWxlXHgxMlx4MWRcblx4MTVyYW5raW5nbGVhZGVyYm9hcmRwb3NceDE4XHgwMyBc"
    "eDAxKFx4MDVceDEyLVxuXHgwNG5ld3NceDE4XHgwNCBceDAzKFx4MGJceDMyXHgxZi5QbGF5ZXJQ"
    "ZXJzb25hbFNob3cuQWNjb3VudE5ld3NceDEyXHgzNlxuXHJoaXN0b3J5ZXBpbmZvXHgxOFx4MDUg"
    "XHgwMyhceDBiXHgzMlx4MWYuUGxheWVyUGVyc29uYWxTaG93LkJhc2ljRVBJbmZvXHgxMlx4Mzhc"
    "blxyY2xhbmJhc2ljaW5mb1x4MThceDA2IFx4MDEoXHgwYlx4MzIhLlBsYXllclBlcnNvbmFsU2hv"
    "dy5DbGFuSW5mb0Jhc2ljXHgxMj5cblx4MTBceDYzXHg2MXB0YWluYmFzaWNpbmZvXHgxOFx4MDcg"
    "XHgwMShceDBiXHgzMiQuUGxheWVyUGVyc29uYWxTaG93LkFjY291bnRJbmZvQmFzaWNceDEyLFxu"
    "XHgwN3BldGluZm9ceDE4XHgwOCBceDAxKFx4MGJceDMyXHgxYi5QbGF5ZXJQZXJzb25hbFNob3cu"
    "UGV0SW5mb1x4MTJceDM3XG5cbnNvY2lhbGluZm9ceDE4XHQgXHgwMShceDBiXHgzMiMuUGxheWVy"
    "UGVyc29uYWxTaG93LlNvY2lhbEJhc2ljSW5mb1x4MTI6XG5ceDBlXHg2NGlhbW9uZGNvc3RyZXNc"
    "eDE4XG4gXHgwMShceDBiXHgzMlwiLlBsYXllclBlcnNvbmFsU2hvdy5EaWFtb25kQ29zdFJlc1x4"
    "MTJceDQxXG5ceDBmXHg2M3JlZGl0c2NvcmVpbmZvXHgxOFx4MGIgXHgwMShceDBiXHgzMiguUGxh"
    "eWVyUGVyc29uYWxTaG93LkNyZWRpdFNjb3JlSW5mb0Jhc2ljXHgxMktcblx4MGVwcmV2ZXRlcmFu"
    "dHlwZVx4MThceDBjIFx4MDEoXHgwZVx4MzJceDMzLlBsYXllclBlcnNvbmFsU2hvdy5FQXR0ZW5k"
    "YW5jZVByZVZldGVyYW5BY3Rpb25UeXBlXHgxMlx4MzNcblx4MDdtbXJsaXN0XHgxOFxyIFx4MDMo"
    "XHgwYlx4MzJcIi5QbGF5ZXJQZXJzb25hbFNob3cuQWNjb3VudE1NUkluZm9ceDEyXHg0NlxuXHgx"
    "NG1vZGVzdGF0c3N1bW1hcnlpbmZvXHgxOFx4MGUgXHgwMShceDBiXHgzMiguUGxheWVyUGVyc29u"
    "YWxTaG93Lk1vZGVTdGF0c1N1bW1hcnlJbmZvXHgxMlx4MzZcblx4MGZ1c2VyX3NwYXJrX2luZm9c"
    "eDE4XHgwZiBceDAxKFx4MGJceDMyXHgxZC5QbGF5ZXJQZXJzb25hbFNob3cuU3BhcmtJbmZvXHgx"
    "Mlx4Mzhcblx4MTFceDYzb2xsYWJfc3BhcmtfaW5mb1x4MThceDEwIFx4MDEoXHgwYlx4MzJceDFk"
    "LlBsYXllclBlcnNvbmFsU2hvdy5TcGFya0luZm9ceDEyU1xuXHgxNlx4NjNvbGxlY3Rpb25fY3Vz"
    "dG9tX2xpc3RceDE4XHgxMSBceDAzKFx4MGJceDMyXHgzMy5QbGF5ZXJQZXJzb25hbFNob3cuQWNj"
    "b3VudENvbGxlY3Rpb25DdXN0b21JdGVtSW5mb1wiXHg4YVx4MTNcblx4MTBceDQxXHg2M1x4NjNv"
    "dW50SW5mb0Jhc2ljXHgxMlx4MTFcblx0YWNjb3VudGlkXHgxOFx4MDEgXHgwMShceDA0XHgxMlx4"
    "MTNcblx4MGJceDYxXHg2M1x4NjNvdW50dHlwZVx4MThceDAyIFx4MDEoXHJceDEyXHgxMFxuXHgw"
    "OG5pY2tuYW1lXHgxOFx4MDMgXHgwMShcdFx4MTJceDEyXG5cbmV4dGVybmFsaWRceDE4XHgwNCBc"
    "eDAxKFx0XHgxMlx4MGVcblx4MDZyZWdpb25ceDE4XHgwNSBceDAxKFx0XHgxMlxyXG5ceDA1bGV2"
    "ZWxceDE4XHgwNiBceDAxKFxyXHgxMlx4MGJcblx4MDNceDY1eHBceDE4XHgwNyBceDAxKFxyXHgx"
    "Mlx4MTRcblx4MGNceDY1eHRlcm5hbHR5cGVceDE4XHgwOCBceDAxKFxyXHgxMlx4MTRcblx4MGNc"
    "eDY1eHRlcm5hbG5hbWVceDE4XHQgXHgwMShcdFx4MTJceDE0XG5ceDBjXHg2NXh0ZXJuYWxpY29u"
    "XHgxOFxuIFx4MDEoXHRceDEyXHgxMFxuXHgwOFx4NjJceDYxbm5lcmlkXHgxOFx4MGIgXHgwMShc"
    "clx4MTJceDBmXG5ceDA3aGVhZHBpY1x4MThceDBjIFx4MDEoXHJceDEyXHgxMFxuXHgwOFx4NjNs"
    "YW5uYW1lXHgxOFxyIFx4MDEoXHRceDEyXHgwY1xuXHgwNHJhbmtceDE4XHgwZSBceDAxKFxyXHgx"
    "Mlx4MTVcblxycmFua2luZ3BvaW50c1x4MThceDBmIFx4MDEoXHJceDEyXHgwY1xuXHgwNHJvbGVc"
    "eDE4XHgxMCBceDAxKFxyXHgxMlx4MTRcblx4MGNoYXNlbGl0ZXBhc3NceDE4XHgxMSBceDAxKFx4"
    "MDhceDEyXHgxMFxuXHgwOFx4NjJceDYxXHg2NGdlY250XHgxOFx4MTIgXHgwMShcclx4MTJceDBm"
    "XG5ceDA3XHg2Mlx4NjFceDY0Z2VpZFx4MThceDEzIFx4MDEoXHJceDEyXHgxMFxuXHgwOHNlYXNv"
    "bmlkXHgxOFx4MTQgXHgwMShcclx4MTJcclxuXHgwNWxpa2VkXHgxOFx4MTUgXHgwMShcclx4MTJc"
    "eDExXG5cdGlzZGVsZXRlZFx4MThceDE2IFx4MDEoXHgwOFx4MTJceDEwXG5ceDA4c2hvd3Jhbmtc"
    "eDE4XHgxNyBceDAxKFx4MDhceDEyXHgxM1xuXHgwYmxhc3Rsb2dpbmF0XHgxOFx4MTggXHgwMShc"
    "eDAzXHgxMlx4MTNcblx4MGJceDY1eHRlcm5hbHVpZFx4MThceDE5IFx4MDEoXHgwNFx4MTJceDEw"
    "XG5ceDA4cmV0dXJuYXRceDE4XHgxYSBceDAxKFx4MDNceDEyXHgxY1xuXHgxNFx4NjNoYW1waW9u"
    "c2hpcHRlYW1uYW1lXHgxOFx4MWIgXHgwMShcdFx4MTIhXG5ceDE5XHg2M2hhbXBpb25zaGlwdGVh"
    "bW1lbWJlcm51bVx4MThceDFjIFx4MDEoXHJceDEyXHgxYVxuXHgxMlx4NjNoYW1waW9uc2hpcHRl"
    "YW1pZFx4MThceDFkIFx4MDEoXHgwNFx4MTJceDBlXG5ceDA2XHg2M3NyYW5rXHgxOFx4MWUgXHgw"
    "MShcclx4MTJceDE3XG5ceDBmXHg2M3NyYW5raW5ncG9pbnRzXHgxOFx4MWYgXHgwMShcclx4MTJc"
    "eDE3XG5ceDBmd2VhcG9uc2tpbnNob3dzXHgxOCAgXHgwMyhcclx4MTJcclxuXHgwNXBpbmlkXHgx"
    "OCEgXHgwMShcclx4MTJceDE2XG5ceDBlaXNjc3JhbmtpbmdiYW5ceDE4XCIgXHgwMShceDA4XHgx"
    "Mlx4MGZcblx4MDdtYXhyYW5rXHgxOCMgXHgwMShcclx4MTJceDExXG5cdGNzbWF4cmFua1x4MTgk"
    "IFx4MDEoXHJceDEyXHgxOFxuXHgxMG1heHJhbmtpbmdwb2ludHNceDE4JSBceDAxKFxyXHgxMlx4"
    "MTNcblx4MGJnYW1lYmFnc2hvd1x4MTgmIFx4MDEoXHJceDEyXHgxM1xuXHgwYnBlYWtyYW5rcG9z"
    "XHgxOFwnIFx4MDEoXHJceDEyXHgxNVxuXHJjc3BlYWtyYW5rcG9zXHgxOCggXHgwMShcclx4MTI6"
    "XG5ceDBlXHg2MVx4NjNceDYzb3VudHByZWZlcnNceDE4KSBceDAxKFx4MGJceDMyXCIuUGxheWVy"
    "UGVyc29uYWxTaG93LkFjY291bnRQcmVmZXJzXHgxMlx4MWRcblx4MTVwZXJpb2RpY3Jhbmtpbmdw"
    "b2ludHNceDE4KiBceDAxKFxyXHgxMlx4MTRcblx4MGNwZXJpb2RpY3JhbmtceDE4KyBceDAxKFxy"
    "XHgxMlx4MTBcblx4MDhceDYzcmVhdGVhdFx4MTgsIFx4MDEoXHgwM1x4MTJMXG5ceDEzdmV0ZXJh"
    "bmxlYXZlZGF5c3RhZ1x4MTgtIFx4MDEoXHgwZVx4MzIvLlBsYXllclBlcnNvbmFsU2hvdy5FQXR0"
    "ZW5kYW5jZVZldGVyYW5MZWF2ZURheXNceDEyXHgxOVxuXHgxMXNlbGVjdGVkaXRlbXNsb3RzXHgx"
    "OC4gXHgwMyhcclx4MTJLXG5ceDBlcHJldmV0ZXJhbnR5cGVceDE4LyBceDAxKFx4MGVceDMyXHgz"
    "My5QbGF5ZXJQZXJzb25hbFNob3cuRUF0dGVuZGFuY2VQcmVWZXRlcmFuQWN0aW9uVHlwZVx4MTJc"
    "clxuXHgwNXRpdGxlXHgxOFx4MzAgXHgwMShcclx4MTI+XG5ceDEwXHg2NXh0ZXJuYWxpY29uaW5m"
    "b1x4MThceDMxIFx4MDEoXHgwYlx4MzIkLlBsYXllclBlcnNvbmFsU2hvdy5FeHRlcm5hbEljb25J"
    "bmZvXHgxMlx4MTZcblx4MGVyZWxlYXNldmVyc2lvblx4MThceDMyIFx4MDEoXHRceDEyXHgxOVxu"
    "XHgxMXZldGVyYW5leHBpcmV0aW1lXHgxOFx4MzMgXHgwMShceDA0XHgxMlx4MTJcblxuc2hvd2Jy"
    "cmFua1x4MThceDM0IFx4MDEoXHgwOFx4MTJceDEyXG5cbnNob3djc3JhbmtceDE4XHgzNSBceDAx"
    "KFx4MDhceDEyXHgwZVxuXHgwNlx4NjNsYW5pZFx4MThceDM2IFx4MDEoXHgwNFx4MTJceDEzXG5c"
    "eDBiXHg2M2xhbmJhZGdlaWRceDE4XHgzNyBceDAxKFxyXHgxMlx4MTdcblx4MGZceDYzdXN0b21j"
    "bGFuYmFkZ2VceDE4XHgzOCBceDAxKFx0XHgxMlx4MWFcblx4MTJ1c2VjdXN0b21jbGFuYmFkZ2Vc"
    "eDE4XHgzOSBceDAxKFx4MDhceDEyXHgxM1xuXHgwYlx4NjNsYW5mcmFtZWlkXHgxODogXHgwMShc"
    "clx4MTJceDE3XG5ceDBmbWVtYmVyc2hpcHN0YXRlXHgxODsgXHgwMShceDA4XHgxMlx4NDNcblx4"
    "MTFzZWxlY3RvY2N1cGF0aW9uc1x4MTg8IFx4MDMoXHgwYlx4MzIoLlBsYXllclBlcnNvbmFsU2hv"
    "dy5PY2N1cGF0aW9uU2Vhc29uSW5mb1x4MTJeXG5ceDFkc29jaWFsaGlnaGxpZ2h0c3dpdGhiYXNp"
    "Y2luZm9ceDE4PSBceDAxKFx4MGJceDMyXHgzNy5QbGF5ZXJQZXJzb25hbFNob3cuU29jaWFsSGln"
    "aExpZ2h0c1dpdGhTb2NpYWxCYXNpY0luZm9ceDEyXHgzN1xuXHJhYnRlc3RjaG9pY2VzXHgxOD4g"
    "XHgwMyhceDBiXHgzMiAuUGxheWVyUGVyc29uYWxTaG93LkFiVGVzdENob2ljZVx4MTJceDM0XG5c"
    "eDBiaXRlbXRhZ2luZm9ceDE4PyBceDAzKFx4MGJceDMyXHgxZi5QbGF5ZXJQZXJzb25hbFNob3cu"
    "SXRlbVRhZ0luZm9ceDEyXHgxMFxuXHgwOHJhbmtzb3J0XHgxOEAgXHgwMShcclx4MTJceDEyXG5c"
    "bmNzcmFua3NvcnRceDE4XHg0MSBceDAxKFxyXHgxMlx4MTFcblx0aGlwcG9yYW5rXHgxOFx4NDIg"
    "XHgwMShcclx4MTJceDFhXG5ceDEyaGlwcG9yYW5raW5ncG9pbnRzXHgxOFx4NDMgXHgwMShcclx4"
    "MTJceDE0XG5ceDBjaGlwcG9tYXhyYW5rXHgxOFx4NDQgXHgwMShcclx4MTJceDE1XG5ccnNob3do"
    "aXBwb3JhbmtceDE4XHg0NSBceDAxKFx4MDhceDEyXHgxOFxuXHgxMGhpcHBvdG90YWxwcm9maXRc"
    "eDE4XHg0NiBceDAxKFxyXHgxMlx4MTdcblx4MGZoaXBwb3RvdGFsd29ydGhceDE4RyBceDAxKFxy"
    "XHgxMlx4Mzlcblx4MGVtb2Rlc3RhdHNpbmZvc1x4MThIIFx4MDMoXHgwYlx4MzIhLlBsYXllclBl"
    "cnNvbmFsU2hvdy5Nb2RlU3RhdHNJbmZvXHgxMlx4MzBcblx0YmFkZ2VpbmZvXHgxOEkgXHgwMShc"
    "eDBiXHgzMlx4MWQuUGxheWVyUGVyc29uYWxTaG93LkJhZGdlSW5mb1x4MTJceDQ2XG5ceDE0cHJp"
    "bWVwcml2aWxlZ2VkZXRhaWxceDE4SiBceDAxKFx4MGJceDMyKC5QbGF5ZXJQZXJzb25hbFNob3cu"
    "UHJpbWVQcml2aWxlZ2VEZXRhaWxceDEyXHgxNFxuXHgwY1x4NjNzcGVha3BvaW50c1x4MThLIFx4"
    "MDEoXHJceDEyXHgxYVxuXHgxMlx4NjRpc3BsYXljc3BlYWtwb2ludFx4MThMIFx4MDEoXHgwOFx4"
    "MTJceDFmXG5ceDE3XHg2M3NwZWFrdG91cm5hbWVudHJhbmtwb3NceDE4TSBceDAxKFxyXHgxMlx4"
    "MTNcblx4MGJceDYxdmF0YXJmcmFtZVx4MThOIFx4MDEoXHJceDEyXHgzM1xuXHRibGFja2xpc3Rc"
    "eDE4TyBceDAxKFx4MGJceDMyIC5QbGF5ZXJQZXJzb25hbFNob3cuQmxhY2tsaXN0UmVzXHgxMk1c"
    "blx4MTV3b3Jrc2hvcF9zdW1tYXJ5X2luZm9ceDE4UCBceDAxKFx4MGJceDMyLi5QbGF5ZXJQZXJz"
    "b25hbFNob3cuV29ya3Nob3BBY2NvdW50U3VtbWFyeUluZm9ceDEyPVxuXG5zcGFya19pbmZvXHgx"
    "OFEgXHgwMShceDBiXHgzMikuUGxheWVyUGVyc29uYWxTaG93LkFjY291bnRCYXNpY1NwYXJrSW5m"
    "b1x4MTI+XG5ceDExc29jaWFsX2Jhc2ljX2luZm9ceDE4UiBceDAxKFx4MGJceDMyIy5QbGF5ZXJQ"
    "ZXJzb25hbFNob3cuU29jaWFsQmFzaWNJbmZvXCJgXG5ceDE1XHg0MVx4NjNceDYzb3VudEJhc2lj"
    "U3BhcmtJbmZvXHgxMlx4MGZcblx4MDdceDYzbGFpbWVkXHgxOFx4MDEgXHgwMShceDA4XHgxMlx4"
    "MzZcblx4MGZ1c2VyX3NwYXJrX2luZm9ceDE4XHgwMiBceDAxKFx4MGJceDMyXHgxZC5QbGF5ZXJQ"
    "ZXJzb25hbFNob3cuU3BhcmtJbmZvXCI9XG5ceDFhV29ya3Nob3BBY2NvdW50U3VtbWFyeUluZm9c"
    "eDEyXHgxMlxuXG5hY2NvdW50X2lkXHgxOFx4MDEgXHgwMShceDA0XHgxMlx4MGJcblx4MDNceDY1"
    "eHBceDE4XHgwMiBceDAxKFxyXCJceGJlXHgwMVxuXHgwY1x4NDJsYWNrbGlzdFJlc1x4MTJceDEy"
    "XG5cbmFjY291bnRfaWRceDE4XHgwMSBceDAxKFx4MDRceDEyXHgxMVxuXHRkZXZpY2VfaWRceDE4"
    "XHgwMiBceDAxKFx0XHgxMlx4MTJcblxuYmFuX3JlYXNvblx4MThceDAzIFx4MDEoXHJceDEyXHgx"
    "MFxuXHgwOFx4NjJceDYxbl90aW1lXHgxOFx4MDQgXHgwMShcclx4MTJceDE5XG5ceDExXHg2Mlx4"
    "NjFuX3JlYXNvbl9kZXRhaWxceDE4XHgwNSBceDAxKFx0XHgxMlx4MTdcblx4MGZpc19pbl9ibGFj"
    "a2xpc3RceDE4XHgwNiBceDAxKFx4MDhceDEyXHgxYlxuXHgxM1x4NjJceDYxbl9leHBpcmVfZHVy"
    "YXRpb25ceDE4XHgwNyBceDAxKFxyXHgxMlx4MTBcblx4MDhceDYyXHg2MW5fdHlwZVx4MThceDA4"
    "IFx4MDEoXHRcIlx4ZDZceDAxXG5ceDBlXHg0MVx4NjNceDYzb3VudFByZWZlcnNceDEyXHgxM1xu"
    "XHgwYmhpZGVteWxvYmJ5XHgxOFx4MDEgXHgwMShceDA4XHgxMlx4MWFcblx4MTJwcmVnYW1lc2hv"
    "d2Nob2ljZXNceDE4XHgwMiBceDAzKFxyXHgxMlx4MWNcblx4MTRceDYycnByZWdhbWVzaG93Y2hv"
    "aWNlc1x4MThceDAzIFx4MDMoXHJceDEyXHgxOFxuXHgxMGhpZGVwZXJzb25hbGluZm9ceDE4XHgw"
    "NCBceDAxKFx4MDhceDEyXHgxZFxuXHgxNVx4NjRpc2FibGVmcmllbmRzcGVjdGF0ZVx4MThceDA1"
    "IFx4MDEoXHgwOFx4MTJceDE2XG5ceDBlaGlkZW9jY3VwYXRpb25ceDE4XHgwNiBceDAxKFx4MDhc"
    "eDEyJFxuXHgxY1x4NjNzX3BlYWtfcHJlZ2FtZV9zaG93X2Nob2ljZXNceDE4XHgwNyBceDAzKFxy"
    "XCJceGFjXHgwMVxuXHgxMFx4NDV4dGVybmFsSWNvbkluZm9ceDEyXHgxNFxuXHgwY1x4NjV4dGVy"
    "bmFsaWNvblx4MThceDAxIFx4MDEoXHRceDEyPlxuXHgwNnN0YXR1c1x4MThceDAyIFx4MDEoXHgw"
    "ZVx4MzIuLlBsYXllclBlcnNvbmFsU2hvdy5FQWNjb3VudEV4dGVybmFsSWNvblN0YXR1c1x4MTJc"
    "eDQyXG5ceDA4c2hvd3R5cGVceDE4XHgwMyBceDAxKFx4MGVceDMyXHgzMC5QbGF5ZXJQZXJzb25h"
    "bFNob3cuRUFjY291bnRFeHRlcm5hbEljb25TaG93VHlwZVwiXHg5Mlx4MDFcblx4MTRPY2N1cGF0"
    "aW9uU2Vhc29uSW5mb1x4MTJceDEwXG5ceDA4c2Vhc29uaWRceDE4XHgwMSBceDAxKFxyXHgxMlx4"
    "MTBcblx4MDhnYW1lbW9kZVx4MThceDAyIFx4MDEoXHJceDEyXHgzMFxuXHgwNGluZm9ceDE4XHgw"
    "MyBceDAxKFx4MGJceDMyXCIuUGxheWVyUGVyc29uYWxTaG93Lk9jY3VwYXRpb25JbmZvXHgxMlx4"
    "MTFcblx0bWF0Y2htb2RlXHgxOFx4MDQgXHgwMShcclx4MTJceDExXG5cdGV4dGVuZHZhbFx4MThc"
    "eDA1IFx4MDEoXHJcInNcblx4MGVPY2N1cGF0aW9uSW5mb1x4MTJceDE0XG5ceDBjb2NjdXBhdGlv"
    "bmlkXHgxOFx4MDEgXHgwMShcclx4MTJceDBlXG5ceDA2c2NvcmVzXHgxOFx4MDIgXHgwMShceDA0"
    "XHgxMlx4MTNcblx4MGJwcm9maWNpZW50c1x4MThceDAzIFx4MDEoXHgwNFx4MTJceDE0XG5ceDBj"
    "cHJvZmljaWVudGx2XHgxOFx4MDQgXHgwMShcclx4MTJceDEwXG5ceDA4aXNzZWxlY3RceDE4XHgw"
    "NSBceDAxKFx4MDhcIlx4YTJceDAxXG4jU29jaWFsSGlnaExpZ2h0c1dpdGhTb2NpYWxCYXNpY0lu"
    "Zm9ceDEyPVxuXHgxMHNvY2lhbGhpZ2hsaWdodHNceDE4XHgwMSBceDAzKFx4MGJceDMyIy5QbGF5"
    "ZXJQZXJzb25hbFNob3cuU29jaWFsSGlnaExpZ2h0XHgxMjxcblx4MGZzb2NpYWxiYXNpY2luZm9c"
    "eDE4XHgwMiBceDAxKFx4MGJceDMyIy5QbGF5ZXJQZXJzb25hbFNob3cuU29jaWFsQmFzaWNJbmZv"
    "XCJrXG5ceDBmU29jaWFsSGlnaExpZ2h0XHgxMlx4Mzdcblx0aGlnaGxpZ2h0XHgxOFx4MDEgXHgw"
    "MShceDBlXHgzMiQuUGxheWVyUGVyc29uYWxTaG93LkVTb2NpYWxIaWdoTGlnaHRceDEyXHgxMFxu"
    "XHgwOFx4NjV4cGlyZWF0XHgxOFx4MDIgXHgwMShceDAzXHgxMlxyXG5ceDA1dmFsdWVceDE4XHgw"
    "MyBceDAxKFxyXCIpXG5ceDBjXHg0MVx4NjJUZXN0Q2hvaWNlXHgxMlx4MGNcblx4MDR0eXBlXHgx"
    "OFx4MDEgXHgwMShcclx4MTJceDBiXG5ceDAzdmFsXHgxOFx4MDIgXHgwMShcclwiPlxuXHgwYkl0"
    "ZW1UYWdJbmZvXHgxMlx4MGVcblx4MDZpdGVtaWRceDE4XHgwMSBceDAxKFxyXHgxMlx4MTBcblx4"
    "MDhzZXJpZXNpZFx4MThceDAyIFx4MDEoXHJceDEyXHJcblx4MDVudW1pZFx4MThceDAzIFx4MDEo"
    "XHJcIjBcblxyTW9kZVN0YXRzSW5mb1x4MTJceDEwXG5ceDA4Z2FtZW1vZGVceDE4XHgwMSBceDAx"
    "KFxyXHgxMlxyXG5ceDA1c2NvcmVceDE4XHgwMiBceDAxKFxyXCJOXG5cdEJhZGdlSW5mb1x4MTJc"
    "eDMwXG5cdGJhZGdldHlwZVx4MThceDAxIFx4MDEoXHgwZVx4MzJceDFkLlBsYXllclBlcnNvbmFs"
    "U2hvdy5CYWRnZVR5cGVceDEyXHgwZlxuXHgwN3N1YnR5cGVceDE4XHgwMiBceDAxKFxyXCJceGRh"
    "XHgwMVxuXHgxNFByaW1lUHJpdmlsZWdlRGV0YWlsXHgxMlx4MTFcblx0YWNjb3VudGlkXHgxOFx4"
    "MDEgXHgwMShceDA0XHgxMlx4MTJcblxucHJpbWVsZXZlbFx4MThceDAyIFx4MDEoXHJceDEyPlxu"
    "XHgwZnByaXZpbGVnZWlkbGlzdFx4MThceDAzIFx4MDMoXHgwZVx4MzIlLlBsYXllclBlcnNvbmFs"
    "U2hvdy5FUHJpbWVQcml2aWxlZ2VJRFx4MTJceDE1XG5ccm1vbnRobHlwb2ludHNceDE4XHgwNCBc"
    "eDAxKFx4MDVceDEyXHgxNlxuXHgwZVx4NjFubnVhbGx5cG9pbnRzXHgxOFx4MDUgXHgwMShceDA1"
    "XHgxMlx4MTFcblx0c3VtcG9pbnRzXHgxOFx4MDYgXHgwMShceDA1XHgxMlx4MTlcblx4MTFzaGFy"
    "ZWVyZW1haW50aW1lc1x4MThceDA3IFx4MDEoXHJcIlx4YWJceDA0XG5cckF2YXRhclByb2ZpbGVc"
    "eDEyXHgxNVxuXHgwOFx4NjF2YXRhcmlkXHgxOFx4MDEgXHgwMShcckhceDAwXHg4OFx4MDFceDAx"
    "XHgxMlx4MTZcblx0c2tpbmNvbG9yXHgxOFx4MDIgXHgwMShcckhceDAxXHg4OFx4MDFceDAxXHgx"
    "Mlx4MGZcblx4MDdceDYzbG90aGVzXHgxOFx4MDMgXHgwMyhcclx4MTJceDE1XG5ccmVxdWlwZWRz"
    "a2lsbHNceDE4XHgwNCBceDAzKFxyXHgxMlx4MTdcblxuaXNzZWxlY3RlZFx4MThceDA1IFx4MDEo"
    "XHgwOEhceDAyXHg4OFx4MDFceDAxXHgxMlx4MWRcblx4MTBwdmVwcmltYXJ5d2VhcG9uXHgxOFx4"
    "MDYgXHgwMShcckhceDAzXHg4OFx4MDFceDAxXHgxMlx4MWRcblx4MTBpc3NlbGVjdGVkYXdha2Vu"
    "XHgxOFx4MDcgXHgwMShceDA4SFx4MDRceDg4XHgwMVx4MDFceDEyXHgxNFxuXHgwN1x4NjVuZHRp"
    "bWVceDE4XHgwOCBceDAxKFxySFx4MDVceDg4XHgwMVx4MDFceDEyP1xuXG51bmxvY2t0eXBlXHgx"
    "OFx0IFx4MDEoXHgwZVx4MzImLlBsYXllclBlcnNvbmFsU2hvdy5FUHJvZmlsZVVubG9ja1R5cGVI"
    "XHgwNlx4ODhceDAxXHgwMVx4MTJceDE3XG5cbnVubG9ja3RpbWVceDE4XG4gXHgwMShcckhceDA3"
    "XHg4OFx4MDFceDAxXHgxMlx4MTlcblx4MGNpc21hcmtlZHN0YXJceDE4XHgwYiBceDAxKFx4MDhI"
    "XHgwOFx4ODhceDAxXHgwMVx4MTJceDFjXG5ceDE0XHg2M2xvdGhlc3RhaWxvcmVmZmVjdHNceDE4"
    "XHgwYyBceDAzKFxyXHgxMlx4MzRcblx4MGJpdGVtdGFnaW5mb1x4MThcciBceDAzKFx4MGJceDMy"
    "XHgxZi5QbGF5ZXJQZXJzb25hbFNob3cuSXRlbVRhZ0luZm9CXHgwYlxuXHRfYXZhdGFyaWRCXHgw"
    "Y1xuXG5fc2tpbmNvbG9yQlxyXG5ceDBiX2lzc2VsZWN0ZWRCXHgxM1xuXHgxMV9wdmVwcmltYXJ5"
    "d2VhcG9uQlx4MTNcblx4MTFfaXNzZWxlY3RlZGF3YWtlbkJcblxuXHgwOF9lbmR0aW1lQlxyXG5c"
    "eDBiX3VubG9ja3R5cGVCXHJcblx4MGJfdW5sb2NrdGltZUJceDBmXG5ccl9pc21hcmtlZHN0YXJc"
    "InBcblx4MGZceDQxdmF0YXJTa2lsbFNsb3RceDEyXHgwZVxuXHgwNnNsb3RpZFx4MThceDAxIFx4"
    "MDEoXHJceDEyXHgwZlxuXHgwN3NraWxsaWRceDE4XHgwMiBceDAxKFxyXHgxMjxcblx4MGJceDY1"
    "cXVpcHNvdXJjZVx4MThceDAzIFx4MDEoXHgwZVx4MzJcJy5QbGF5ZXJQZXJzb25hbFNob3cuRVBy"
    "b2ZpbGVFcXVpcFNvdXJjZVwiXHg4ZVx4MDFcblx4MGJceDQxXHg2M1x4NjNvdW50TmV3c1x4MTJc"
    "eDMyXG5ceDA0dHlwZVx4MThceDAxIFx4MDEoXHgwZVx4MzIkLlBsYXllclBlcnNvbmFsU2hvdy5F"
    "QWNjb3VudE5ld3NUeXBlXHgxMlx4Mzdcblx4MDdceDYzb250ZW50XHgxOFx4MDIgXHgwMShceDBi"
    "XHgzMiYuUGxheWVyUGVyc29uYWxTaG93LkFjY291bnROZXdzQ29udGVudFx4MTJceDEyXG5cbnVw"
    "ZGF0ZXRpbWVceDE4XHgwMyBceDAxKFx4MDNcIlx4YjdceDAxXG5ceDEyXHg0MVx4NjNceDYzb3Vu"
    "dE5ld3NDb250ZW50XHgxMlx4MGZcblx4MDdpdGVtaWRzXHgxOFx4MDEgXHgwMyhcclx4MTJceDBj"
    "XG5ceDA0cmFua1x4MThceDAyIFx4MDEoXHJceDEyXHgxMVxuXHRtYXRjaG1vZGVceDE4XHgwMyBc"
    "eDAxKFxyXHgxMlxyXG5ceDA1bWFwaWRceDE4XHgwNCBceDAxKFxyXHgxMlx4MTBcblx4MDhnYW1l"
    "bW9kZVx4MThceDA1IFx4MDEoXHJceDEyXHgxMVxuXHRncm91cG1vZGVceDE4XHgwNiBceDAxKFxy"
    "XHgxMlx4MTVcblxydHJlYXN1cmVib3hpZFx4MThceDA3IFx4MDEoXHJceDEyXHgxM1xuXHgwYlx4"
    "NjNvbW1vZGl0eWlkXHgxOFx4MDggXHgwMShcclx4MTJceDBmXG5ceDA3c3RvcmVpZFx4MThcdCBc"
    "eDAxKFxyXCJceDhiXHgwMVxuXHgwYlx4NDJceDYxc2ljRVBJbmZvXHgxMlx4MTFcblx0ZXBldmVu"
    "dGlkXHgxOFx4MDEgXHgwMShcclx4MTJceDExXG5cdG93bmVkcGFzc1x4MThceDAyIFx4MDEoXHgw"
    "OFx4MTJceDBmXG5ceDA3XHg2NXBiYWRnZVx4MThceDAzIFx4MDEoXHJceDEyXHgxMFxuXHgwOFx4"
    "NjJceDYxXHg2NGdlY250XHgxOFx4MDQgXHgwMShcclx4MTJceDBlXG5ceDA2XHg2MnBpY29uXHgx"
    "OFx4MDUgXHgwMShcdFx4MTJceDEwXG5ceDA4bWF4bGV2ZWxceDE4XHgwNiBceDAxKFxyXHgxMlx4"
    "MTFcblx0ZXZlbnRuYW1lXHgxOFx4MDcgXHgwMShcdFwiXHg5MFx4MDFcblxyQ2xhbkluZm9CYXNp"
    "Y1x4MTJceDBlXG5ceDA2XHg2M2xhbmlkXHgxOFx4MDEgXHgwMShceDA0XHgxMlx4MTBcblx4MDhc"
    "eDYzbGFubmFtZVx4MThceDAyIFx4MDEoXHRceDEyXHgxMVxuXHRjYXB0YWluaWRceDE4XHgwMyBc"
    "eDAxKFx4MDRceDEyXHgxMVxuXHRjbGFubGV2ZWxceDE4XHgwNCBceDAxKFxyXHgxMlx4MTBcblx4"
    "MDhceDYzXHg2MXBhY2l0eVx4MThceDA1IFx4MDEoXHJceDEyXHgxMVxuXHRtZW1iZXJudW1ceDE4"
    "XHgwNiBceDAxKFxyXHgxMlx4MTJcblxuaG9ub3Jwb2ludFx4MThceDA3IFx4MDEoXHJcIlx4ZTZc"
    "eDAxXG5ceDA3UGV0SW5mb1x4MTJcblxuXHgwMmlkXHgxOFx4MDEgXHgwMShcclx4MTJceDBjXG5c"
    "eDA0bmFtZVx4MThceDAyIFx4MDEoXHRceDEyXHJcblx4MDVsZXZlbFx4MThceDAzIFx4MDEoXHJc"
    "eDEyXHgwYlxuXHgwM1x4NjV4cFx4MThceDA0IFx4MDEoXHJceDEyXHgxMlxuXG5pc3NlbGVjdGVk"
    "XHgxOFx4MDUgXHgwMShceDA4XHgxMlx4MGVcblx4MDZza2luaWRceDE4XHgwNiBceDAxKFxyXHgx"
    "Mlx4MGZcblx4MDdceDYxXHg2M3Rpb25zXHgxOFx4MDcgXHgwMyhcclx4MTJceDMwXG5ceDA2c2tp"
    "bGxzXHgxOFx4MDggXHgwMyhceDBiXHgzMiAuUGxheWVyUGVyc29uYWxTaG93LlBldFNraWxsSW5m"
    "b1x4MTJceDE3XG5ceDBmc2VsZWN0ZWRza2lsbGlkXHgxOFx0IFx4MDEoXHJceDEyXHgxNFxuXHgw"
    "Y2lzbWFya2Vkc3Rhclx4MThcbiBceDAxKFx4MDhceDEyXHgwZlxuXHgwN1x4NjVuZHRpbWVceDE4"
    "XHgwYiBceDAxKFxyXCJCXG5ceDBjUGV0U2tpbGxJbmZvXHgxMlxyXG5ceDA1cGV0aWRceDE4XHgw"
    "MSBceDAxKFxyXHgxMlx4MGZcblx4MDdza2lsbGlkXHgxOFx4MDIgXHgwMShcclx4MTJceDEyXG5c"
    "bnNraWxsbGV2ZWxceDE4XHgwMyBceDAxKFxyXCJceDgwXHgwNVxuXHgwZlNvY2lhbEJhc2ljSW5m"
    "b1x4MTJceDExXG5cdGFjY291bnRpZFx4MThceDAxIFx4MDEoXHgwNFx4MTJceDMxXG5ceDA2Z2Vu"
    "ZGVyXHgxOFx4MDIgXHgwMShceDBlXHgzMiEuUGxheWVyUGVyc29uYWxTaG93LkVTb2NpYWxHZW5k"
    "ZXJceDEyXHgzNVxuXHgwOGxhbmd1YWdlXHgxOFx4MDMgXHgwMShceDBlXHgzMiMuUGxheWVyUGVy"
    "c29uYWxTaG93LkVTb2NpYWxMYW5ndWFnZVx4MTJceDM5XG5cbnRpbWVvbmxpbmVceDE4XHgwNCBc"
    "eDAxKFx4MGVceDMyJS5QbGF5ZXJQZXJzb25hbFNob3cuRVNvY2lhbFRpbWVPbmxpbmVceDEyXHgz"
    "OVxuXG50aW1lYWN0aXZlXHgxOFx4MDUgXHgwMShceDBlXHgzMiUuUGxheWVyUGVyc29uYWxTaG93"
    "LkVTb2NpYWxUaW1lQWN0aXZlXHgxMj9cblx0YmF0dGxldGFnXHgxOFx4MDYgXHgwMyhceDBlXHgz"
    "MiwuUGxheWVyUGVyc29uYWxTaG93LkVTb2NpYWxQbGF5ZXJCYXR0bGVUYWdJRFx4MTJceDM3XG5c"
    "dHNvY2lhbHRhZ1x4MThceDA3IFx4MDMoXHgwZVx4MzIkLlBsYXllclBlcnNvbmFsU2hvdy5FU29j"
    "aWFsU29jaWFsVGFnXHgxMlx4MzlcblxubW9kZXByZWZlclx4MThceDA4IFx4MDEoXHgwZVx4MzIl"
    "LlBsYXllclBlcnNvbmFsU2hvdy5FU29jaWFsTW9kZVByZWZlclx4MTJceDExXG5cdHNpZ25hdHVy"
    "ZVx4MThcdCBceDAxKFx0XHgxMlx4MzVcblx4MDhyYW5rc2hvd1x4MThcbiBceDAxKFx4MGVceDMy"
    "Iy5QbGF5ZXJQZXJzb25hbFNob3cuRVNvY2lhbFJhbmtTaG93XHgxMlx4MTZcblx4MGVceDYyXHg2"
    "MXR0bGV0YWdjb3VudFx4MThceDBiIFx4MDMoXHJceDEyXHgxZVxuXHgxNnNpZ25hdHVyZWJhbmV4"
    "cGlyZXRpbWVceDE4XHgwYyBceDAxKFx4MDNceDEyXHg0M1xuXHgxMWxlYWRlcmJvYXJkdGl0bGVz"
    "XHgxOFxyIFx4MDEoXHgwYlx4MzIoLlBsYXllclBlcnNvbmFsU2hvdy5MZWFkZXJib2FyZFRpdGxl"
    "SW5mb1wiXHhkOFx4MDJcblx4MTRMZWFkZXJib2FyZFRpdGxlSW5mb1x4MTJceDQ2XG5ceDE0d2Vh"
    "cG9ucG93ZXJ0aXRsZWluZm9ceDE4XHgwMSBceDAzKFx4MGJceDMyKC5QbGF5ZXJQZXJzb25hbFNo"
    "b3cuV2VhcG9uUG93ZXJUaXRsZUluZm9ceDEyQFxuXHgxMWd1aWxkd2FydGl0bGVpbmZvXHgxOFx4"
    "MDIgXHgwMyhceDBiXHgzMiUuUGxheWVyUGVyc29uYWxTaG93Lkd1aWxkV2FyVGl0bGVJbmZvXHgx"
    "Mj5cblx4MTByYW5raW5ndGl0bGVpbmZvXHgxOFx4MDMgXHgwMyhceDBiXHgzMiQuUGxheWVyUGVy"
    "c29uYWxTaG93LlJhbmtpbmdUaXRsZUluZm9ceDEyXHgxOVxuXHgxMXRpdGxlZmlyc3RyZWNlaXZl"
    "XHgxOFx4MDQgXHgwMShceDA4XHgxMjxcblx4MGZceDYzc3BlYWt0aXRsZWluZm9ceDE4XHgwNSBc"
    "eDAzKFx4MGJceDMyIy5QbGF5ZXJQZXJzb25hbFNob3cuQ1NQZWFrVGl0bGVJbmZvXHgxMlx4MWRc"
    "blx4MTVwZWFrdGl0bGVmaXJzdHJlY2VpdmVceDE4XHgwNiBceDAxKFx4MDhcIlx4YmVceDAyXG5c"
    "eDE0V2VhcG9uUG93ZXJUaXRsZUluZm9ceDEyXHgwZVxuXHgwNnJlZ2lvblx4MThceDAxIFx4MDEo"
    "XHRceDEyXHgxMlxuXG50aXRsZWNmZ2lkXHgxOFx4MDIgXHgwMShcclx4MTJceDE1XG5ccmxlYWRl"
    "cmJvYXJkaWRceDE4XHgwMyBceDAxKFx4MDRceDEyXHgxMFxuXHgwOHdlYXBvbmlkXHgxOFx4MDQg"
    "XHgwMShcclx4MTJceDBjXG5ceDA0cmFua1x4MThceDA1IFx4MDEoXHJceDEyXHgxMlxuXG5leHBp"
    "cmV0aW1lXHgxOFx4MDYgXHgwMShceDAzXHgxMlx4MTJcblxucmV3YXJkdGltZVx4MThceDA3IFx4"
    "MDEoXHgwM1x4MTJceDEyXG5cbnJlZ2lvbm5hbWVceDE4XHgwOCBceDAxKFx0XHgxMlx4NDNcblxu"
    "cmVnaW9udHlwZVx4MThcdCBceDAxKFx4MGVceDMyLy5QbGF5ZXJQZXJzb25hbFNob3cuRUxlYWRl"
    "ckJvYXJkVGl0bGVSZWdpb25UeXBlXHgxMlx4MGNcblx4MDRpc2JyXHgxOFxuIFx4MDEoXHgwOFx4"
    "MTI8XG5cdHRpdGxldHlwZVx4MThceDBiIFx4MDEoXHgwZVx4MzIpLlBsYXllclBlcnNvbmFsU2hv"
    "dy5FTGVhZGVyQm9hcmRUaXRsZVR5cGVcIlx4YmFceDAxXG5ceDExR3VpbGRXYXJUaXRsZUluZm9c"
    "eDEyXHgwZVxuXHgwNnJlZ2lvblx4MThceDAxIFx4MDEoXHRceDEyXHgwZVxuXHgwNlx4NjNsYW5p"
    "ZFx4MThceDAyIFx4MDEoXHgwNFx4MTJceDEyXG5cbnRpdGxlY2ZnaWRceDE4XHgwMyBceDAxKFxy"
    "XHgxMlx4MTVcblxybGVhZGVyYm9hcmRpZFx4MThceDA0IFx4MDEoXHgwNFx4MTJceDBjXG5ceDA0"
    "cmFua1x4MThceDA1IFx4MDEoXHJceDEyXHgxMlxuXG5leHBpcmV0aW1lXHgxOFx4MDYgXHgwMShc"
    "eDAzXHgxMlx4MTJcblxucmV3YXJkdGltZVx4MThceDA3IFx4MDEoXHgwM1x4MTJceDEyXG5cbmlz"
    "ZXF1aXBwZWRceDE4XHgwOCBceDAxKFx4MDhceDEyXHgxMFxuXHgwOFx4NjNsYW5uYW1lXHgxOFx0"
    "IFx4MDEoXHRcIlx4ZWFceDAxXG5ceDEwUmFua2luZ1RpdGxlSW5mb1x4MTJceDBlXG5ceDA2cmVn"
    "aW9uXHgxOFx4MDEgXHgwMShcdFx4MTJceDEyXG5cbnRpdGxlY2ZnaWRceDE4XHgwMiBceDAxKFxy"
    "XHgxMlx4MTVcblxybGVhZGVyYm9hcmRpZFx4MThceDAzIFx4MDEoXHgwNFx4MTJceDBjXG5ceDA0"
    "cmFua1x4MThceDA0IFx4MDEoXHJceDEyXHgxMlxuXG5leHBpcmV0aW1lXHgxOFx4MDUgXHgwMShc"
    "eDAzXHgxMlx4MTJcblxucmV3YXJkdGltZVx4MThceDA2IFx4MDEoXHgwM1x4MTJceDEyXG5cbnJl"
    "Z2lvbm5hbWVceDE4XHgwNyBceDAxKFx0XHgxMlx4NDNcblxucmVnaW9udHlwZVx4MThceDA4IFx4"
    "MDEoXHgwZVx4MzIvLlBsYXllclBlcnNvbmFsU2hvdy5FTGVhZGVyQm9hcmRUaXRsZVJlZ2lvblR5"
    "cGVceDEyXHgwY1xuXHgwNGlzYnJceDE4XHQgXHgwMShceDA4XCJceGU5XHgwMVxuXHgwZlx4NDNT"
    "UGVha1RpdGxlSW5mb1x4MTJceDBlXG5ceDA2cmVnaW9uXHgxOFx4MDEgXHgwMShcdFx4MTJceDEy"
    "XG5cbnRpdGxlY2ZnaWRceDE4XHgwMiBceDAxKFxyXHgxMlx4MTVcblxybGVhZGVyYm9hcmRpZFx4"
    "MThceDAzIFx4MDEoXHgwNFx4MTJceDBjXG5ceDA0cmFua1x4MThceDA0IFx4MDEoXHJceDEyXHgx"
    "MlxuXG5leHBpcmV0aW1lXHgxOFx4MDUgXHgwMShceDAzXHgxMlx4MTJcblxucmV3YXJkdGltZVx4"
    "MThceDA2IFx4MDEoXHgwM1x4MTJceDEyXG5cbnJlZ2lvbm5hbWVceDE4XHgwNyBceDAxKFx0XHgx"
    "Mlx4MGNcblx4MDRpc2JyXHgxOFx4MDggXHgwMShceDA4XHgxMlx4NDNcblxucmVnaW9udHlwZVx4"
    "MThcdCBceDAxKFx4MGVceDMyLy5QbGF5ZXJQZXJzb25hbFNob3cuRUxlYWRlckJvYXJkVGl0bGVS"
    "ZWdpb25UeXBlXCIlXG5ceDBlXHg0NGlhbW9uZENvc3RSZXNceDEyXHgxM1xuXHgwYlx4NjRpYW1v"
    "bmRjb3N0XHgxOFx4MDEgXHgwMShcclwiXHhlNlx4MDJcblx4MTRceDQzcmVkaXRTY29yZUluZm9C"
    "YXNpY1x4MTJceDEzXG5ceDBiXHg2M3JlZGl0c2NvcmVceDE4XHgwMSBceDAxKFxyXHgxMlx4MGVc"
    "blx4MDZpc2luaXRceDE4XHgwMiBceDAxKFx4MDhceDEyQFxuXHgwYnJld2FyZHN0YXRlXHgxOFx4"
    "MDMgXHgwMShceDBlXHgzMisuUGxheWVyUGVyc29uYWxTaG93LkVDcmVkaXRTY29yZVJld2FyZFN0"
    "YXRlXHgxMlx4MWVcblx4MTZwZXJpb2RpY3N1bW1hcnlsaWtlY250XHgxOFx4MDQgXHgwMShcclx4"
    "MTIhXG5ceDE5cGVyaW9kaWNzdW1tYXJ5aWxsZWdhbGNudFx4MThceDA1IFx4MDEoXHJceDEyXHgx"
    "NlxuXHgwZXdlZWtseW1hdGNoY250XHgxOFx4MDYgXHgwMShcclx4MTIgXG5ceDE4cGVyaW9kaWNz"
    "dW1tYXJ5c3RhcnR0aW1lXHgxOFx4MDcgXHgwMShceDAzXHgxMlx4MWVcblx4MTZwZXJpb2RpY3N1"
    "bW1hcnllbmR0aW1lXHgxOFx4MDggXHgwMShceDAzXHgxMkpcblx4MTRwZXJpb2RpY3N1bW1hcnls"
    "ZXZlbFx4MThcdCBceDAxKFx4MGVceDMyLC5QbGF5ZXJQZXJzb25hbFNob3cuRUNyZWRpdFNjb3Jl"
    "U3VtbWFyeUxldmVsXCJVXG5ceDBlXHg0MVx4NjNceDYzb3VudE1NUkluZm9ceDEyXHgxMFxuXHgw"
    "OGdhbWVtb2RlXHgxOFx4MDEgXHgwMShcclx4MTJceDBiXG5ceDAzbW1yXHgxOFx4MDIgXHgwMShc"
    "clx4MTJceDEwXG5ceDA4XHg2Mm90cG9pbnRceDE4XHgwMyBceDAxKFxyXHgxMlx4MTJcblxuc3Ry"
    "ZWFrd2luc1x4MThceDA0IFx4MDEoXHJcIkJcblx4MTRNb2RlU3RhdHNTdW1tYXJ5SW5mb1x4MTJc"
    "eDE4XG5ceDEwcmVhY2hlZGhlcm9pY2NudFx4MThceDAxIFx4MDEoXHJceDEyXHgxMFxuXHgwOG1h"
    "eHNjb3JlXHgxOFx4MDIgXHgwMShcclwiRVxuXHgxNFNwYXJrU3RhZ2VBcHBlYXJhbmNlXHgxMlx4"
    "MTBcblx4MDhzdGFnZV9pZFx4MThceDAxIFx4MDEoXHJceDEyXHgxYlxuXHgxM1x4NjFwcGVhcmFu"
    "Y2VfaXRlbV9pZHNceDE4XHgwMiBceDAzKFxyXCJceGNiXHgwMlxuXHRTcGFya0luZm9ceDEyLVxu"
    "XHgwNXN0YXRlXHgxOFx4MDEgXHgwMShceDBlXHgzMlx4MWUuUGxheWVyUGVyc29uYWxTaG93LlNw"
    "YXJrU3RhdGVceDEyXHJcblx4MDVsZXZlbFx4MThceDAyIFx4MDEoXHJceDEyXHgwYlxuXHgwM1x4"
    "NjV4cFx4MThceDAzIFx4MDEoXHgwNFx4MTJceDE5XG5ceDExbG9naW5fc3RyZWFrX2RheXNceDE4"
    "XHgwNCBceDAxKFxyXHgxMlx4MGVcblx4MDZ0ZW1wZXJceDE4XHgwNSBceDAxKFxyXHgxMlx4MWJc"
    "blx4MTNceDYxcHBlYXJhbmNlX2l0ZW1faWRzXHgxOFx4MDYgXHgwMyhcclx4MTIgXG5ceDE4XHg2"
    "NG9ybWFudF9yZWNvdmVyX3Byb2dyZXNzXHgxOFx4MDcgXHgwMShcclx4MTIlXG5ceDFkXHg2NXh0"
    "aW5ndWlzaGVkX3JlY292ZXJfcHJvZ3Jlc3NceDE4XHgwOCBceDAxKFxyXHgxMlx4MThcblx4MTBc"
    "eDYxcHBlYXJhbmNlX3N0YWdlXHgxOFx0IFx4MDEoXHJceDEySFxuXHgxNnN0YWdlX2FwcGVhcmFu"
    "Y2VfaXRlbXNceDE4XG4gXHgwMyhceDBiXHgzMiguUGxheWVyUGVyc29uYWxTaG93LlNwYXJrU3Rh"
    "Z2VBcHBlYXJhbmNlXCJHXG5ceDFmXHg0MVx4NjNceDYzb3VudENvbGxlY3Rpb25DdXN0b21JdGVt"
    "SW5mb1x4MTJceDBmXG5ceDA3aXRlbV9pZFx4MThceDAxIFx4MDEoXHJceDEyXHgxM1xuXHgwYlx4"
    "NjN1c3RvbV9pbmZvXHgxOFx4MDIgXHgwMShcdCpceGU5XG5cblx4MGZceDQzXHg2MWxsU2lnblNy"
    "Y1R5cGVceDEyXHgxNFxuXHgxMFx4NDNceDYxbGxTaWduU3JjX05PTkVceDEwXHgwMFx4MTJceDE3"
    "XG5ceDEzXHg0M1x4NjFsbFNpZ25TcmNfV0lUSE9VVFx4MTBceDAxXHgxMiNcblx4MWZceDQzXHg2"
    "MWxsU2lnblNyY19TRUFSQ0hfQ0hBTVBJT05TSElQXHgxMFx4MDJceDEyXHgxYVxuXHgxNlx4NDNc"
    "eDYxbGxTaWduU3JjX1NFQVJDSF9DVVBceDEwXHgwM1x4MTJceDFkXG5ceDE5XHg0M1x4NjFsbFNp"
    "Z25TcmNfU0VBUkNIX0ZSSUVORFx4MTBceDA0XHgxMlx4MWRcblx4MTlceDQzXHg2MWxsU2lnblNy"
    "Y19TRUFSQ0hfQ0hVTU1ZXHgxMFx4MDVceDEyXHgxOVxuXHgxNVx4NDNceDYxbGxTaWduU3JjX0dB"
    "TUVfT1ZFUlx4MTBceDA2XHgxMlwiXG5ceDFlXHg0M1x4NjFsbFNpZ25TcmNfUEVSU09OQUxfU0hP"
    "V19WSUVXXHgxMFx4MDdceDEyIFxuXHgxY1x4NDNceDYxbGxTaWduU3JjX1BFUlNPTkFMX1NIT1df"
    "RVBceDEwXHgwOFx4MTIjXG5ceDFmXHg0M1x4NjFsbFNpZ25TcmNfUEVSU09OQUxfU0hPV19PV05F"
    "Ulx4MTBcdFx4MTJceDFhXG5ceDE2XHg0M1x4NjFsbFNpZ25TcmNfQlJFSUZfSU5GT1x4MTBcblx4"
    "MTJceDFkXG5ceDE5XHg0M1x4NjFsbFNpZ25TcmNfRlJJRU5EX1JFQ0FMTFx4MTBceDBiXHgxMlx4"
    "MWZcblx4MWJceDQzXHg2MWxsU2lnblNyY19GUklFTkRfUExBVEZPUk1ceDEwXHgwY1x4MTJceDFl"
    "XG5ceDFhXHg0M1x4NjFsbFNpZ25TcmNfRlJJRU5EX1JFUVVFU1RceDEwXHJceDEyXHgxYlxuXHgx"
    "N1x4NDNceDYxbGxTaWduU3JjX0ZSSUVORF9MSVNUXHgxMFx4MGVceDEyXHgxYVxuXHgxNlx4NDNc"
    "eDYxbGxTaWduU3JjX0ZSSUVORF9OVEZceDEwXHgwZlx4MTIgXG5ceDFjXHg0M1x4NjFsbFNpZ25T"
    "cmNfRlJJRU5EX1JFQ09NTUVORFx4MTBceDEwXHgxMlx4MWFcblx4MTZceDQzXHg2MWxsU2lnblNy"
    "Y19GUklFTkRfQ0RUXHgxMFx4MTFceDEyXHgxY1xuXHgxOFx4NDNceDYxbGxTaWduU3JjX0NMQU5f"
    "UkVRVUVTVFx4MTBceDEyXHgxMlx4MWNcblx4MThceDQzXHg2MWxsU2lnblNyY19DTEFOX01FTUJF"
    "UlNceDEwXHgxM1x4MTJceDFiXG5ceDE3XHg0M1x4NjFsbFNpZ25TcmNfQ1VQX1JFUVVFU1RceDEw"
    "XHgxNFx4MTJceDFiXG5ceDE3XHg0M1x4NjFsbFNpZ25TcmNfQ1VQX01FTUJFUlNceDEwXHgxNVx4"
    "MTIkXG4gQ2FsbFNpZ25TcmNfQ0hBTVBJT05TSElQX1JFUVVFU1RceDEwXHgxNlx4MTIkXG4gQ2Fs"
    "bFNpZ25TcmNfQ0hBTVBJT05TSElQX01FTUJFUlNceDEwXHgxN1x4MTIjXG5ceDFmXHg0M1x4NjFs"
    "bFNpZ25TcmNfQ0hBTVBJT05TSElQX1NFQVNPTlx4MTBceDE4XHgxMlx4MWVcblx4MWFceDQzXHg2"
    "MWxsU2lnblNyY19DSFVNTVlfUkVRVUVTVFx4MTBceDE5XHgxMlx4MWJcblx4MTdceDQzXHg2MWxs"
    "U2lnblNyY19DSFVNTVlfTElTVFx4MTBceDFhXHgxMihcbiRDYWxsU2lnblNyY19DSFVNTVlfUkVD"
    "T01NRU5EX1NUVURFTlRceDEwXHgxYlx4MTJcJ1xuI0NhbGxTaWduU3JjX0NIVU1NWV9SRUNPTU1F"
    "TkRfTUVOVE9SXHgxMFx4MWNceDEyI1xuXHgxZlx4NDNceDYxbGxTaWduU3JjX0xFQURFUkJPQVJE"
    "X1BST0ZJTEVceDEwXHgxZFx4MTJcJ1xuI0NhbGxTaWduU3JjX1BPT0xMRUFERVJCT0FSRF9QUk9G"
    "SUxFXHgxMFx4MWVceDEyXHgxZlxuXHgxYlx4NDNceDYxbGxTaWduU3JjX1JFQ0VOVF9WSVNJVE9S"
    "U1x4MTBceDFmXHgxMlwiXG5ceDFlXHg0M1x4NjFsbFNpZ25TcmNfTE9CQllfUE9QVVBfV0lORE9X"
    "XHgxMCBceDEyJVxuIUNhbGxTaWduU3JjX01BVENITUFLSU5HX0JMQUNLTElTVFx4MTAhXHgxMlwi"
    "XG5ceDFlXHg0M1x4NjFsbFNpZ25TcmNfTUFUQ0hNQUtJTkdfU09DSUFMXHgxMFwiXHgxMiBcblx4"
    "MWNceDQzXHg2MWxsU2lnblNyY19NQVRDSF9TUEVDVEFUSU9OXHgxMCNceDEyKFxuJENhbGxTaWdu"
    "U3JjX1NPQ0lBTF9URUFNX1VQX1JFQ09NTUVORFx4MTAkXHgxMiVcbiFDYWxsU2lnblNyY19DTEFO"
    "X0lOVklURV9TVFJBTkdFUlNceDEwJVx4MTIgXG5ceDFjXHg0M1x4NjFsbFNpZ25TcmNfU0VORF9H"
    "SUZUX05PVElGWVx4MTAmXHgxMlx4MWRcblx4MTlceDQzXHg2MWxsU2lnblNyY19QTEFZRVJfTkVB"
    "UkJZXHgxMFwnXHgxMiZcblwiQ2FsbFNpZ25TcmNfRlJFU0hfUExBWUVSX1JFQ09NTUVORFx4MTAo"
    "Klx4YTZceDAxXG5ceDFiXHg0NVx4NDF0dGVuZGFuY2VWZXRlcmFuTGVhdmVEYXlzXHgxMlx4MThc"
    "blx4MTRWRVRFUkFOTEVBVkVEQVlTTk9ORVx4MTBceDAwXHgxMlx4MTlcblx4MTVWRVRFUkFOTEVB"
    "VkVEQVlTU0hPUlRceDEwXHgwMVx4MTJceDFhXG5ceDE2VkVURVJBTkxFQVZFREFZU05PUk1BTFx4"
    "MTBceDAyXHgxMlx4MThcblx4MTRWRVRFUkFOTEVBVkVEQVlTTE9OR1x4MTBceDAzXHgxMlx4MWNc"
    "blx4MThWRVRFUkFOTEVBVkVEQVlTVkVSWUxPTkdceDEwXHgwNCpceDdmXG5ceDFmXHg0NVx4NDF0"
    "dGVuZGFuY2VQcmVWZXRlcmFuQWN0aW9uVHlwZVx4MTJceDFjXG5ceDE4UFJFVkVURVJBTkFDVElP"
    "TlRZUEVOT05FXHgxMFx4MDBceDEyIFxuXHgxY1BSRVZFVEVSQU5BQ1RJT05UWVBFQUNUSVZJVFlc"
    "eDEwXHgwMVx4MTJceDFjXG5ceDE4UFJFVkVURVJBTkFDVElPTlRZUEVCVUZGXHgxMFx4MDIqdVxu"
    "XHgxYVx4NDVceDQxXHg2M1x4NjNvdW50RXh0ZXJuYWxJY29uU3RhdHVzXHgxMlx4MWFcblx4MTZc"
    "eDQ1WFRFUk5BTElDT05TVEFUVVNOT05FXHgxMFx4MDBceDEyXHgxZVxuXHgxYVx4NDVYVEVSTkFM"
    "SUNPTlNUQVRVU05PVElOVVNFXHgxMFx4MDFceDEyXHgxYlxuXHgxN1x4NDVYVEVSTkFMSUNPTlNU"
    "QVRVU0lOVVNFXHgxMFx4MDIqeVxuXHgxY1x4NDVceDQxXHg2M1x4NjNvdW50RXh0ZXJuYWxJY29u"
    "U2hvd1R5cGVceDEyXHgxY1xuXHgxOFx4NDVYVEVSTkFMSUNPTlNIT1dUWVBFTk9ORVx4MTBceDAw"
    "XHgxMlx4MWVcblx4MWFceDQ1WFRFUk5BTElDT05TSE9XVFlQRUZSSUVORFx4MTBceDAxXHgxMlx4"
    "MWJcblx4MTdceDQ1WFRFUk5BTElDT05TSE9XVFlQRUFMTFx4MTBceDAyKlx4OGJceDAzXG5ceDEw"
    "XHg0NVNvY2lhbEhpZ2hMaWdodFx4MTJceDExXG5cckhJR0hMSUdIVE5PTkVceDEwXHgwMFx4MTJc"
    "eDEyXG5ceDBlSElHSExJR0hUQlJXSU5ceDEwXHgwMVx4MTJceDEyXG5ceDBlSElHSExJR0hUQ1NN"
    "VlBceDEwXHgwMlx4MTJceDE4XG5ceDE0SElHSExJR0hUQlJTVFJFQUtXSU5ceDEwXHgwM1x4MTJc"
    "eDE4XG5ceDE0SElHSExJR0hUQ1NTVFJFQUtXSU5ceDEwXHgwNFx4MTJceDFmXG5ceDFiSElHSExJ"
    "R0hUQ1NSQU5LR1JPVVBVUEdSQURFXHgxMFx4MDVceDEyXHgxNFxuXHgxMEhJR0hMSUdIVFRFQU1B"
    "Q0VceDEwXHgwNlx4MTJceDFkXG5ceDE5SElHSExJR0hUV0VBUE9OUE9XRVJUSVRMRVx4MTBceDA3"
    "XHgxMlx4MWZcblx4MWJISUdITElHSFRCUlJBTktHUk9VUFVQR1JBREVceDEwXHRceDEyXCJcblx4"
    "MWVISUdITElHSFRCUlNUUkVBS1dJTkVYRUNFTExFTlRceDEwXG5ceDEyXCJcblx4MWVISUdITElH"
    "SFRDU1NUUkVBS1dJTkVYRUNFTExFTlRceDEwXHgwYlx4MTJceDE0XG5ceDEwSElHSExJR0hUVkVU"
    "RVJBTlx4MTBceDBjXHgxMlx4MTlcblx4MTVISUdITElHSFRSQU5LSU5HVElUTEVceDEwXHJceDEy"
    "XHgxOFxuXHgxNEhJR0hMSUdIVENTUEVBS1RJVExFXHgxMFx4MGUqTFxuXHRCYWRnZVR5cGVceDEy"
    "XHgxOFxuXHgxNFx4NDJceDQxXHg0NEdFVFlQRVVOU1BFQ0lGSUVEXHgxMFx4MDBceDEyXHgxMVxu"
    "XHJCQURHRVRZUEVST0xFXHgxMFx4MDFceDEyXHgxMlxuXHgwZVx4NDJceDQxXHg0NEdFVFlQRVBS"
    "SU1FXHgxMFx4MDIqXHhlZlx4MDRcblx4MTFceDQ1UHJpbWVQcml2aWxlZ2VJRFx4MTJceDEzXG5c"
    "eDBmUFJJVklMRUdFSUROT05FXHgxMFx4MDBceDEyXHgxNFxuXHgxMFBSSVZJTEVHRUlEQkFER0Vc"
    "eDEwXHgwMVx4MTJceDFhXG5ceDE2UFJJVklMRUdFSURQUk9GSUxFU0tJTlx4MTBceDAyXHgxMlx4"
    "MTlcblx4MTVQUklWSUxFR0VJRFBST0ZJTEVBTklceDEwXHgwM1x4MTJceDFjXG5ceDE4UFJJVklM"
    "RUdFSURJTlRFUkZBQ0VTS0lOXHgxMFx4MDRceDEyXHgxN1xuXHgxM1BSSVZJTEVHRUlEU0VUU0hB"
    "UkVceDEwXHgwNVx4MTJceDFhXG5ceDE2UFJJVklMRUdFSURBVkFUQVJGUkFNRVx4MTBceDA2XHgx"
    "Mlx4MThcblx4MTRQUklWSUxFR0VJRE5BTUVDT0xPUlx4MTBceDA3XHgxMlx4MTdcblx4MTNQUklW"
    "SUxFR0VJREZFU1RJVkFMXHgxMFx4MDhceDEyXHgxOFxuXHgxNFBSSVZJTEVHRUlEQklHU0NSRUVO"
    "XHgxMFx0XHgxMiNcblx4MWZQUklWSUxFR0VJRE1BVENITUFLSU5HQkxBQ0tMSVNUXHgxMFxuXHgx"
    "Mlx4MTVcblx4MTFQUklWSUxFR0VJREFERFNFVFx4MTBceDBiXHgxMlx4MThcblx4MTRQUklWSUxF"
    "R0VJREFEREZSSUVORFx4MTBceDBjXHgxMlx4MWNcblx4MThQUklWSUxFR0VJREVYQ0xVU0lWRVNI"
    "T1BceDEwXHJceDEyXHgxZFxuXHgxOVBSSVZJTEVHRUlERVhDTFVTSVZFR0FDSEFceDEwXHgwZVx4"
    "MTJceDE0XG5ceDEwUFJJVklMRUdFSURFTU9URVx4MTBceDBmXHgxMlx4MWNcblx4MThQUklWSUxF"
    "R0VJREFWQVRBUkJBTk5FUjFceDEwXHgxMFx4MTJceDFjXG5ceDE4UFJJVklMRUdFSURBVkFUQVJC"
    "QU5ORVIyXHgxMFx4MTFceDEyXHgxY1xuXHgxOFBSSVZJTEVHRUlEQVZBVEFSQkFOTkVSM1x4MTBc"
    "eDEyXHgxMlx4MTdcblx4MTNQUklWSUxFR0VJREdMT09XQUxMXHgxMFx4MTNceDEyXHgxZlxuXHgx"
    "YlBSSVZJTEVHRUlEUFJJTUVMRUFERVJCT0FSRFx4MTBceDE0XHgxMlx4MWJcblx4MTdQUklWSUxF"
    "R0VJRFBST0ZJTEVCQURHRVx4MTBceDE1Kkpcblx4MTNceDQ1UHJvZmlsZUVxdWlwU291cmNlXHgx"
    "Mlx4MTNcblx4MGZceDQ1UVVJUFNPVVJDRVNFTEZceDEwXHgwMFx4MTJceDFlXG5ceDFhXHg0NVFV"
    "SVBTT1VSQ0VDT05GSURBTlRGUklFTkRceDEwXHgwMSo8XG5ceDEyXHg0NVByb2ZpbGVVbmxvY2tU"
    "eXBlXHgxMlx4MTJcblx4MGVVTkxPQ0tUWVBFTk9ORVx4MTBceDAwXHgxMlx4MTJcblx4MGVVTkxP"
    "Q0tUWVBFTElOS1x4MTBceDAxKldcblxyRVNvY2lhbEdlbmRlclx4MTJceDBlXG5cbkdFTkRFUk5P"
    "TkVceDEwXHgwMFx4MTJceDBlXG5cbkdFTkRFUk1BTEVceDEwXHgwMVx4MTJceDEwXG5ceDBjR0VO"
    "REVSRkVNQUxFXHgxMFx4MDJceDEyXHgxNFxuXHgwZkdFTkRFUlVOTElNSVRFRFx4MTBceGU3XHgw"
    "NypceGY3XHgwM1xuXHgwZlx4NDVTb2NpYWxMYW5ndWFnZVx4MTJceDEwXG5ceDBjTEFOR1VBR0VO"
    "T05FXHgxMFx4MDBceDEyXHgwZVxuXG5MQU5HVUFHRUVOXHgxMFx4MDFceDEyXHgxOFxuXHgxNExB"
    "TkdVQUdFQ05TSU1QTElGSUVEXHgxMFx4MDJceDEyXHgxOVxuXHgxNUxBTkdVQUdFQ05UUkFESVRJ"
    "T05BTFx4MTBceDAzXHgxMlx4MTBcblx4MGNMQU5HVUFHRVRIQUlceDEwXHgwNFx4MTJceDE2XG5c"
    "eDEyTEFOR1VBR0VWSUVUTkFNRVNFXHgxMFx4MDVceDEyXHgxNlxuXHgxMkxBTkdVQUdFSU5ET05F"
    "U0lBTlx4MTBceDA2XHgxMlx4MTZcblx4MTJMQU5HVUFHRVBPUlRVR1VFU0VceDEwXHgwN1x4MTJc"
    "eDEzXG5ceDBmTEFOR1VBR0VTUEFOSVNIXHgxMFx4MDhceDEyXHgxM1xuXHgwZkxBTkdVQUdFUlVT"
    "U0lBTlx4MTBcdFx4MTJceDEyXG5ceDBlTEFOR1VBR0VLT1JFQU5ceDEwXG5ceDEyXHgxMlxuXHgw"
    "ZUxBTkdVQUdFRlJFTkNIXHgxMFx4MGJceDEyXHgxMlxuXHgwZUxBTkdVQUdFR0VSTUFOXHgxMFx4"
    "MGNceDEyXHgxM1xuXHgwZkxBTkdVQUdFVFVSS0lTSFx4MTBcclx4MTJceDExXG5cckxBTkdVQUdF"
    "SElORElceDEwXHgwZVx4MTJceDE0XG5ceDEwTEFOR1VBR0VKQVBBTkVTRVx4MTBceDBmXHgxMlx4"
    "MTRcblx4MTBMQU5HVUFHRVJPTUFOSUFOXHgxMFx4MTBceDEyXHgxMlxuXHgwZUxBTkdVQUdFQVJB"
    "QklDXHgxMFx4MTFceDEyXHgxM1xuXHgwZkxBTkdVQUdFQlVSTUVTRVx4MTBceDEyXHgxMlx4MTBc"
    "blx4MGNMQU5HVUFHRVVSRFVceDEwXHgxM1x4MTJceDEzXG5ceDBmTEFOR1VBR0VCRU5HQUxJXHgx"
    "MFx4MTRceDEyXHgxMVxuXHJMQU5HVUFHRU1BTEFZXHgxMFx4MTVceDEyXHgxNlxuXHgxMUxBTkdV"
    "QUdFVU5MSU1JVEVEXHgxMFx4ZTdceDA3Km9cblx4MTFceDQ1U29jaWFsVGltZU9ubGluZVx4MTJc"
    "eDEyXG5ceDBlVElNRU9OTElORU5PTkVceDEwXHgwMFx4MTJceDE1XG5ceDExVElNRU9OTElORVdP"
    "UktEQVlceDEwXHgwMVx4MTJceDE1XG5ceDExVElNRU9OTElORVdFRUtFTkRceDEwXHgwMlx4MTJc"
    "eDE4XG5ceDEzVElNRU9OTElORVVOTElNSVRFRFx4MTBceGU3XHgwNypceDg2XHgwMVxuXHgxMVx4"
    "NDVTb2NpYWxUaW1lQWN0aXZlXHgxMlx4MTJcblx4MGVUSU1FQUNUSVZFTk9ORVx4MTBceDAwXHgx"
    "Mlx4MTVcblx4MTFUSU1FQUNUSVZFTU9STklOR1x4MTBceDAxXHgxMlx4MTdcblx4MTNUSU1FQUNU"
    "SVZFQUZURVJOT09OXHgxMFx4MDJceDEyXHgxM1xuXHgwZlRJTUVBQ1RJVkVOSUdIVFx4MTBceDAz"
    "XHgxMlx4MThcblx4MTNUSU1FQUNUSVZFVU5MSU1JVEVEXHgxMFx4ZTdceDA3Klx4ZjJceDAyXG5c"
    "eDE4XHg0NVNvY2lhbFBsYXllckJhdHRsZVRhZ0lEXHgxMlx4MTlcblx4MTVQTEFZRVJCQVRUTEVU"
    "QUdJRE5PTkVceDEwXHgwMFx4MTIgXG5ceDFiUExBWUVSQkFUVExFVEFHSURET01JTkFUSU9OXHgx"
    "MFx4Y2RceDA4XHgxMlx4MWRcblx4MThQTEFZRVJCQVRUTEVUQUdJRFVOQ1JPV05ceDEwXHhjZVx4"
    "MDhceDEyIVxuXHgxY1BMQVlFUkJBVFRMRVRBR0lEQkVTVFBBUlRORVJceDEwXHhjZlx4MDhceDEy"
    "XHgxY1xuXHgxN1BMQVlFUkJBVFRMRVRBR0lEU05JUEVSXHgxMFx4ZDBceDA4XHgxMlx4MWJcblx4"
    "MTZQTEFZRVJCQVRUTEVUQUdJRE1FTEVFXHgxMFx4ZDFceDA4XHgxMiBcblx4MWJQTEFZRVJCQVRU"
    "TEVUQUdJRFBFQUNFTUFLRVJceDEwXHhkMlx4MDhceDEyXHgxY1xuXHgxN1BMQVlFUkJBVFRMRVRB"
    "R0lEQU1CVVNIXHgxMFx4ZDNceDA4XHgxMlx4MWZcblx4MWFQTEFZRVJCQVRUTEVUQUdJRFNIT1JU"
    "U1RPUFx4MTBceGQ0XHgwOFx4MTJceDFkXG5ceDE4UExBWUVSQkFUVExFVEFHSURSQU1QQUdFXHgx"
    "MFx4ZDVceDA4XHgxMlx4MWNcblx4MTdQTEFZRVJCQVRUTEVUQUdJRExFQURFUlx4MTBceGQ2XHgw"
    "OCpceGUyXHgwMVxuXHgxMFx4NDVTb2NpYWxTb2NpYWxUYWdceDEyXHgxMVxuXHJTT0NJQUxUQUdO"
    "T05FXHgxMFx4MDBceDEyXHgxNVxuXHgxMFNPQ0lBTFRBR0ZBU0hJT05ceDEwXHhiNVx4MTBceDEy"
    "XHgxNFxuXHgwZlNPQ0lBTFRBR1NPQ0lBTFx4MTBceGI2XHgxMFx4MTJceDE1XG5ceDEwU09DSUFM"
    "VEFHVkVURVJBTlx4MTBceGI3XHgxMFx4MTJceDE0XG5ceDBmU09DSUFMVEFHTkVXQklFXHgxMFx4"
    "YjhceDEwXHgxMlx4MThcblx4MTNTT0NJQUxUQUdQTEFZRk9SV0lOXHgxMFx4YjlceDEwXHgxMlx4"
    "MThcblx4MTNTT0NJQUxUQUdQTEFZRk9SRlVOXHgxMFx4YmFceDEwXHgxMlx4MTVcblx4MTBTT0NJ"
    "QUxUQUdWT0lDRU9OXHgxMFx4YmJceDEwXHgxMlx4MTZcblx4MTFTT0NJQUxUQUdWT0lDRU9GRlx4"
    "MTBceGJjXHgxMCpceDgyXHgwMVxuXHgxMVx4NDVTb2NpYWxNb2RlUHJlZmVyXHgxMlx4MTJcblx4"
    "MGVNT0RFUFJFRkVSTk9ORVx4MTBceDAwXHgxMlx4MTBcblx4MGNNT0RFUFJFRkVSQlJceDEwXHgw"
    "MVx4MTJceDEwXG5ceDBjTU9ERVBSRUZFUkNTXHgxMFx4MDJceDEyXHgxYlxuXHgxN01PREVQUkVG"
    "RVJFTlRFUlRBSU5NRU5UXHgxMFx4MDNceDEyXHgxOFxuXHgxM01PREVQUkVGRVJVTkxJTUlURURc"
    "eDEwXHhlN1x4MDcqW1xuXHgwZlx4NDVTb2NpYWxSYW5rU2hvd1x4MTJceDEwXG5ceDBjUkFOS1NI"
    "T1dOT05FXHgxMFx4MDBceDEyXHgwZVxuXG5SQU5LU0hPV0JSXHgxMFx4MDFceDEyXHgwZVxuXG5S"
    "QU5LU0hPV0NTXHgxMFx4MDJceDEyXHgxNlxuXHgxMVJBTktTSE9XVU5MSU1JVEVEXHgxMFx4ZTdc"
    "eDA3Klx4ZGFceDAxXG5ceDFiXHg0NUxlYWRlckJvYXJkVGl0bGVSZWdpb25UeXBlXHgxMlwiXG5c"
    "eDFlTEVBREVSQk9BUkRUSVRMRVJFR0lPTlRZUEVOT05FXHgxMFx4MDBceDEyJVxuIUxFQURFUkJP"
    "QVJEVElUTEVSRUdJT05UWVBFQ09VTlRSWVx4MTBceDAxXHgxMiZcblwiTEVBREVSQk9BUkRUSVRM"
    "RVJFR0lPTlRZUEVQUk9WSU5DRVx4MTBceDAyXHgxMlwiXG5ceDFlTEVBREVSQk9BUkRUSVRMRVJF"
    "R0lPTlRZUEVDSVRZXHgxMFx4MDNceDEyJFxuIExFQURFUkJPQVJEVElUTEVSRUdJT05UWVBFUkVH"
    "SU9OXHgxMFx4MDQqXHhkMlx4MDJcblx4MTVceDQ1TGVhZGVyQm9hcmRUaXRsZVR5cGVceDEyXHgx"
    "Y1xuXHgxOExFQURFUkJPQVJEVElUTEVUWVBFTk9ORVx4MTBceDAwXHgxMiVcbiFMRUFERVJCT0FS"
    "RFRJVExFVFlQRVdFQVBPTlBPV0VSQlJceDEwXHgwMVx4MTIlXG4hTEVBREVSQk9BUkRUSVRMRVRZ"
    "UEVXRUFQT05QT1dFUkNTXHgxMFx4MDJceDEyXHgxZlxuXHgxYkxFQURFUkJPQVJEVElUTEVUWVBF"
    "Q0xBTldBUlx4MTBceDAzXHgxMlx4MWVcblx4MWFMRUFERVJCT0FSRFRJVExFVFlQRVJBTktCUlx4"
    "MTBceDA0XHgxMlx4MWVcblx4MWFMRUFERVJCT0FSRFRJVExFVFlQRVJBTktDU1x4MTBceDA1XHgx"
    "Mlx4MWVcblx4MWFMRUFERVJCT0FSRFRJVExFVFlQRVBFQUtDU1x4MTBceDA2XHgxMiVcbiFMRUFE"
    "RVJCT0FSRFRJVExFVFlQRUdSQU5ETUFTVEVSQlJceDEwXHg2M1x4MTIlXG4hTEVBREVSQk9BUkRU"
    "SVRMRVRZUEVHUkFORE1BU1RFUkNTXHgxMFx4NjQqY1xuXHgxN1x4NDVceDQzcmVkaXRTY29yZVJl"
    "d2FyZFN0YXRlXHgxMlx4MTZcblx4MTJSRVdBUkRTVEFURUlOVkFMSURceDEwXHgwMFx4MTJceDE4"
    "XG5ceDE0UkVXQVJEU1RBVEVVTkNMQUlNRURceDEwXHgwMVx4MTJceDE2XG5ceDEyUkVXQVJEU1RB"
    "VEVDTEFJTUVEXHgxMFx4MDIqXHg3ZlxuXHgxOFx4NDVceDQzcmVkaXRTY29yZVN1bW1hcnlMZXZl"
    "bFx4MTJceDE3XG5ceDEzU1VNTUFSWUxFVkVMTk9USU5JVFx4MTBceDAwXHgxMlx4MTFcblxyU1VN"
    "TUFSWUxFVkVMQVx4MTBceDAxXHgxMlx4MTFcblxyU1VNTUFSWUxFVkVMQlx4MTBceDAyXHgxMlx4"
    "MTFcblxyU1VNTUFSWUxFVkVMQ1x4MTBceDAzXHgxMlx4MTFcblxyU1VNTUFSWUxFVkVMRFx4MTBc"
    "eDA0Klx4ZjhceDAxXG5ceDEwXHg0NVx4NDFceDYzXHg2M291bnROZXdzVHlwZVx4MTJceDEwXG5c"
    "eDBjTkVXU1RZUEVOT05FXHgxMFx4MDBceDEyXHgxMFxuXHgwY05FV1NUWVBFUkFOS1x4MTBceDAx"
    "XHgxMlx4MTNcblx4MGZORVdTVFlQRUxPVFRFUllceDEwXHgwMlx4MTJceDE0XG5ceDEwTkVXU1RZ"
    "UEVQVVJDSEFTRVx4MTBceDAzXHgxMlx4MTdcblx4MTNORVdTVFlQRVRSRUFTVVJFQk9YXHgxMFx4"
    "MDRceDEyXHgxNVxuXHgxMU5FV1NUWVBFRUxJVEVQQVNTXHgxMFx4MDVceDEyXHgxOVxuXHgxNU5F"
    "V1NUWVBFRVhDSEFOR0VTVE9SRVx4MTBceDA2XHgxMlx4MTJcblx4MGVORVdTVFlQRUJVTkRMRVx4"
    "MTBceDA3XHgxMlwiXG5ceDFlTkVXU1RZUEVMT1RURVJZU1BFQ0lBTEVYQ0hBTkdFXHgxMFx4MDhc"
    "eDEyXHgxMlxuXHgwZU5FV1NUWVBFT1RIRVJTXHgxMFx0Km1cblxuU3BhcmtTdGF0ZVx4MTJceDEz"
    "XG5ceDBmU3BhcmtTdGF0ZV9OT05FXHgxMFx4MDBceDEyXHgxNVxuXHgxMVNwYXJrU3RhdGVfQUNU"
    "SVZFXHgxMFx4MDFceDEyXHgxNlxuXHgxMlNwYXJrU3RhdGVfRE9STUFOVFx4MTBceDAyXHgxMlx4"
    "MWJcblx4MTdTcGFya1N0YXRlX0VYVElOR1VJU0hFRFx4MTBceDAzXHg2Mlx4MDZwcm90bzMnKQ0K"
    "DQpfZ2xvYmFscyA9IGdsb2JhbHMoKQ0KX2J1aWxkZXIuQnVpbGRNZXNzYWdlQW5kRW51bURlc2Ny"
    "aXB0b3JzKERFU0NSSVBUT1IsIF9nbG9iYWxzKQ0KX2J1aWxkZXIuQnVpbGRUb3BEZXNjcmlwdG9y"
    "c0FuZE1lc3NhZ2VzKERFU0NSSVBUT1IsICdQbGF5ZXJQZXJzb25hbFNob3dfcGIyJywgX2dsb2Jh"
    "bHMpDQppZiBub3QgX2Rlc2NyaXB0b3IuX1VTRV9DX0RFU0NSSVBUT1JTOg0KICBERVNDUklQVE9S"
    "Ll9sb2FkZWRfb3B0aW9ucyA9IE5vbmUNCiAgX2dsb2JhbHNbJ19DQUxMU0lHTlNSQ1RZUEUnXS5f"
    "c2VyaWFsaXplZF9zdGFydD0xMDA4MQ0KICBfZ2xvYmFsc1snX0NBTExTSUdOU1JDVFlQRSddLl9z"
    "ZXJpYWxpemVkX2VuZD0xMTQ2Ng0KICBfZ2xvYmFsc1snX0VBVFRFTkRBTkNFVkVURVJBTkxFQVZF"
    "REFZUyddLl9zZXJpYWxpemVkX3N0YXJ0PTExNDY5DQogIF9nbG9iYWxzWydfRUFUVEVOREFOQ0VW"
    "RVRFUkFOTEVBVkVEQVlTJ10uX3NlcmlhbGl6ZWRfZW5kPTExNjM1DQogIF9nbG9iYWxzWydfRUFU"
    "VEVOREFOQ0VQUkVWRVRFUkFOQUNUSU9OVFlQRSddLl9zZXJpYWxpemVkX3N0YXJ0PTExNjM3DQog"
    "IF9nbG9iYWxzWydfRUFUVEVOREFOQ0VQUkVWRVRFUkFOQUNUSU9OVFlQRSddLl9zZXJpYWxpemVk"
    "X2VuZD0xMTc2NA0KICBfZ2xvYmFsc1snX0VBQ0NPVU5URVhURVJOQUxJQ09OU1RBVFVTJ10uX3Nl"
    "cmlhbGl6ZWRfc3RhcnQ9MTE3NjYNCiAgX2dsb2JhbHNbJ19FQUNDT1VOVEVYVEVSTkFMSUNPTlNU"
    "QVRVUyddLl9zZXJpYWxpemVkX2VuZD0xMTg4Mw0KICBfZ2xvYmFsc1snX0VBQ0NPVU5URVhURVJO"
    "QUxJQ09OU0hPV1RZUEUnXS5fc2VyaWFsaXplZF9zdGFydD0xMTg4NQ0KICBfZ2xvYmFsc1snX0VB"
    "Q0NPVU5URVhURVJOQUxJQ09OU0hPV1RZUEUnXS5fc2VyaWFsaXplZF9lbmQ9MTIwMDYNCiAgX2ds"
    "b2JhbHNbJ19FU09DSUFMSElHSExJR0hUJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MTIwMDkNCiAgX2ds"
    "b2JhbHNbJ19FU09DSUFMSElHSExJR0hUJ10uX3NlcmlhbGl6ZWRfZW5kPTEyNDA0DQogIF9nbG9i"
    "YWxzWydfQkFER0VUWVBFJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MTI0MDYNCiAgX2dsb2JhbHNbJ19C"
    "QURHRVRZUEUnXS5fc2VyaWFsaXplZF9lbmQ9MTI0ODINCiAgX2dsb2JhbHNbJ19FUFJJTUVQUklW"
    "SUxFR0VJRCddLl9zZXJpYWxpemVkX3N0YXJ0PTEyNDg1DQogIF9nbG9iYWxzWydfRVBSSU1FUFJJ"
    "VklMRUdFSUQnXS5fc2VyaWFsaXplZF9lbmQ9MTMxMDgNCiAgX2dsb2JhbHNbJ19FUFJPRklMRUVR"
    "VUlQU09VUkNFJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MTMxMTANCiAgX2dsb2JhbHNbJ19FUFJPRklM"
    "RUVRVUlQU09VUkNFJ10uX3NlcmlhbGl6ZWRfZW5kPTEzMTg0DQogIF9nbG9iYWxzWydfRVBST0ZJ"
    "TEVVTkxPQ0tUWVBFJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MTMxODYNCiAgX2dsb2JhbHNbJ19FUFJP"
    "RklMRVVOTE9DS1RZUEUnXS5fc2VyaWFsaXplZF9lbmQ9MTMyNDYNCiAgX2dsb2JhbHNbJ19FU09D"
    "SUFMR0VOREVSJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MTMyNDgNCiAgX2dsb2JhbHNbJ19FU09DSUFM"
    "R0VOREVSJ10uX3NlcmlhbGl6ZWRfZW5kPTEzMzM1DQogIF9nbG9iYWxzWydfRVNPQ0lBTExBTkdV"
    "QUdFJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MTMzMzgNCiAgX2dsb2JhbHNbJ19FU09DSUFMTEFOR1VB"
    "R0UnXS5fc2VyaWFsaXplZF9lbmQ9MTM4NDENCiAgX2dsb2JhbHNbJ19FU09DSUFMVElNRU9OTElO"
    "RSddLl9zZXJpYWxpemVkX3N0YXJ0PTEzODQzDQogIF9nbG9iYWxzWydfRVNPQ0lBTFRJTUVPTkxJ"
    "TkUnXS5fc2VyaWFsaXplZF9lbmQ9MTM5NTQNCiAgX2dsb2JhbHNbJ19FU09DSUFMVElNRUFDVElW"
    "RSddLl9zZXJpYWxpemVkX3N0YXJ0PTEzOTU3DQogIF9nbG9iYWxzWydfRVNPQ0lBTFRJTUVBQ1RJ"
    "VkUnXS5fc2VyaWFsaXplZF9lbmQ9MTQwOTENCiAgX2dsb2JhbHNbJ19FU09DSUFMUExBWUVSQkFU"
    "VExFVEFHSUQnXS5fc2VyaWFsaXplZF9zdGFydD0xNDA5NA0KICBfZ2xvYmFsc1snX0VTT0NJQUxQ"
    "TEFZRVJCQVRUTEVUQUdJRCddLl9zZXJpYWxpemVkX2VuZD0xNDQ2NA0KICBfZ2xvYmFsc1snX0VT"
    "T0NJQUxTT0NJQUxUQUcnXS5fc2VyaWFsaXplZF9zdGFydD0xNDQ2Nw0KICBfZ2xvYmFsc1snX0VT"
    "T0NJQUxTT0NJQUxUQUcnXS5fc2VyaWFsaXplZF9lbmQ9MTQ2OTMNCiAgX2dsb2JhbHNbJ19FU09D"
    "SUFMTU9ERVBSRUZFUiddLl9zZXJpYWxpemVkX3N0YXJ0PTE0Njk2DQogIF9nbG9iYWxzWydfRVNP"
    "Q0lBTE1PREVQUkVGRVInXS5fc2VyaWFsaXplZF9lbmQ9MTQ4MjYNCiAgX2dsb2JhbHNbJ19FU09D"
    "SUFMUkFOS1NIT1cnXS5fc2VyaWFsaXplZF9zdGFydD0xNDgyOA0KICBfZ2xvYmFsc1snX0VTT0NJ"
    "QUxSQU5LU0hPVyddLl9zZXJpYWxpemVkX2VuZD0xNDkxOQ0KICBfZ2xvYmFsc1snX0VMRUFERVJC"
    "T0FSRFRJVExFUkVHSU9OVFlQRSddLl9zZXJpYWxpemVkX3N0YXJ0PTE0OTIyDQogIF9nbG9iYWxz"
    "WydfRUxFQURFUkJPQVJEVElUTEVSRUdJT05UWVBFJ10uX3NlcmlhbGl6ZWRfZW5kPTE1MTQwDQog"
    "IF9nbG9iYWxzWydfRUxFQURFUkJPQVJEVElUTEVUWVBFJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MTUx"
    "NDMNCiAgX2dsb2JhbHNbJ19FTEVBREVSQk9BUkRUSVRMRVRZUEUnXS5fc2VyaWFsaXplZF9lbmQ9"
    "MTU0ODENCiAgX2dsb2JhbHNbJ19FQ1JFRElUU0NPUkVSRVdBUkRTVEFURSddLl9zZXJpYWxpemVk"
    "X3N0YXJ0PTE1NDgzDQogIF9nbG9iYWxzWydfRUNSRURJVFNDT1JFUkVXQVJEU1RBVEUnXS5fc2Vy"
    "aWFsaXplZF9lbmQ9MTU1ODINCiAgX2dsb2JhbHNbJ19FQ1JFRElUU0NPUkVTVU1NQVJZTEVWRUwn"
    "XS5fc2VyaWFsaXplZF9zdGFydD0xNTU4NA0KICBfZ2xvYmFsc1snX0VDUkVESVRTQ09SRVNVTU1B"
    "UllMRVZFTCddLl9zZXJpYWxpemVkX2VuZD0xNTcxMQ0KICBfZ2xvYmFsc1snX0VBQ0NPVU5UTkVX"
    "U1RZUEUnXS5fc2VyaWFsaXplZF9zdGFydD0xNTcxNA0KICBfZ2xvYmFsc1snX0VBQ0NPVU5UTkVX"
    "U1RZUEUnXS5fc2VyaWFsaXplZF9lbmQ9MTU5NjINCiAgX2dsb2JhbHNbJ19TUEFSS1NUQVRFJ10u"
    "X3NlcmlhbGl6ZWRfc3RhcnQ9MTU5NjQNCiAgX2dsb2JhbHNbJ19TUEFSS1NUQVRFJ10uX3Nlcmlh"
    "bGl6ZWRfZW5kPTE2MDczDQogIF9nbG9iYWxzWydfUkVRVUVTVCddLl9zZXJpYWxpemVkX3N0YXJ0"
    "PTQ5DQogIF9nbG9iYWxzWydfUkVRVUVTVCddLl9zZXJpYWxpemVkX2VuZD0yNzcNCiAgX2dsb2Jh"
    "bHNbJ19SRVNQT05TRSddLl9zZXJpYWxpemVkX3N0YXJ0PTI4MA0KICBfZ2xvYmFsc1snX1JFU1BP"
    "TlNFJ10uX3NlcmlhbGl6ZWRfZW5kPTEyOTANCiAgX2dsb2JhbHNbJ19BQ0NPVU5USU5GT0JBU0lD"
    "J10uX3NlcmlhbGl6ZWRfc3RhcnQ9MTI5Mw0KICBfZ2xvYmFsc1snX0FDQ09VTlRJTkZPQkFTSUMn"
    "XS5fc2VyaWFsaXplZF9lbmQ9MzczNQ0KICBfZ2xvYmFsc1snX0FDQ09VTlRCQVNJQ1NQQVJLSU5G"
    "TyddLl9zZXJpYWxpemVkX3N0YXJ0PTM3MzcNCiAgX2dsb2JhbHNbJ19BQ0NPVU5UQkFTSUNTUEFS"
    "S0lORk8nXS5fc2VyaWFsaXplZF9lbmQ9MzgzMw0KICBfZ2xvYmFsc1snX1dPUktTSE9QQUNDT1VO"
    "VFNVTU1BUllJTkZPJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MzgzNQ0KICBfZ2xvYmFsc1snX1dPUktT"
    "SE9QQUNDT1VOVFNVTU1BUllJTkZPJ10uX3NlcmlhbGl6ZWRfZW5kPTM4OTYNCiAgX2dsb2JhbHNb"
    "J19CTEFDS0xJU1RSRVMnXS5fc2VyaWFsaXplZF9zdGFydD0zODk5DQogIF9nbG9iYWxzWydfQkxB"
    "Q0tMSVNUUkVTJ10uX3NlcmlhbGl6ZWRfZW5kPTQwODkNCiAgX2dsb2JhbHNbJ19BQ0NPVU5UUFJF"
    "RkVSUyddLl9zZXJpYWxpemVkX3N0YXJ0PTQwOTINCiAgX2dsb2JhbHNbJ19BQ0NPVU5UUFJFRkVS"
    "UyddLl9zZXJpYWxpemVkX2VuZD00MzA2DQogIF9nbG9iYWxzWydfRVhURVJOQUxJQ09OSU5GTydd"
    "Ll9zZXJpYWxpemVkX3N0YXJ0PTQzMDkNCiAgX2dsb2JhbHNbJ19FWFRFUk5BTElDT05JTkZPJ10u"
    "X3NlcmlhbGl6ZWRfZW5kPTQ0ODENCiAgX2dsb2JhbHNbJ19PQ0NVUEFUSU9OU0VBU09OSU5GTydd"
    "Ll9zZXJpYWxpemVkX3N0YXJ0PTQ0ODQNCiAgX2dsb2JhbHNbJ19PQ0NVUEFUSU9OU0VBU09OSU5G"
    "TyddLl9zZXJpYWxpemVkX2VuZD00NjMwDQogIF9nbG9iYWxzWydfT0NDVVBBVElPTklORk8nXS5f"
    "c2VyaWFsaXplZF9zdGFydD00NjMyDQogIF9nbG9iYWxzWydfT0NDVVBBVElPTklORk8nXS5fc2Vy"
    "aWFsaXplZF9lbmQ9NDc0Nw0KICBfZ2xvYmFsc1snX1NPQ0lBTEhJR0hMSUdIVFNXSVRIU09DSUFM"
    "QkFTSUNJTkZPJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9NDc1MA0KICBfZ2xvYmFsc1snX1NPQ0lBTEhJ"
    "R0hMSUdIVFNXSVRIU09DSUFMQkFTSUNJTkZPJ10uX3NlcmlhbGl6ZWRfZW5kPTQ5MTINCiAgX2ds"
    "b2JhbHNbJ19TT0NJQUxISUdITElHSFQnXS5fc2VyaWFsaXplZF9zdGFydD00OTE0DQogIF9nbG9i"
    "YWxzWydfU09DSUFMSElHSExJR0hUJ10uX3NlcmlhbGl6ZWRfZW5kPTUwMjENCiAgX2dsb2JhbHNb"
    "J19BQlRFU1RDSE9JQ0UnXS5fc2VyaWFsaXplZF9zdGFydD01MDIzDQogIF9nbG9iYWxzWydfQUJU"
    "RVNUQ0hPSUNFJ10uX3NlcmlhbGl6ZWRfZW5kPTUwNjQNCiAgX2dsb2JhbHNbJ19JVEVNVEFHSU5G"
    "TyddLl9zZXJpYWxpemVkX3N0YXJ0PTUwNjYNCiAgX2dsb2JhbHNbJ19JVEVNVEFHSU5GTyddLl9z"
    "ZXJpYWxpemVkX2VuZD01MTI4DQogIF9nbG9iYWxzWydfTU9ERVNUQVRTSU5GTyddLl9zZXJpYWxp"
    "emVkX3N0YXJ0PTUxMzANCiAgX2dsb2JhbHNbJ19NT0RFU1RBVFNJTkZPJ10uX3NlcmlhbGl6ZWRf"
    "ZW5kPTUxNzgNCiAgX2dsb2JhbHNbJ19CQURHRUlORk8nXS5fc2VyaWFsaXplZF9zdGFydD01MTgw"
    "DQogIF9nbG9iYWxzWydfQkFER0VJTkZPJ10uX3NlcmlhbGl6ZWRfZW5kPTUyNTgNCiAgX2dsb2Jh"
    "bHNbJ19QUklNRVBSSVZJTEVHRURFVEFJTCddLl9zZXJpYWxpemVkX3N0YXJ0PTUyNjENCiAgX2ds"
    "b2JhbHNbJ19QUklNRVBSSVZJTEVHRURFVEFJTCddLl9zZXJpYWxpemVkX2VuZD01NDc5DQogIF9n"
    "bG9iYWxzWydfQVZBVEFSUFJPRklMRSddLl9zZXJpYWxpemVkX3N0YXJ0PTU0ODINCiAgX2dsb2Jh"
    "bHNbJ19BVkFUQVJQUk9GSUxFJ10uX3NlcmlhbGl6ZWRfZW5kPTYwMzcNCiAgX2dsb2JhbHNbJ19B"
    "VkFUQVJTS0lMTFNMT1QnXS5fc2VyaWFsaXplZF9zdGFydD02MDM5DQogIF9nbG9iYWxzWydfQVZB"
    "VEFSU0tJTExTTE9UJ10uX3NlcmlhbGl6ZWRfZW5kPTYxNTENCiAgX2dsb2JhbHNbJ19BQ0NPVU5U"
    "TkVXUyddLl9zZXJpYWxpemVkX3N0YXJ0PTYxNTQNCiAgX2dsb2JhbHNbJ19BQ0NPVU5UTkVXUydd"
    "Ll9zZXJpYWxpemVkX2VuZD02Mjk2DQogIF9nbG9iYWxzWydfQUNDT1VOVE5FV1NDT05URU5UJ10u"
    "X3NlcmlhbGl6ZWRfc3RhcnQ9NjI5OQ0KICBfZ2xvYmFsc1snX0FDQ09VTlRORVdTQ09OVEVOVCdd"
    "Ll9zZXJpYWxpemVkX2VuZD02NDgyDQogIF9nbG9iYWxzWydfQkFTSUNFUElORk8nXS5fc2VyaWFs"
    "aXplZF9zdGFydD02NDg1DQogIF9nbG9iYWxzWydfQkFTSUNFUElORk8nXS5fc2VyaWFsaXplZF9l"
    "bmQ9NjYyNA0KICBfZ2xvYmFsc1snX0NMQU5JTkZPQkFTSUMnXS5fc2VyaWFsaXplZF9zdGFydD02"
    "NjI3DQogIF9nbG9iYWxzWydfQ0xBTklORk9CQVNJQyddLl9zZXJpYWxpemVkX2VuZD02NzcxDQog"
    "IF9nbG9iYWxzWydfUEVUSU5GTyddLl9zZXJpYWxpemVkX3N0YXJ0PTY3NzQNCiAgX2dsb2JhbHNb"
    "J19QRVRJTkZPJ10uX3NlcmlhbGl6ZWRfZW5kPTcwMDQNCiAgX2dsb2JhbHNbJ19QRVRTS0lMTElO"
    "Rk8nXS5fc2VyaWFsaXplZF9zdGFydD03MDA2DQogIF9nbG9iYWxzWydfUEVUU0tJTExJTkZPJ10u"
    "X3NlcmlhbGl6ZWRfZW5kPTcwNzINCiAgX2dsb2JhbHNbJ19TT0NJQUxCQVNJQ0lORk8nXS5fc2Vy"
    "aWFsaXplZF9zdGFydD03MDc1DQogIF9nbG9iYWxzWydfU09DSUFMQkFTSUNJTkZPJ10uX3Nlcmlh"
    "bGl6ZWRfZW5kPTc3MTUNCiAgX2dsb2JhbHNbJ19MRUFERVJCT0FSRFRJVExFSU5GTyddLl9zZXJp"
    "YWxpemVkX3N0YXJ0PTc3MTgNCiAgX2dsb2JhbHNbJ19MRUFERVJCT0FSRFRJVExFSU5GTyddLl9z"
    "ZXJpYWxpemVkX2VuZD04MDYyDQogIF9nbG9iYWxzWydfV0VBUE9OUE9XRVJUSVRMRUlORk8nXS5f"
    "c2VyaWFsaXplZF9zdGFydD04MDY1DQogIF9nbG9iYWxzWydfV0VBUE9OUE9XRVJUSVRMRUlORk8n"
    "XS5fc2VyaWFsaXplZF9lbmQ9ODM4Mw0KICBfZ2xvYmFsc1snX0dVSUxEV0FSVElUTEVJTkZPJ10u"
    "X3NlcmlhbGl6ZWRfc3RhcnQ9ODM4Ng0KICBfZ2xvYmFsc1snX0dVSUxEV0FSVElUTEVJTkZPJ10u"
    "X3NlcmlhbGl6ZWRfZW5kPTg1NzINCiAgX2dsb2JhbHNbJ19SQU5LSU5HVElUTEVJTkZPJ10uX3Nl"
    "cmlhbGl6ZWRfc3RhcnQ9ODU3NQ0KICBfZ2xvYmFsc1snX1JBTktJTkdUSVRMRUlORk8nXS5fc2Vy"
    "aWFsaXplZF9lbmQ9ODgwOQ0KICBfZ2xvYmFsc1snX0NTUEVBS1RJVExFSU5GTyddLl9zZXJpYWxp"
    "emVkX3N0YXJ0PTg4MTINCiAgX2dsb2JhbHNbJ19DU1BFQUtUSVRMRUlORk8nXS5fc2VyaWFsaXpl"
    "ZF9lbmQ9OTA0NQ0KICBfZ2xvYmFsc1snX0RJQU1PTkRDT1NUUkVTJ10uX3NlcmlhbGl6ZWRfc3Rh"
    "cnQ9OTA0Nw0KICBfZ2xvYmFsc1snX0RJQU1PTkRDT1NUUkVTJ10uX3NlcmlhbGl6ZWRfZW5kPTkw"
    "ODQNCiAgX2dsb2JhbHNbJ19DUkVESVRTQ09SRUlORk9CQVNJQyddLl9zZXJpYWxpemVkX3N0YXJ0"
    "PTkwODcNCiAgX2dsb2JhbHNbJ19DUkVESVRTQ09SRUlORk9CQVNJQyddLl9zZXJpYWxpemVkX2Vu"
    "ZD05NDQ1DQogIF9nbG9iYWxzWydfQUNDT1VOVE1NUklORk8nXS5fc2VyaWFsaXplZF9zdGFydD05"
    "NDQ3DQogIF9nbG9iYWxzWydfQUNDT1VOVE1NUklORk8nXS5fc2VyaWFsaXplZF9lbmQ9OTUzMg0K"
    "ICBfZ2xvYmFsc1snX01PREVTVEFUU1NVTU1BUllJTkZPJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9OTUz"
    "NA0KICBfZ2xvYmFsc1snX01PREVTVEFUU1NVTU1BUllJTkZPJ10uX3NlcmlhbGl6ZWRfZW5kPTk2"
    "MDANCiAgX2dsb2JhbHNbJ19TUEFSS1NUQUdFQVBQRUFSQU5DRSddLl9zZXJpYWxpemVkX3N0YXJ0"
    "PTk2MDINCiAgX2dsb2JhbHNbJ19TUEFSS1NUQUdFQVBQRUFSQU5DRSddLl9zZXJpYWxpemVkX2Vu"
    "ZD05NjcxDQogIF9nbG9iYWxzWydfU1BBUktJTkZPJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9OTY3NA0K"
    "ICBfZ2xvYmFsc1snX1NQQVJLSU5GTyddLl9zZXJpYWxpemVkX2VuZD0xMDAwNQ0KICBfZ2xvYmFs"
    "c1snX0FDQ09VTlRDT0xMRUNUSU9OQ1VTVE9NSVRFTUlORk8nXS5fc2VyaWFsaXplZF9zdGFydD0x"
    "MDAwNw0KICBfZ2xvYmFsc1snX0FDQ09VTlRDT0xMRUNUSU9OQ1VTVE9NSVRFTUlORk8nXS5fc2Vy"
    "aWFsaXplZF9lbmQ9MTAwNzgNCiMgQEBwcm90b2NfaW5zZXJ0aW9uX3BvaW50KG1vZHVsZV9zY29w"
    "ZSkNCg=="
  ),
  "PlayerStats_pb2": (
    "IyAtKi0gY29kaW5nOiB1dGYtOCAtKi0NCiMgR2VuZXJhdGVkIGJ5IHRoZSBwcm90b2NvbCBidWZm"
    "ZXIgY29tcGlsZXIuICBETyBOT1QgRURJVCENCiMgTk8gQ0hFQ0tFRC1JTiBQUk9UT0JVRiBHRU5D"
    "T0RFDQojIHNvdXJjZTogUGxheWVyU3RhdHMucHJvdG8NCiMgUHJvdG9idWYgUHl0aG9uIFZlcnNp"
    "b246IDYuMzMuMQ0KIiIiR2VuZXJhdGVkIHByb3RvY29sIGJ1ZmZlciBjb2RlLiIiIg0KZnJvbSBn"
    "b29nbGUucHJvdG9idWYgaW1wb3J0IGRlc2NyaXB0b3IgYXMgX2Rlc2NyaXB0b3INCmZyb20gZ29v"
    "Z2xlLnByb3RvYnVmIGltcG9ydCBkZXNjcmlwdG9yX3Bvb2wgYXMgX2Rlc2NyaXB0b3JfcG9vbA0K"
    "ZnJvbSBnb29nbGUucHJvdG9idWYgaW1wb3J0IHJ1bnRpbWVfdmVyc2lvbiBhcyBfcnVudGltZV92"
    "ZXJzaW9uDQpmcm9tIGdvb2dsZS5wcm90b2J1ZiBpbXBvcnQgc3ltYm9sX2RhdGFiYXNlIGFzIF9z"
    "eW1ib2xfZGF0YWJhc2UNCmZyb20gZ29vZ2xlLnByb3RvYnVmLmludGVybmFsIGltcG9ydCBidWls"
    "ZGVyIGFzIF9idWlsZGVyDQpfcnVudGltZV92ZXJzaW9uLlZhbGlkYXRlUHJvdG9idWZSdW50aW1l"
    "VmVyc2lvbigNCiAgICBfcnVudGltZV92ZXJzaW9uLkRvbWFpbi5QVUJMSUMsDQogICAgNiwNCiAg"
    "ICAzMywNCiAgICAxLA0KICAgICcnLA0KICAgICdQbGF5ZXJTdGF0cy5wcm90bycNCikNCiMgQEBw"
    "cm90b2NfaW5zZXJ0aW9uX3BvaW50KGltcG9ydHMpDQoNCl9zeW1fZGIgPSBfc3ltYm9sX2RhdGFi"
    "YXNlLkRlZmF1bHQoKQ0KDQoNCg0KDQpERVNDUklQVE9SID0gX2Rlc2NyaXB0b3JfcG9vbC5EZWZh"
    "dWx0KCkuQWRkU2VyaWFsaXplZEZpbGUoYidcblx4MTFQbGF5ZXJTdGF0cy5wcm90b1x4MTJceDBi"
    "UGxheWVyU3RhdHNcIi9cblx4MDdyZXF1ZXN0XHgxMlx4MTFcblx0YWNjb3VudGlkXHgxOFx4MDEg"
    "XHgwMShceDA0XHgxMlx4MTFcblx0bWF0Y2htb2RlXHgxOFx4MDIgXHgwMShcclwiXHhjM1x4MDFc"
    "blx4MDhyZXNwb25zZVx4MTI8XG5cdHNvbG9zdGF0c1x4MThceDAxIFx4MDEoXHgwYlx4MzIpLlBs"
    "YXllclN0YXRzLkFjY291bnRJbmZvV2l0aFN0YXRzVG9DbGllbnRceDEyO1xuXHgwOFx4NjR1b3N0"
    "YXRzXHgxOFx4MDIgXHgwMShceDBiXHgzMikuUGxheWVyU3RhdHMuQWNjb3VudEluZm9XaXRoU3Rh"
    "dHNUb0NsaWVudFx4MTI8XG5cdHF1YWRzdGF0c1x4MThceDAzIFx4MDEoXHgwYlx4MzIpLlBsYXll"
    "clN0YXRzLkFjY291bnRJbmZvV2l0aFN0YXRzVG9DbGllbnRcIlx4OWNceDAxXG5ceDFjXHg0MVx4"
    "NjNceDYzb3VudEluZm9XaXRoU3RhdHNUb0NsaWVudFx4MTJceDExXG5cdGFjY291bnRpZFx4MThc"
    "eDAxIFx4MDEoXHgwNFx4MTJceDEzXG5ceDBiZ2FtZXNwbGF5ZWRceDE4XHgwMiBceDAxKFxyXHgx"
    "Mlx4MGNcblx4MDR3aW5zXHgxOFx4MDMgXHgwMShcclx4MTJcclxuXHgwNWtpbGxzXHgxOFx4MDQg"
    "XHgwMShcclx4MTJceDM3XG5ccmRldGFpbGVkc3RhdHNceDE4XHgwNSBceDAxKFx4MGJceDMyIC5Q"
    "bGF5ZXJTdGF0cy5QbGF5ZXJEZXRhaWxlZFN0YXRzXCJceDg2XHgwM1xuXHgxM1BsYXllckRldGFp"
    "bGVkU3RhdHNceDEyXHgwZVxuXHgwNlx4NjRceDY1XHg2MXRoc1x4MThceDAxIFx4MDEoXHJceDEy"
    "XHgxM1xuXHgwYnRvcDEwX3RpbWVzXHgxOFx4MDIgXHgwMShcclx4MTJceDEzXG5ceDBidG9wX25f"
    "dGltZXNceDE4XHgwMyBceDAxKFxyXHgxMlx4MWFcblx4MTJceDY0aXN0YW5jZV90cmF2ZWxsZWRc"
    "eDE4XHgwNCBceDAxKFxyXHgxMlx4MTVcblxyc3Vydml2YWxfdGltZVx4MThceDA1IFx4MDEoXHJc"
    "eDEyXHgwZlxuXHgwN3Jldml2ZXNceDE4XHgwNiBceDAxKFxyXHgxMlx4MTVcblxyaGlnaGVzdF9r"
    "aWxsc1x4MThceDA3IFx4MDEoXHJceDEyXHgwZVxuXHgwNlx4NjRceDYxbWFnZVx4MThceDA4IFx4"
    "MDEoXHJceDEyXHgxMlxuXG5yb2FkX2tpbGxzXHgxOFx0IFx4MDEoXHJceDEyXHgxMVxuXHRoZWFk"
    "c2hvdHNceDE4XG4gXHgwMShcclx4MTJceDE2XG5ceDBlaGVhZHNob3Rfa2lsbHNceDE4XHgwYiBc"
    "eDAxKFxyXHgxMlx4MTJcblxua25vY2tfZG93blx4MThceDBjIFx4MDEoXHJceDEyXHgxMFxuXHgw"
    "OHBpY2tfdXBzXHgxOFxyIFx4MDEoXHJceDEyXHgxNVxuXHJyYXRpbmdfcG9pbnRzXHgxOFx4MGUg"
    "XHgwMShceDAxXHgxMlx4MWNcblx4MTRyYXRpbmdfZW5hYmxlZF9nYW1lc1x4MThceDBmIFx4MDEo"
    "XHJceDEyXHgxNlxuXHgwZWdvbGRfbWVkYWxfY250XHgxOFx4MTAgXHgwMShcclx4MTJceDE4XG5c"
    "eDEwc2lsdmVyX21lZGFsX2NudFx4MThceDExIFx4MDEoXHJiXHgwNnByb3RvMycpDQoNCl9nbG9i"
    "YWxzID0gZ2xvYmFscygpDQpfYnVpbGRlci5CdWlsZE1lc3NhZ2VBbmRFbnVtRGVzY3JpcHRvcnMo"
    "REVTQ1JJUFRPUiwgX2dsb2JhbHMpDQpfYnVpbGRlci5CdWlsZFRvcERlc2NyaXB0b3JzQW5kTWVz"
    "c2FnZXMoREVTQ1JJUFRPUiwgJ1BsYXllclN0YXRzX3BiMicsIF9nbG9iYWxzKQ0KaWYgbm90IF9k"
    "ZXNjcmlwdG9yLl9VU0VfQ19ERVNDUklQVE9SUzoNCiAgREVTQ1JJUFRPUi5fbG9hZGVkX29wdGlv"
    "bnMgPSBOb25lDQogIF9nbG9iYWxzWydfUkVRVUVTVCddLl9zZXJpYWxpemVkX3N0YXJ0PTM0DQog"
    "IF9nbG9iYWxzWydfUkVRVUVTVCddLl9zZXJpYWxpemVkX2VuZD04MQ0KICBfZ2xvYmFsc1snX1JF"
    "U1BPTlNFJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9ODQNCiAgX2dsb2JhbHNbJ19SRVNQT05TRSddLl9z"
    "ZXJpYWxpemVkX2VuZD0yNzkNCiAgX2dsb2JhbHNbJ19BQ0NPVU5USU5GT1dJVEhTVEFUU1RPQ0xJ"
    "RU5UJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9MjgyDQogIF9nbG9iYWxzWydfQUNDT1VOVElORk9XSVRI"
    "U1RBVFNUT0NMSUVOVCddLl9zZXJpYWxpemVkX2VuZD00MzgNCiAgX2dsb2JhbHNbJ19QTEFZRVJE"
    "RVRBSUxFRFNUQVRTJ10uX3NlcmlhbGl6ZWRfc3RhcnQ9NDQxDQogIF9nbG9iYWxzWydfUExBWUVS"
    "REVUQUlMRURTVEFUUyddLl9zZXJpYWxpemVkX2VuZD04MzENCiMgQEBwcm90b2NfaW5zZXJ0aW9u"
    "X3BvaW50KG1vZHVsZV9zY29wZSkNCg=="
  ),
  "PlayerCSStats_pb2": (
    "IyAtKi0gY29kaW5nOiB1dGYtOCAtKi0NCiMgR2VuZXJhdGVkIGJ5IHRoZSBwcm90b2NvbCBidWZm"
    "ZXIgY29tcGlsZXIuICBETyBOT1QgRURJVCENCiMgTk8gQ0hFQ0tFRC1JTiBQUk9UT0JVRiBHRU5D"
    "T0RFDQojIHNvdXJjZTogUGxheWVyQ1NTdGF0cy5wcm90bw0KIyBQcm90b2J1ZiBQeXRob24gVmVy"
    "c2lvbjogNi4zMy4xDQoiIiJHZW5lcmF0ZWQgcHJvdG9jb2wgYnVmZmVyIGNvZGUuIiIiDQpmcm9t"
    "IGdvb2dsZS5wcm90b2J1ZiBpbXBvcnQgZGVzY3JpcHRvciBhcyBfZGVzY3JpcHRvcg0KZnJvbSBn"
    "b29nbGUucHJvdG9idWYgaW1wb3J0IGRlc2NyaXB0b3JfcG9vbCBhcyBfZGVzY3JpcHRvcl9wb29s"
    "DQpmcm9tIGdvb2dsZS5wcm90b2J1ZiBpbXBvcnQgcnVudGltZV92ZXJzaW9uIGFzIF9ydW50aW1l"
    "X3ZlcnNpb24NCmZyb20gZ29vZ2xlLnByb3RvYnVmIGltcG9ydCBzeW1ib2xfZGF0YWJhc2UgYXMg"
    "X3N5bWJvbF9kYXRhYmFzZQ0KZnJvbSBnb29nbGUucHJvdG9idWYuaW50ZXJuYWwgaW1wb3J0IGJ1"
    "aWxkZXIgYXMgX2J1aWxkZXINCl9ydW50aW1lX3ZlcnNpb24uVmFsaWRhdGVQcm90b2J1ZlJ1bnRp"
    "bWVWZXJzaW9uKA0KICAgIF9ydW50aW1lX3ZlcnNpb24uRG9tYWluLlBVQkxJQywNCiAgICA2LA0K"
    "ICAgIDMzLA0KICAgIDEsDQogICAgJycsDQogICAgJ1BsYXllckNTU3RhdHMucHJvdG8nDQopDQoj"
    "IEBAcHJvdG9jX2luc2VydGlvbl9wb2ludChpbXBvcnRzKQ0KDQpfc3ltX2RiID0gX3N5bWJvbF9k"
    "YXRhYmFzZS5EZWZhdWx0KCkNCg0KDQoNCg0KREVTQ1JJUFRPUiA9IF9kZXNjcmlwdG9yX3Bvb2wu"
    "RGVmYXVsdCgpLkFkZFNlcmlhbGl6ZWRGaWxlKGInXG5ceDEzUGxheWVyQ1NTdGF0cy5wcm90b1x4"
    "MTJcclBsYXllckNTU3RhdHNcIlNcblx4MDdyZXF1ZXN0XHgxMlx4MTFcblx0YWNjb3VudGlkXHgx"
    "OFx4MDEgXHgwMShceDA0XHgxMlx4MTBcblx4MDhzZWFzb25pZFx4MThceDAyIFx4MDEoXHJceDEy"
    "XHgxMFxuXHgwOGdhbWVtb2RlXHgxOFx4MDMgXHgwMShcclx4MTJceDExXG5cdG1hdGNobW9kZVx4"
    "MThceDA0IFx4MDEoXHJcIkJcblx4MDhyZXNwb25zZVx4MTJceDM2XG5ceDA3XHg2M3NzdGF0c1x4"
    "MThceDAxIFx4MDEoXHgwYlx4MzIlLlBsYXllckNTU3RhdHMuQWNjb3VudEluZm9XaXRoVENTdGF0"
    "c1wiXHg5NFx4MDFcblx4MTZceDQxXHg2M1x4NjNvdW50SW5mb1dpdGhUQ1N0YXRzXHgxMlx4MTFc"
    "blx0YWNjb3VudGlkXHgxOFx4MDEgXHgwMShceDA0XHgxMlx4MTNcblx4MGJnYW1lc3BsYXllZFx4"
    "MThceDAyIFx4MDEoXHJceDEyXHgwY1xuXHgwNHdpbnNceDE4XHgwMyBceDAxKFxyXHgxMlxyXG5c"
    "eDA1a2lsbHNceDE4XHgwNCBceDAxKFxyXHgxMlx4MzVcblxyZGV0YWlsZWRzdGF0c1x4MThceDA1"
    "IFx4MDEoXHgwYlx4MzJceDFlLlBsYXllckNTU3RhdHMuRGV0YWlsZWRUQ1N0YXRzXCJceGNmXHgw"
    "M1xuXHgwZlx4NDRceDY1dGFpbGVkVENTdGF0c1x4MTJceDExXG5cdG12cF9jb3VudFx4MThceDAx"
    "IFx4MDEoXHJceDEyXHgxNFxuXHgwY1x4NjRvdWJsZV9raWxsc1x4MThceDAyIFx4MDEoXHJceDEy"
    "XHgxNFxuXHgwY3RyaXBsZV9raWxsc1x4MThceDAzIFx4MDEoXHJceDEyXHgxMlxuXG5mb3VyX2tp"
    "bGxzXHgxOFx4MDQgXHgwMShcclx4MTJceDBlXG5ceDA2XHg2NFx4NjFtYWdlXHgxOFx4MDUgXHgw"
    "MShcclx4MTJceDE3XG5ceDBmaGVhZF9zaG90X2tpbGxzXHgxOFx4MDYgXHgwMShcclx4MTJceDEz"
    "XG5ceDBia25vY2tfZG93bnNceDE4XHgwNyBceDAxKFxyXHgxMlx4MTBcblx4MDhyZXZpdmFsc1x4"
    "MThceDA4IFx4MDEoXHJceDEyXHgwZlxuXHgwN1x4NjFzc2lzdHNceDE4XHQgXHgwMShcclx4MTJc"
    "eDBlXG5ceDA2XHg2NFx4NjVceDYxdGhzXHgxOFxuIFx4MDEoXHJceDEyXHgxM1xuXHgwYnN0cmVh"
    "a193aW5zXHgxOFx4MGIgXHgwMShcclx4MTJceDE2XG5ceDBldGhyb3dpbmdfa2lsbHNceDE4XHgw"
    "YyBceDAxKFxyXHgxMlx4MWNcblx4MTRvbmVfZ2FtZV9tb3N0X2RhbWFnZVx4MThcciBceDAxKFxy"
    "XHgxMlx4MWJcblx4MTNvbmVfZ2FtZV9tb3N0X2tpbGxzXHgxOFx4MGUgXHgwMShcclx4MTJceDE1"
    "XG5ccnJhdGluZ19wb2ludHNceDE4XHgwZiBceDAxKFx4MDFceDEyXHgxY1xuXHgxNHJhdGluZ19l"
    "bmFibGVkX2dhbWVzXHgxOFx4MTAgXHgwMShcclx4MTJceDE2XG5ceDBlaGVhZHNob3RfY291bnRc"
    "eDE4XHgxMSBceDAxKFxyXHgxMlx4MTFcblx0aGl0X2NvdW50XHgxOFx4MTIgXHgwMShcclx4MTJc"
    "eDE2XG5ceDBlZ29sZF9tZWRhbF9jbnRceDE4XHgxMyBceDAxKFxyXHgxMlx4MThcblx4MTBzaWx2"
    "ZXJfbWVkYWxfY250XHgxOFx4MTQgXHgwMShccmJceDA2cHJvdG8zJykNCg0KX2dsb2JhbHMgPSBn"
    "bG9iYWxzKCkNCl9idWlsZGVyLkJ1aWxkTWVzc2FnZUFuZEVudW1EZXNjcmlwdG9ycyhERVNDUklQ"
    "VE9SLCBfZ2xvYmFscykNCl9idWlsZGVyLkJ1aWxkVG9wRGVzY3JpcHRvcnNBbmRNZXNzYWdlcyhE"
    "RVNDUklQVE9SLCAnUGxheWVyQ1NTdGF0c19wYjInLCBfZ2xvYmFscykNCmlmIG5vdCBfZGVzY3Jp"
    "cHRvci5fVVNFX0NfREVTQ1JJUFRPUlM6DQogIERFU0NSSVBUT1IuX2xvYWRlZF9vcHRpb25zID0g"
    "Tm9uZQ0KICBfZ2xvYmFsc1snX1JFUVVFU1QnXS5fc2VyaWFsaXplZF9zdGFydD0zOA0KICBfZ2xv"
    "YmFsc1snX1JFUVVFU1QnXS5fc2VyaWFsaXplZF9lbmQ9MTIxDQogIF9nbG9iYWxzWydfUkVTUE9O"
    "U0UnXS5fc2VyaWFsaXplZF9zdGFydD0xMjMNCiAgX2dsb2JhbHNbJ19SRVNQT05TRSddLl9zZXJp"
    "YWxpemVkX2VuZD0xODkNCiAgX2dsb2JhbHNbJ19BQ0NPVU5USU5GT1dJVEhUQ1NUQVRTJ10uX3Nl"
    "cmlhbGl6ZWRfc3RhcnQ9MTkyDQogIF9nbG9iYWxzWydfQUNDT1VOVElORk9XSVRIVENTVEFUUydd"
    "Ll9zZXJpYWxpemVkX2VuZD0zNDANCiAgX2dsb2JhbHNbJ19ERVRBSUxFRFRDU1RBVFMnXS5fc2Vy"
    "aWFsaXplZF9zdGFydD0zNDMNCiAgX2dsb2JhbHNbJ19ERVRBSUxFRFRDU1RBVFMnXS5fc2VyaWFs"
    "aXplZF9lbmQ9ODA2DQojIEBAcHJvdG9jX2luc2VydGlvbl9wb2ludChtb2R1bGVfc2NvcGUpDQo="
  ),
  "SearchAccountByName_pb2": (
    "IyAtKi0gY29kaW5nOiB1dGYtOCAtKi0NCiMgR2VuZXJhdGVkIGJ5IHRoZSBwcm90b2NvbCBidWZm"
    "ZXIgY29tcGlsZXIuICBETyBOT1QgRURJVCENCiMgTk8gQ0hFQ0tFRC1JTiBQUk9UT0JVRiBHRU5D"
    "T0RFDQojIHNvdXJjZTogU2VhcmNoQWNjb3VudEJ5TmFtZS5wcm90bw0KIyBQcm90b2J1ZiBQeXRo"
    "b24gVmVyc2lvbjogNi4zMy4xDQoiIiJHZW5lcmF0ZWQgcHJvdG9jb2wgYnVmZmVyIGNvZGUuIiIi"
    "DQpmcm9tIGdvb2dsZS5wcm90b2J1ZiBpbXBvcnQgZGVzY3JpcHRvciBhcyBfZGVzY3JpcHRvcg0K"
    "ZnJvbSBnb29nbGUucHJvdG9idWYgaW1wb3J0IGRlc2NyaXB0b3JfcG9vbCBhcyBfZGVzY3JpcHRv"
    "cl9wb29sDQpmcm9tIGdvb2dsZS5wcm90b2J1ZiBpbXBvcnQgcnVudGltZV92ZXJzaW9uIGFzIF9y"
    "dW50aW1lX3ZlcnNpb24NCmZyb20gZ29vZ2xlLnByb3RvYnVmIGltcG9ydCBzeW1ib2xfZGF0YWJh"
    "c2UgYXMgX3N5bWJvbF9kYXRhYmFzZQ0KZnJvbSBnb29nbGUucHJvdG9idWYuaW50ZXJuYWwgaW1w"
    "b3J0IGJ1aWxkZXIgYXMgX2J1aWxkZXINCl9ydW50aW1lX3ZlcnNpb24uVmFsaWRhdGVQcm90b2J1"
    "ZlJ1bnRpbWVWZXJzaW9uKA0KICAgIF9ydW50aW1lX3ZlcnNpb24uRG9tYWluLlBVQkxJQywNCiAg"
    "ICA2LA0KICAgIDMzLA0KICAgIDEsDQogICAgJycsDQogICAgJ1NlYXJjaEFjY291bnRCeU5hbWUu"
    "cHJvdG8nDQopDQojIEBAcHJvdG9jX2luc2VydGlvbl9wb2ludChpbXBvcnRzKQ0KDQpfc3ltX2Ri"
    "ID0gX3N5bWJvbF9kYXRhYmFzZS5EZWZhdWx0KCkNCg0KDQpmcm9tIFByb3RvLmNvbXBpbGVkIGlt"
    "cG9ydCBQbGF5ZXJQZXJzb25hbFNob3dfcGIyIGFzIFBsYXllclBlcnNvbmFsU2hvd19fcGIyDQoN"
    "Cg0KREVTQ1JJUFRPUiA9IF9kZXNjcmlwdG9yX3Bvb2wuRGVmYXVsdCgpLkFkZFNlcmlhbGl6ZWRG"
    "aWxlKGInXG5ceDE5U2VhcmNoQWNjb3VudEJ5TmFtZS5wcm90b1x4MTJceDEzU2VhcmNoQWNjb3Vu"
    "dEJ5TmFtZVx4MWFceDE4UGxheWVyUGVyc29uYWxTaG93LnByb3RvXCJceDFhXG5ceDA3cmVxdWVz"
    "dFx4MTJceDBmXG5ceDA3a2V5d29yZFx4MThceDAxIFx4MDEoXHRcIj9cblx4MDhyZXNwb25zZVx4"
    "MTJceDMzXG5ceDA1aW5mb3NceDE4XHgwMSBceDAzKFx4MGJceDMyJC5QbGF5ZXJQZXJzb25hbFNo"
    "b3cuQWNjb3VudEluZm9CYXNpY2JceDA2cHJvdG8zJykNCg0KX2dsb2JhbHMgPSBnbG9iYWxzKCkN"
    "Cl9idWlsZGVyLkJ1aWxkTWVzc2FnZUFuZEVudW1EZXNjcmlwdG9ycyhERVNDUklQVE9SLCBfZ2xv"
    "YmFscykNCl9idWlsZGVyLkJ1aWxkVG9wRGVzY3JpcHRvcnNBbmRNZXNzYWdlcyhERVNDUklQVE9S"
    "LCAnU2VhcmNoQWNjb3VudEJ5TmFtZV9wYjInLCBfZ2xvYmFscykNCmlmIG5vdCBfZGVzY3JpcHRv"
    "ci5fVVNFX0NfREVTQ1JJUFRPUlM6DQogIERFU0NSSVBUT1IuX2xvYWRlZF9vcHRpb25zID0gTm9u"
    "ZQ0KICBfZ2xvYmFsc1snX1JFUVVFU1QnXS5fc2VyaWFsaXplZF9zdGFydD03Ng0KICBfZ2xvYmFs"
    "c1snX1JFUVVFU1QnXS5fc2VyaWFsaXplZF9lbmQ9MTAyDQogIF9nbG9iYWxzWydfUkVTUE9OU0Un"
    "XS5fc2VyaWFsaXplZF9zdGFydD0xMDQNCiAgX2dsb2JhbHNbJ19SRVNQT05TRSddLl9zZXJpYWxp"
    "emVkX2VuZD0xNjcNCiMgQEBwcm90b2NfaW5zZXJ0aW9uX3BvaW50KG1vZHVsZV9zY29wZSkNCg=="
  ),
}

def _load_embedded_pb2():
    # Pre-register `Proto` and `Proto.compiled` as empty package modules so that
    # `from Proto.compiled import X_pb2` inside any pb2 source resolves to our
    # already-exec'd modules (attribute lookup on the package).
    _proto_pkg = sys.modules.get("Proto") or _types.ModuleType("Proto")
    _proto_pkg.__path__ = []  # mark as package
    sys.modules["Proto"] = _proto_pkg
    _compiled_pkg = sys.modules.get("Proto.compiled") or _types.ModuleType("Proto.compiled")
    _compiled_pkg.__path__ = []
    sys.modules["Proto.compiled"] = _compiled_pkg
    _proto_pkg.compiled = _compiled_pkg

    # Load order matters: modules that are imported by others must go first.
    _order = [
        "MajorLogin_pb2",
        "PlayerPersonalShow_pb2",  # referenced by SearchAccountByName_pb2
        "PlayerStats_pb2",
        "PlayerCSStats_pb2",
        "SearchAccountByName_pb2",
    ]
    out = {}
    for _n in _order:
        _b64 = _PB2_BLOBS[_n]
        _src = base64.b64decode(_b64).decode('utf-8')
        _mod = _types.ModuleType(_n)
        _mod.__file__ = f'<embedded:{_n}>'
        sys.modules[_n] = _mod
        # Also expose as attribute of Proto.compiled so `from Proto.compiled import X`
        # works inside later pb2 modules that cross-import.
        setattr(_compiled_pkg, _n, _mod)
        sys.modules[f"Proto.compiled.{_n}"] = _mod
        exec(compile(_src, _mod.__file__, 'exec'), _mod.__dict__)
        out[_n] = _mod
    return out

_pb2_modules = _load_embedded_pb2()
MajorLogin_pb2 = _pb2_modules['MajorLogin_pb2']
PlayerPersonalShow_pb2 = _pb2_modules['PlayerPersonalShow_pb2']
PlayerStats_pb2 = _pb2_modules['PlayerStats_pb2']
PlayerCSStats_pb2 = _pb2_modules['PlayerCSStats_pb2']
SearchAccountByName_pb2 = _pb2_modules['SearchAccountByName_pb2']

from google.protobuf import json_format  # noqa: E402
from google.protobuf.message import Message  # noqa: E402

# ---------------------------------------------------------------------------
# Constants pulled from Configuration/AESConfiguration.py + APIConfiguration.py
# ---------------------------------------------------------------------------
MAIN_KEY = b"Yg&tc%DEuh6%Zc^8"
MAIN_IV = b"6oyZDr22E3ychjM%"
RELEASEVERSION = "OB53"

# Region service-account credentials (copied from AccountConfiguration.json).
REGION_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    "IND": {"uid": 4700643276, "password": "F899A3ED0A0869A0E8E2F8EDE2DFB845D0BE0B99C6898522F077DC5E8C51EF10"},
    "SG":  {"uid": 4700643298, "password": "7331DA99639E0A83643373047534759BA37228A1571DB1E6AC9A11907C6307C1"},
    "RU":  {"uid": 4700643336, "password": "306C4921230C81F5A4E06A7942B6CA372691F2D6C166BC8405F4C605AD8DC643"},
    "ID":  {"uid": 4700643359, "password": "917E4D8D16CD46052041C3DDB55BD95C2247CDD86DDA135C9604C8AF40FAEAE8"},
    "TW":  {"uid": 4700643420, "password": "3119F3296BC915688DC5B93B1F02E28C15AA1B1780E5B22EB9CB5DBC9AEE8ABB"},
    "US":  {"uid": 4700643502, "password": "2C49F0B031ABBF0C8F8A815B9DE1BF3DAAC92F11594F457D3462212D3E4A21BC"},
    "VN":  {"uid": 4700643587, "password": "04A90DB66D9864D0038782E24D7D2B9DB7B6679B207859AD17D4272B9C9F9B84"},
    "TH":  {"uid": 4700643618, "password": "8E6DBF6E06946824BA9A98ACAE10FA106CC30318EB95756B0642FAB7AE6884B4"},
    "ME":  {"uid": 4700643647, "password": "43DFF0D51E2257E8C340E49930C9EC0A1FEA034664CD8065FF0DE3BD62975006"},
    "PK":  {"uid": 4700643671, "password": "276803AC7B39A91FDDDBE2FCA1B36C66F886600E8248827E5A2F8DE1859F1D0A"},
    "CIS": {"uid": 4700643691, "password": "6A83C2E605DADDD28A42096187725F0D9BDCD06C03849ACAF65F2DFD9228CF68"},
    "BR":  {"uid": 4700643716, "password": "48F4557A85CFFBFAF063F58461E37AE386EAFF6F01AC4DBDC31B4B7C8009CCAF"},
    "BD":  {"uid": 4700643735, "password": "A4C021D128BA47746CC54C1F62A1FB186F08F41DDA0731B7D5BC1C693AB26769"},
}

# Endpoints
GARENA_OAUTH_URL = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"

# Per-region MajorLogin gateway. Wrong gateway -> auth lands on the wrong
# game cluster and any subsequent UID lookup returns HTTP 500.
REGION_LOGIN_URLS: Dict[str, str] = {
    "IND": "https://loginbp.ggblueshark.com/MajorLogin",
    "BD":  "https://loginbp.ggblueshark.com/MajorLogin",
    "ID":  "https://loginbp.ggblueshark.com/MajorLogin",
    "SG":  "https://loginbp.ggblueshark.com/MajorLogin",
    "VN":  "https://loginbp.ggblueshark.com/MajorLogin",
    "TW":  "https://loginbp.ggblueshark.com/MajorLogin",
    "PK":  "https://loginbp.ggblueshark.com/MajorLogin",
    "CIS": "https://loginbp.ggblueshark.com/MajorLogin",
    "RU":  "https://loginbp.ggblueshark.com/MajorLogin",
    "BR":  "https://loginbp.ggpolarbear.com/MajorLogin",
    "US":  "https://loginbp.ggpolarbear.com/MajorLogin",
    "SAC": "https://loginbp.ggpolarbear.com/MajorLogin",
    "ME":  "https://loginbp.common.ggbluefox.com/MajorLogin",
    "TH":  "https://loginbp.common.ggbluefox.com/MajorLogin",
}
# If the primary URL fails, try these in order.
LOGIN_FALLBACK_URLS: List[str] = [
    "https://loginbp.ggblueshark.com/MajorLogin",
    "https://loginbp.common.ggbluefox.com/MajorLogin",
    "https://loginbp.ggpolarbear.com/MajorLogin",
    "https://loginbp.ggwhitehawk.com/MajorLogin",
]

# In-game game-cluster base URL per region. The serverUrl returned by
# MajorLogin can be wrong when the bot account is pinned to a different
# cluster, so we override using the user-supplied region.
REGION_CLIENT_URLS: Dict[str, str] = {
    "IND": "https://client.ind.freefiremobile.com",
    "BD":  "https://clientbp.ggblueshark.com",
    "ID":  "https://clientbp.ggblueshark.com",
    "SG":  "https://clientbp.ggblueshark.com",
    "VN":  "https://clientbp.ggblueshark.com",
    "CIS": "https://clientbp.ggblueshark.com",
    "PK":  "https://clientbp.ggblueshark.com",
    "TW":  "https://clientbp.ggblueshark.com",
    "RU":  "https://clientbp.ggblueshark.com",
    "BR":  "https://client.us.freefiremobile.com",
    "US":  "https://client.us.freefiremobile.com",
    "SAC": "https://client.us.freefiremobile.com",
    "ME":  "https://clientbp.common.ggbluefox.com",
    "TH":  "https://clientbp.common.ggbluefox.com",
}

GARENA_CLIENT_ID = "100067"
GARENA_CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

DEFAULT_TIMEOUT = 30

# JWT cache - reuse until it expires so we skip oauth + MajorLogin (saves ~1s).
_TOKEN_CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ff_full_info_token.json")
_TOKEN_EXP_SAFETY_SEC = 120  # treat as expired this many seconds early

# ---------------------------------------------------------------------------
# AES + protobuf helpers (mirrors Utilities/until.py)
# ---------------------------------------------------------------------------

def _pad(buf: bytes) -> bytes:
    pad_len = AES.block_size - (len(buf) % AES.block_size)
    return buf + bytes([pad_len] * pad_len)


def aes_encrypt(buf: bytes) -> bytes:
    cipher = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV)
    return cipher.encrypt(_pad(buf))


def encode_protobuf(data: Dict[str, Any], proto_msg: Message) -> bytes:
    json_format.ParseDict(data, proto_msg)
    return aes_encrypt(proto_msg.SerializeToString())


def decode_protobuf(raw: bytes, msg_cls) -> Dict[str, Any]:
    inst = msg_cls()
    inst.ParseFromString(raw)
    try:
        out = json_format.MessageToJson(inst, preserving_proto_field_name=True)
    except TypeError:
        out = json_format.MessageToJson(inst)
    return json.loads(out)


# ---------------------------------------------------------------------------
# Auth flow
# ---------------------------------------------------------------------------

def get_garena_token(uid: Any, password: str) -> Optional[Dict[str, Any]]:
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }
    payload = {
        "uid": str(uid),
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": GARENA_CLIENT_SECRET,
        "client_id": GARENA_CLIENT_ID,
    }
    try:
        r = SESSION.post(GARENA_OAUTH_URL, data=payload, headers=headers, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[oauth] error: {e}")
        return None


def get_major_login(access_token: str, open_id: str,
                     region: str = "IND") -> Optional[Dict[str, Any]]:
    payload = encode_protobuf(
        {"openid": open_id, "logintoken": access_token, "platform": "4"},
        MajorLogin_pb2.request(),
    )
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; A063 Build/TKQ1.221220.001)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Expect": "100-continue",
        "Authorization": "Bearer",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    primary = REGION_LOGIN_URLS.get(region.upper(), LOGIN_FALLBACK_URLS[0])
    urls: List[str] = [primary] + [u for u in LOGIN_FALLBACK_URLS if u != primary]
    last_err: Optional[str] = None
    for url in urls:
        try:
            r = SESSION.post(url, data=payload, headers=headers, timeout=DEFAULT_TIMEOUT)
            r.raise_for_status()
            decoded = decode_protobuf(r.content, MajorLogin_pb2.response)
            if decoded and decoded.get("token") and decoded.get("serverUrl"):
                return decoded
            last_err = f"empty/invalid response from {url}: {decoded}"
        except Exception as e:
            last_err = f"{url}: {e}"
            print(f"[MajorLogin] {url} failed: {e}")
    print(f"[MajorLogin] all gateways failed. last={last_err}")
    return None


def _load_credentials_txt() -> Optional[Dict[str, str]]:
    """Read uid=/password= from credentials.txt next to this script if present."""
    _here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(_here, "credentials.txt")
    if not os.path.isfile(path):
        return None
    uid, pwd = None, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("uid="):
                    uid = line.split("=", 1)[1].strip()
                elif line.lower().startswith("password="):
                    pwd = line.split("=", 1)[1].strip()
    except Exception as e:
        print(f"[creds] could not read credentials.txt: {e}")
        return None
    if uid and pwd:
        return {"uid": uid, "password": pwd}
    return None


def _jwt_exp(token: str) -> Optional[int]:
    """Return the JWT's `exp` claim (unix seconds) without verifying signature."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return int(payload.get("exp", 0)) or None
    except Exception:
        return None


def _load_cached_auth(region: str) -> Optional[Dict[str, str]]:
    if not os.path.isfile(_TOKEN_CACHE_PATH):
        return None
    try:
        with open(_TOKEN_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("region") != region:
            return None
        token = data.get("jwt")
        server_url = data.get("server_url")
        if not token or not server_url:
            return None
        exp = _jwt_exp(token)
        if exp and exp - _TOKEN_EXP_SAFETY_SEC > time.time():
            return {"jwt": token, "server_url": server_url, "cached": True}
    except Exception:
        return None
    return None


def _save_cached_auth(region: str, auth: Dict[str, Any]) -> None:
    try:
        with open(_TOKEN_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "region": region,
                "jwt": auth["jwt"],
                "server_url": auth["server_url"],
                "saved_at": int(time.time()),
            }, f)
    except Exception:
        pass


def authenticate(region: str) -> Optional[Dict[str, str]]:
    region = region.upper()
    if region not in REGION_ACCOUNTS:
        print(f"Unknown region '{region}'. Available: {list(REGION_ACCOUNTS)}")
        return None

    # Prefer real account from credentials.txt because the bundled service
    # accounts (AccountConfiguration.json) are pinned to the US cluster
    # and therefore can't query UIDs that live on IND/BR/etc.
    cached = _load_cached_auth(region)
    if cached:
        return cached

    creds = _load_credentials_txt()
    if creds:
        acct = creds
    else:
        acct = REGION_ACCOUNTS[region]
    token_resp = get_garena_token(acct["uid"], acct["password"])
    if not token_resp or "access_token" not in token_resp:
        print(f"[-] Garena oauth failed: {token_resp}")
        return None
    major = get_major_login(token_resp["access_token"], token_resp["open_id"], region)
    if not major or "token" not in major or "serverUrl" not in major:
        print(f"[-] MajorLogin failed: {major}")
        return None
    returned_server = major.get("serverUrl") or ""
    region_server = REGION_CLIENT_URLS.get(region, returned_server)
    server_url = region_server or returned_server
    auth = {"jwt": major["token"], "server_url": server_url, "major_login_raw": major}
    _save_cached_auth(region, auth)
    return auth


# ---------------------------------------------------------------------------
# In-game endpoints
# ---------------------------------------------------------------------------

def _ingame_headers(jwt: str) -> Dict[str, str]:
    return {
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "Authorization": f"Bearer {jwt}",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1",
    }


def get_player_personal_show(server_url: str, jwt: str, account_id: int,
                              need_gallery_info: bool = True,
                              need_blacklist: bool = True,
                              need_spark_info: bool = True,
                              call_sign_src: int = 7) -> Optional[Dict[str, Any]]:
    payload = encode_protobuf({
        "accountId": account_id,
        "callSignSrc": call_sign_src,
        "needGalleryInfo": need_gallery_info,
        "needBlacklist": need_blacklist,
        "needSparkInfo": need_spark_info,
    }, PlayerPersonalShow_pb2.request())
    try:
        r = SESSION.post(f"{server_url}/GetPlayerPersonalShow",
                          data=payload, headers=_ingame_headers(jwt), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return decode_protobuf(r.content, PlayerPersonalShow_pb2.response)
    except Exception as e:
        print(f"[GetPlayerPersonalShow] error: {e}")
        return None


def get_player_br_stats(server_url: str, jwt: str, account_id: int,
                         match_type: str = "CAREER") -> Optional[Dict[str, Any]]:
    mapping = {"CAREER": 0, "NORMAL": 1, "RANKED": 2}
    matchmode = mapping.get(match_type.upper(), 0)
    payload = encode_protobuf(
        {"accountid": account_id, "matchmode": matchmode},
        PlayerStats_pb2.request(),
    )
    try:
        r = SESSION.post(f"{server_url}/GetPlayerStats",
                          data=payload, headers=_ingame_headers(jwt), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return decode_protobuf(r.content, PlayerStats_pb2.response)
    except Exception as e:
        print(f"[GetPlayerStats BR/{match_type}] error: {e}")
        return None


def get_player_cs_stats(server_url: str, jwt: str, account_id: int,
                         match_type: str = "CAREER") -> Optional[Dict[str, Any]]:
    mapping = {"CAREER": 0, "NORMAL": 1, "RANKED": 6}
    matchmode = mapping.get(match_type.upper(), 0)
    payload = encode_protobuf(
        {"accountid": account_id, "gamemode": 15, "matchmode": matchmode},
        PlayerCSStats_pb2.request(),
    )
    try:
        r = SESSION.post(f"{server_url}/GetPlayerTCStats",
                          data=payload, headers=_ingame_headers(jwt), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return decode_protobuf(r.content, PlayerCSStats_pb2.response)
    except Exception as e:
        print(f"[GetPlayerTCStats CS/{match_type}] error: {e}")
        return None


def fuzzy_search_account_by_name(server_url: str, jwt: str, keyword: str) -> Optional[Dict[str, Any]]:
    if len(str(keyword).strip()) < 3:
        return None
    payload = encode_protobuf(
        {"keyword": str(keyword)},
        SearchAccountByName_pb2.request(),
    )
    try:
        r = SESSION.post(f"{server_url}/FuzzySearchAccountByName",
                          data=payload, headers=_ingame_headers(jwt), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return decode_protobuf(r.content, SearchAccountByName_pb2.response)
    except Exception as e:
        print(f"[FuzzySearchAccountByName] error: {e}")
        return None


# ---------------------------------------------------------------------------
# Derivation: Prime / Evo / skin / bundle / pet counts from PersonalShow
# ---------------------------------------------------------------------------

def _ts(value: Any) -> Optional[str]:
    try:
        v = int(value)
        if v <= 0:
            return None
        return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None


def _ts_ist(value: Any) -> Optional[str]:
    try:
        v = int(value)
        if v <= 0:
            return None
        from datetime import timezone, timedelta
        IST = timezone(timedelta(hours=5, minutes=30))
        dt_ist = datetime.fromtimestamp(v, tz=IST)
        return dt_ist.strftime("%d %B %Y, %I:%M %p IST")
    except Exception:
        return None


def derive_summary(personal: Dict[str, Any]) -> Dict[str, Any]:
    """Pull out the headline fields the user asked for."""
    summary: Dict[str, Any] = {}
    basic = personal.get("basicinfo", {}) or {}
    profile = personal.get("profileinfo", {}) or {}
    pet = personal.get("petinfo", {}) or {}
    clan = personal.get("clanbasicinfo", {}) or {}
    social = personal.get("socialinfo", {}) or {}
    history_ep = personal.get("historyepinfo", []) or []
    user_spark = personal.get("user_spark_info") or basic.get("spark_info", {}).get("user_spark_info") or {}
    collab_spark = personal.get("collab_spark_info") or {}
    prime = basic.get("primeprivilegedetail", {}) or {}
    badge = basic.get("badgeinfo", {}) or {}

    summary["uid"] = basic.get("accountid")
    summary["nickname"] = basic.get("nickname")
    summary["region"] = basic.get("region")
    summary["level"] = basic.get("level")
    summary["exp"] = basic.get("exp")
    summary["liked"] = basic.get("liked")
    summary["title"] = basic.get("title")
    summary["banner_id"] = basic.get("bannerid")
    summary["head_pic"] = basic.get("headpic")
    summary["avatar_frame"] = basic.get("avatarframe")
    summary["pin_id"] = basic.get("pinid")
    summary["release_version"] = basic.get("releaseversion")
    summary["account_created_at"] = _ts_ist(basic.get("createat"))
    summary["last_login_at"] = _ts_ist(basic.get("lastloginat"))
    summary["has_elite_pass"] = basic.get("haselitepass", False)
    summary["badge_count"] = basic.get("badgecnt", 0)
    summary["badge_id"] = basic.get("badgeid")
    summary["season_id"] = basic.get("seasonid")
    summary["br_rank"] = basic.get("rank")
    summary["br_rank_points"] = basic.get("rankingpoints")
    summary["br_max_rank"] = basic.get("maxrank")
    summary["cs_rank"] = basic.get("csrank")
    summary["cs_rank_points"] = basic.get("csrankingpoints")
    summary["cs_max_rank"] = basic.get("csmaxrank")
    summary["cs_peak_points"] = basic.get("cspeakpoints")

    # Clan / guild
    summary["clan"] = {
        "id": clan.get("clanid") or basic.get("clanid"),
        "name": clan.get("clanname") or basic.get("clanname"),
        "level": clan.get("clanlevel"),
        "members": clan.get("membernum"),
        "capacity": clan.get("capacity"),
        "captain_id": clan.get("captainid"),
        "honor_points": clan.get("honorpoint"),
    }

    # Pet
    summary["pet"] = {
        "id": pet.get("id"),
        "name": pet.get("name"),
        "level": pet.get("level"),
        "skin_id": pet.get("skinid"),
        "selected": pet.get("isselected", False),
        "skills": pet.get("skills", []),
    }

    # Avatar / equipped skins (clothes), weapon-skin shows
    clothes = profile.get("clothes", []) or []
    weapon_skins = basic.get("weaponskinshows", []) or []
    selected_slots = basic.get("selecteditemslots", []) or []
    summary["avatar"] = {
        "avatar_id": profile.get("avatarid"),
        "skin_color": profile.get("skincolor"),
        "equipped_clothes": clothes,
        "equipped_skills": profile.get("equipedskills", []),
        "is_selected": profile.get("isselected", False),
        "is_awaken": profile.get("isselectedawaken", False),
        "endtime": _ts(profile.get("endtime")),
    }
    summary["equipped_clothes_count"] = len(clothes)
    summary["weapon_skin_count"] = len(weapon_skins)
    summary["weapon_skin_ids"] = weapon_skins
    summary["selected_item_slots"] = selected_slots
    # Heuristic "bundle count" -> equipped clothing pieces are usually bundle items
    summary["bundle_count_estimate"] = len(set(clothes))

    # Prime privilege
    summary["prime"] = {
        "level": prime.get("primelevel", 0),
        "privilege_ids": prime.get("privilegeidlist", []),
        "privilege_count": len(prime.get("privilegeidlist", [])),
        "monthly_points": prime.get("monthlypoints"),
        "annually_points": prime.get("annuallypoints"),
        "sum_points": prime.get("sumpoints"),
        "sharer_remain_times": prime.get("shareeremaintimes"),
        "is_prime": bool(prime.get("primelevel", 0)),
    }
    summary["badge_info"] = {
        "type": badge.get("badgetype"),
        "subtype": badge.get("subtype"),
    }

    # Spark / Evo
    def _spark(s):
        if not s:
            return None
        return {
            "state": s.get("state"),
            "level": s.get("level"),
            "exp": s.get("exp"),
            "login_streak_days": s.get("login_streak_days"),
            "temper": s.get("temper"),
            "appearance_stage": s.get("appearance_stage"),
            "appearance_item_ids": s.get("appearance_item_ids", []),
            "stage_appearance_items": s.get("stage_appearance_items", []),
        }
    summary["spark_user"] = _spark(user_spark)
    summary["spark_collab"] = _spark(collab_spark)
    summary["evo_active"] = bool(user_spark and user_spark.get("state"))

    # Elite Pass history
    summary["ep_history"] = [
        {
            "event_id": ep.get("epeventid"),
            "owned_pass": ep.get("ownedpass", False),
            "badge_count": ep.get("badgecnt", 0),
            "max_level": ep.get("maxlevel"),
            "event_name": ep.get("eventname"),
        }
        for ep in history_ep
    ]
    summary["ep_pass_count"] = sum(1 for ep in history_ep if ep.get("ownedpass"))

    # Social / signature
    summary["social"] = {
        "signature": social.get("signature"),
        "gender": social.get("gender"),
        "language": social.get("language"),
        "mode_prefer": social.get("modeprefer"),
        "rank_show": social.get("rankshow"),
        "leaderboard_titles": social.get("leaderboardtitles"),
    }

    # Credit score
    cs = personal.get("creditscoreinfo", {}) or {}
    summary["credit_score"] = {
        "score": cs.get("creditscore"),
        "is_init": cs.get("isinit"),
        "weekly_match_count": cs.get("weeklymatchcnt"),
        "level": cs.get("periodicsummarylevel"),
    }

    # Mode stats summary + MMR
    summary["mode_stats_summary"] = personal.get("modestatssummaryinfo")
    summary["mmr_list"] = personal.get("mmrlist", [])

    return summary


# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------

def print_report(summary: Dict[str, Any]) -> None:
    line = "=" * 78
    print("\n" + line)
    print("  FREE FIRE - FULL ACCOUNT REPORT")
    print(line)
    print(f"  UID            : {summary.get('uid')}")
    print(f"  Nickname       : {summary.get('nickname')}")
    print(f"  Region         : {summary.get('region')}")
    print(f"  Level / EXP    : {summary.get('level')} / {summary.get('exp')}")
    print(f"  Likes          : {summary.get('liked')}")
    print(f"  Created        : {summary.get('account_created_at')}")
    print(f"  Last login     : {summary.get('last_login_at')}")
    print(f"  Release ver    : {summary.get('release_version')}")
    print(f"  Title          : {summary.get('title')}")
    print(f"  Banner / Pin   : {summary.get('banner_id')} / {summary.get('pin_id')}")
    print(f"  Avatar frame   : {summary.get('avatar_frame')}")
    print(f"  Elite Pass     : {summary.get('has_elite_pass')}")
    print()
    print("  -- RANKS --")
    print(f"  BR rank/pts    : {summary.get('br_rank')} / {summary.get('br_rank_points')}  (peak {summary.get('br_max_rank')})")
    print(f"  CS rank/pts    : {summary.get('cs_rank')} / {summary.get('cs_rank_points')}  (peak {summary.get('cs_max_rank')}, peak pts {summary.get('cs_peak_points')})")
    print()
    print("  -- COSMETICS / BUNDLES --")
    print(f"  Equipped clothes count : {summary.get('equipped_clothes_count')}")
    print(f"  Bundle count (estimate): {summary.get('bundle_count_estimate')}")
    print(f"  Weapon skins shown     : {summary.get('weapon_skin_count')} -> {summary.get('weapon_skin_ids')}")
    print(f"  Selected item slots    : {summary.get('selected_item_slots')}")
    print(f"  Avatar id              : {summary.get('avatar', {}).get('avatar_id')}")
    print(f"  Equipped clothes ids   : {summary.get('avatar', {}).get('equipped_clothes')}")
    print(f"  Equipped skills        : {summary.get('avatar', {}).get('equipped_skills')}")
    print(f"  Avatar endtime         : {summary.get('avatar', {}).get('endtime')}")
    print()
    print("  -- PRIME --")
    p = summary.get("prime", {})
    print(f"  Is Prime               : {p.get('is_prime')}")
    print(f"  Prime level            : {p.get('level')}")
    print(f"  Privilege count        : {p.get('privilege_count')}")
    print(f"  Privilege IDs          : {p.get('privilege_ids')}")
    print(f"  Monthly / Annual / Sum : {p.get('monthly_points')} / {p.get('annually_points')} / {p.get('sum_points')}")
    print()
    print("  -- EVO / SPARK --")
    s = summary.get("spark_user") or {}
    print(f"  Active                 : {summary.get('evo_active')}")
    print(f"  State / Level / EXP    : {s.get('state')} / {s.get('level')} / {s.get('exp')}")
    print(f"  Login streak days      : {s.get('login_streak_days')}")
    print(f"  Appearance stage       : {s.get('appearance_stage')}")
    print(f"  Appearance items       : {s.get('appearance_item_ids')}")
    if summary.get("spark_collab"):
        sc = summary["spark_collab"]
        print(f"  [Collab spark] state/lvl/exp = {sc.get('state')}/{sc.get('level')}/{sc.get('exp')}")
    print()
    print("  -- PET --")
    pet = summary.get("pet", {})
    print(f"  Pet id / name          : {pet.get('id')} / {pet.get('name')}")
    print(f"  Level / Skin           : {pet.get('level')} / {pet.get('skin_id')}")
    print(f"  Selected               : {pet.get('selected')}")
    print()
    print("  -- CLAN / GUILD --")
    c = summary.get("clan", {})
    print(f"  Clan name / id         : {c.get('name')} / {c.get('id')}")
    print(f"  Level / Members        : {c.get('level')} / {c.get('members')} of {c.get('capacity')}")
    print(f"  Captain id / Honor pts : {c.get('captain_id')} / {c.get('honor_points')}")
    print()
    print("  -- BADGE / EP --")
    print(f"  Badge count            : {summary.get('badge_count')} (id {summary.get('badge_id')})")
    print(f"  EP passes owned        : {summary.get('ep_pass_count')}")
    for ep in summary.get("ep_history", []):
        print(f"    * {ep['event_name']:<25} owned={ep['owned_pass']:<5} badges={ep['badge_count']} maxlvl={ep['max_level']}")
    print()
    print("  -- CREDIT SCORE --")
    cr = summary.get("credit_score", {})
    print(f"  Score / Init / Weekly  : {cr.get('score')} / {cr.get('is_init')} / {cr.get('weekly_match_count')}")
    print()
    print("  -- SOCIAL --")
    so = summary.get("social", {})
    print(f"  BIO                    : {so.get('signature')}")
    print(f"  Gender / Language      : {so.get('gender')} / {so.get('language')}")
    print(f"  Mode prefer / RankShow : {so.get('mode_prefer')} / {so.get('rank_show')}")
    print(line + "\n")


# ---------------------------------------------------------------------------
# Master orchestrator
# ---------------------------------------------------------------------------

def gather_full_info(uid: int, region: str = "IND") -> Dict[str, Any]:
    started = time.time()
    report: Dict[str, Any] = {
        "uid": uid,
        "region_used": region,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "ok": False,
        "summary": {},
        "raw": {},
        "errors": [],
    }

    auth = authenticate(region)
    if not auth:
        report["errors"].append("authentication_failed")
        return report
    server_url = auth["server_url"]
    jwt = auth["jwt"]

    # Fire all in-game calls in parallel.
    tasks = {
        "personal_show": lambda: get_player_personal_show(server_url, jwt, uid,
                                                            need_gallery_info=True,
                                                            need_blacklist=True,
                                                            need_spark_info=True),
        "br_career":     lambda: get_player_br_stats(server_url, jwt, uid, "CAREER"),
        "br_ranked":     lambda: get_player_br_stats(server_url, jwt, uid, "RANKED"),
        "cs_career":     lambda: get_player_cs_stats(server_url, jwt, uid, "CAREER"),
        "cs_ranked":     lambda: get_player_cs_stats(server_url, jwt, uid, "RANKED"),
    }
    with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        futures = {name: ex.submit(fn) for name, fn in tasks.items()}
        results = {name: fut.result() for name, fut in futures.items()}

    personal = results.get("personal_show")
    if not personal:
        report["errors"].append("personal_show_failed")
    for k, v in results.items():
        report["raw"][k] = v

    nickname = (personal or {}).get("basicinfo", {}).get("nickname", "")
    if nickname and len(nickname) >= 3:
        report["raw"]["fuzzy_search"] = fuzzy_search_account_by_name(server_url, jwt, nickname)

    if personal:
        report["summary"] = derive_summary(personal)
        report["ok"] = True

    report["elapsed_seconds"] = round(time.time() - started, 3)
    print(f"[*] API time (auth+fetch): {report['elapsed_seconds']}s")
    return report


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 78)
    print("  FREE FIRE - FULL ACCOUNT INFO GATHERER (IND, fast mode)")
    print("=" * 78)
    uid_raw = input("Enter Free Fire UID: ").strip()
    if not uid_raw.isdigit():
        print("UID must be numeric.")
        return
    uid = int(uid_raw)
    region = "IND"  # credentials.txt is IND-only
    report = gather_full_info(uid, region)
    if report.get("ok"):
        print_report(report["summary"])
    else:
        print("\n[!] Could not retrieve player info. Errors:")
        for err in report["errors"]:
            print(f"   - {err}")
    out_path = os.path.join(_HERE, f"ff_full_info_{uid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    print(f"[+] Full JSON report saved -> {out_path}")


if __name__ == "__main__":
    main()


# ===========================================================================
# HTTP API (merged from former ff_api.py). Run with gunicorn ff_full_info:app
# ===========================================================================
try:
    from flask import Flask, jsonify, request as _flask_request
    from flask_cors import CORS

    _CREDS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credentials.txt")
    if not os.path.isfile(_CREDS_PATH):
        _env_uid = os.environ.get("FF_UID")
        _env_pwd = os.environ.get("FF_PASSWORD")
        if _env_uid and _env_pwd:
            with open(_CREDS_PATH, "w", encoding="utf-8") as _f:
                _f.write(f"uid={_env_uid}\npassword={_env_pwd}\n")

    app = Flask(__name__)
    CORS(app)

    @app.route("/")
    def _health():
        return jsonify({"ok": True, "service": "ff_full_info api"})

    def _do_lookup(uid_raw):
        if uid_raw is None:
            return jsonify({"ok": False, "error": "missing uid"}), 400
        try:
            uid = int(str(uid_raw).strip())
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "uid must be numeric"}), 400
        report = gather_full_info(uid, region="IND")
        if not report.get("ok"):
            return jsonify({
                "ok": False,
                "uid": uid,
                "errors": report.get("errors", []),
            }), 502
        summary = report.get("summary", {})
        return jsonify({
            "ok": True,
            "uid": uid,
            "elapsed_seconds": report.get("elapsed_seconds"),
            "summary": summary,
            **summary,
        })

    @app.route("/api/uid/<uid>", methods=["GET"])
    def _api_uid_get(uid):
        return _do_lookup(uid)

    @app.route("/api/uid", methods=["POST"])
    def _api_uid_post():
        data = _flask_request.get_json(silent=True) or {}
        return _do_lookup(data.get("uid") or _flask_request.form.get("uid"))
except ImportError:
    # Flask not installed (CLI-only environment). Skip API setup.
    app = None
