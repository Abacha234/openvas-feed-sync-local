# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841823");
  script_cve_id("CVE-2014-1418");
  script_tag(name:"creation_date", value:"2014-05-19 05:54:49 +0000 (Mon, 19 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2212-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2212-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2212-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-2212-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephen Stewart, Michael Nelson, Natalia Bidart and James Westby
discovered that Django improperly removed Vary and Cache-Control headers
from HTTP responses when replying to a request from an Internet Explorer
or Chrome Frame client. An attacker may use this to retrieve private data
or poison caches. This update removes workarounds for bugs in Internet
Explorer 6 and 7. (CVE-2014-1418)

Peter Kuma and Gavin Wahl discovered that Django did not correctly
validate some malformed URLs, which are accepted by some browsers. An
attacker may use this to cause unexpected redirects. An update has been
provided for 12.04 LTS, 12.10, 13.10, and 14.04 LTS, this issue remains
unfixed for 10.04 LTS as no 'is_safe_url()' functionality existed in
this version.");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
