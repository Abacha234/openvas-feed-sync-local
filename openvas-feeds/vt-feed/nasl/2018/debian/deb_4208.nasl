# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704208");
  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");
  script_tag(name:"creation_date", value:"2018-05-21 22:00:00 +0000 (Mon, 21 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-30 13:15:00 +0000 (Tue, 30 Jul 2019)");

  script_name("Debian: Security Advisory (DSA-4208)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4208");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4208");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/procps");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'procps' package(s) announced via the DSA-4208 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Qualys Research Labs discovered multiple vulnerabilities in procps, a set of command line and full screen utilities for browsing procfs. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2018-1122

top read its configuration from the current working directory if no $HOME was configured. If top were started from a directory writable by the attacker (such as /tmp) this could result in local privilege escalation.

CVE-2018-1123

Denial of service against the ps invocation of another user.

CVE-2018-1124

An integer overflow in the file2strvec() function of libprocps could result in local privilege escalation.

CVE-2018-1125

A stack-based buffer overflow in pgrep could result in denial of service for a user using pgrep for inspecting a specially crafted process.

CVE-2018-1126

Incorrect integer size parameters used in wrappers for standard C allocators could cause integer truncation and lead to integer overflow issues.

For the oldstable distribution (jessie), these problems have been fixed in version 2:3.3.9-9+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 2:3.3.12-3+deb9u1.

We recommend that you upgrade your procps packages.

For the detailed security status of procps please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'procps' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);