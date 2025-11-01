# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703026");
  script_cve_id("CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638", "CVE-2014-3639");
  script_tag(name:"creation_date", value:"2014-09-15 22:00:00 +0000 (Mon, 15 Sep 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3026)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3026");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3026");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dbus' package(s) announced via the DSA-3026 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alban Crequy and Simon McVittie discovered several vulnerabilities in the D-Bus message daemon.

CVE-2014-3635

On 64-bit platforms, file descriptor passing could be abused by local users to cause heap corruption in dbus-daemon, leading to a crash, or potentially to arbitrary code execution.

CVE-2014-3636

A denial-of-service vulnerability in dbus-daemon allowed local attackers to prevent new connections to dbus-daemon, or disconnect existing clients, by exhausting descriptor limits.

CVE-2014-3637

Malicious local users could create D-Bus connections to dbus-daemon which could not be terminated by killing the participating processes, resulting in a denial-of-service vulnerability.

CVE-2014-3638

dbus-daemon suffered from a denial-of-service vulnerability in the code which tracks which messages expect a reply, allowing local attackers to reduce the performance of dbus-daemon.

CVE-2014-3639

dbus-daemon did not properly reject malicious connections from local users, resulting in a denial-of-service vulnerability.

For the stable distribution (wheezy), these problems have been fixed in version 1.6.8-1+deb7u4.

For the unstable distribution (sid), these problems have been fixed in version 1.8.8-1.

We recommend that you upgrade your dbus packages.");

  script_tag(name:"affected", value:"'dbus' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);