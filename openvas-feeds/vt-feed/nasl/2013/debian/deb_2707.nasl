# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702707");
  script_cve_id("CVE-2013-2168");
  script_tag(name:"creation_date", value:"2013-06-12 22:00:00 +0000 (Wed, 12 Jun 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2707)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2707");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2707");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dbus' package(s) announced via the DSA-2707 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexandru Cornea discovered a vulnerability in libdbus caused by an implementation bug in _dbus_printf_string_upper_bound(). This vulnerability can be exploited by a local user to crash system services that use libdbus, causing denial of service. Depending on the dbus services running, it could lead to complete system crash.

The oldstable distribution (squeeze) is not affected by this problem.

For the stable distribution (wheezy), this problem has been fixed in version 1.6.8-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 1.6.12-1.

For the unstable distribution (sid), this problem has been fixed in version 1.6.12-1.

We recommend that you upgrade your dbus packages.");

  script_tag(name:"affected", value:"'dbus' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);