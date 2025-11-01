# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703481");
  script_cve_id("CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8778", "CVE-2015-8779");
  script_tag(name:"creation_date", value:"2016-02-15 23:00:00 +0000 (Mon, 15 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3481");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3481");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'glibc' package(s) announced via the DSA-3481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in the GNU C Library, glibc.

The first vulnerability listed below is considered to have critical impact.

CVE-2015-7547

The Google Security Team and Red Hat discovered that the glibc host name resolver function, getaddrinfo, when processing AF_UNSPEC queries (for dual A/AAAA lookups), could mismanage its internal buffers, leading to a stack-based buffer overflow and arbitrary code execution. This vulnerability affects most applications which perform host name resolution using getaddrinfo, including system services.

CVE-2015-8776

Adam Nielsen discovered that if an invalid separated time value is passed to strftime, the strftime function could crash or leak information. Applications normally pass only valid time information to strftime, no affected applications are known.

CVE-2015-8778

Szabolcs Nagy reported that the rarely-used hcreate and hcreate_r functions did not check the size argument properly, leading to a crash (denial of service) for certain arguments. No impacted applications are known at this time.

CVE-2015-8779

The catopen function contains several unbound stack allocations (stack overflows), causing it the crash the process (denial of service). No applications where this issue has a security impact are currently known.

While it is only necessary to ensure that all processes are not using the old glibc anymore, it is recommended to reboot the machines after applying the security upgrade.

For the stable distribution (jessie), these problems have been fixed in version 2.19-18+deb8u3.

For the unstable distribution (sid), these problems will be fixed in version 2.21-8.

We recommend that you upgrade your glibc packages.");

  script_tag(name:"affected", value:"'glibc' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);