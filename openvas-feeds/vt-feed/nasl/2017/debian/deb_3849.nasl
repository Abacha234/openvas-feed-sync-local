# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703849");
  script_cve_id("CVE-2017-6410", "CVE-2017-8422");
  script_tag(name:"creation_date", value:"2017-05-11 22:00:00 +0000 (Thu, 11 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3849)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3849");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3849");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kde4libs' package(s) announced via the DSA-3849 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in kde4libs, the core libraries for all KDE 4 applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2017-6410

Itzik Kotler, Yonatan Fridburg and Amit Klein of Safebreach Labs reported that URLs are not sanitized before passing them to FindProxyForURL, potentially allowing a remote attacker to obtain sensitive information via a crafted PAC file.

CVE-2017-8422

Sebastian Krahmer from SUSE discovered that the KAuth framework contains a logic flaw in which the service invoking dbus is not properly checked. This flaw allows spoofing the identity of the caller and gaining root privileges from an unprivileged account.

For the stable distribution (jessie), these problems have been fixed in version 4:4.14.2-5+deb8u2.

For the unstable distribution (sid), these problems have been fixed in version 4:4.14.26-2.

We recommend that you upgrade your kde4libs packages.");

  script_tag(name:"affected", value:"'kde4libs' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);