# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704977");
  script_cve_id("CVE-2021-28694", "CVE-2021-28695", "CVE-2021-28696", "CVE-2021-28697", "CVE-2021-28698", "CVE-2021-28699", "CVE-2021-28700", "CVE-2021-28701");
  script_tag(name:"creation_date", value:"2021-09-22 01:00:12 +0000 (Wed, 22 Sep 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-16 21:15:00 +0000 (Thu, 16 Sep 2021)");

  script_name("Debian: Security Advisory (DSA-4977)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4977");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4977");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-4977 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor, which could result in privilege escalation, denial of service or information leaks.

With the end of upstream support for the 4.11 branch, the version of xen in the oldstable distribution (buster) is no longer supported. If you rely on security support for your Xen installation an update to the stable distribution (bullseye) is recommended.

For the stable distribution (bullseye), these problems have been fixed in version 4.14.3-1~deb11u1.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);