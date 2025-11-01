# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704274");
  script_cve_id("CVE-2018-15468", "CVE-2018-15469", "CVE-2018-15470", "CVE-2018-3620", "CVE-2018-3646");
  script_tag(name:"creation_date", value:"2018-08-15 22:00:00 +0000 (Wed, 15 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-4274)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4274");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4274");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-273.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-4274 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides mitigations for the L1 Terminal Fault vulnerability affecting a range of Intel CPUs.

For additional information please refer to [link moved to references]. The microcode updates mentioned there are not yet available in a form distributable by Debian.

In addition two denial of service vulnerabilities have been fixed (XSA-268 and XSA-269).

For the stable distribution (stretch), these problems have been fixed in version 4.8.4+xsa273+shim4.10.1+xsa273-1+deb9u10.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);