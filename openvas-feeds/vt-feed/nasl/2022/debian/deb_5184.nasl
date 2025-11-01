# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705184");
  script_cve_id("CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-23825", "CVE-2022-26362", "CVE-2022-26363", "CVE-2022-26364", "CVE-2022-29900");
  script_tag(name:"creation_date", value:"2022-07-17 01:00:16 +0000 (Sun, 17 Jul 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-06 19:15:00 +0000 (Wed, 06 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-5184)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5184");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5184");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-404.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-407.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-5184 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor, which could result in privilege escalation. In addition this updates provides mitigations for the Retbleed speculative execution attack and the MMIO stale data vulnerabilities.

For additional information please refer to the following pages: [link moved to references] [link moved to references]

For the stable distribution (bullseye), these problems have been fixed in version 4.14.5+24-g87d90d511c-1.

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