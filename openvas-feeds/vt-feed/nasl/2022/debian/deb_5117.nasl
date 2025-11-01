# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705117");
  script_cve_id("CVE-2022-23033", "CVE-2022-23034", "CVE-2022-23035", "CVE-2022-26356", "CVE-2022-26357", "CVE-2022-26358", "CVE-2022-26359", "CVE-2022-26360", "CVE-2022-26361");
  script_tag(name:"creation_date", value:"2022-04-20 01:00:35 +0000 (Wed, 20 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-14 19:17:00 +0000 (Thu, 14 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-5117)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5117");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5117");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-5117 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor, which could result in privilege escalation, denial of service or information leaks.

For the stable distribution (bullseye), these problems have been fixed in version 4.14.4+74-gd7b22226b5-1.

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