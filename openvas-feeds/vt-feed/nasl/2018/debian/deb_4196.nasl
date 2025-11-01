# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704196");
  script_cve_id("CVE-2018-1087", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2018-05-07 22:00:00 +0000 (Mon, 07 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4196)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4196");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4196");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4196 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation or denial of service.

CVE-2018-1087

Andy Lutomirski discovered that the KVM implementation did not properly handle #DB exceptions while deferred by MOV SS/POP SS, allowing an unprivileged KVM guest user to crash the guest or potentially escalate their privileges.

CVE-2018-8897

Nick Peterson of Everdox Tech LLC discovered that #DB exceptions that are deferred by MOV SS or POP SS are not properly handled, allowing an unprivileged user to crash the kernel and cause a denial of service.

For the oldstable distribution (jessie), these problems have been fixed in version 3.16.56-1+deb8u1. This update includes various fixes for regressions from 3.16.56-1 as released in DSA-4187-1 (Cf. #897427, #898067 and #898100).

For the stable distribution (stretch), these problems have been fixed in version 4.9.88-1+deb9u1. The fix for CVE-2018-1108 applied in DSA-4188-1 is temporarily reverted due to various regression, cf. #897599.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);