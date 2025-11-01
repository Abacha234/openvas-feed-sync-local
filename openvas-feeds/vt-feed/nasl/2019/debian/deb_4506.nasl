# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704506");
  script_cve_id("CVE-2018-20815", "CVE-2019-13164", "CVE-2019-14378");
  script_tag(name:"creation_date", value:"2019-08-27 02:00:19 +0000 (Tue, 27 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-02 23:15:00 +0000 (Tue, 02 Jul 2019)");

  script_name("Debian: Security Advisory (DSA-4506)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4506");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4506");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/qemu");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DSA-4506 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in QEMU, a fast processor emulator, which could result in denial of service, the execution of arbitrary code or bypass of ACLs.

In addition this update fixes a regression which could cause NBD connections to hang.

For the oldstable distribution (stretch), these problems have been fixed in version 1:2.8+dfsg-6+deb9u8.

We recommend that you upgrade your qemu packages.

For the detailed security status of qemu please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);