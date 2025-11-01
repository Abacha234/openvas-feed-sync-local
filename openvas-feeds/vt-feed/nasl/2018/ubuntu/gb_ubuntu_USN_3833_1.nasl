# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843839");
  script_cve_id("CVE-2018-18955", "CVE-2018-6559");
  script_tag(name:"creation_date", value:"2018-12-04 07:10:35 +0000 (Tue, 04 Dec 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3833-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3833-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3833-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-meta-aws' package(s) announced via the USN-3833-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the Linux kernel mishandles mapping UID or GID
ranges inside nested user namespaces in some situations. A local attacker
could use this to bypass access controls on resources outside the
namespace. (CVE-2018-18955)

Philipp Wendler discovered that the overlayfs implementation in the Linux
kernel did not properly verify the directory contents permissions from
within a unprivileged user namespace. A local attacker could use this to
expose sensitive information (protected file names). (CVE-2018-6559)");

  script_tag(name:"affected", value:"'linux-aws, linux-meta-aws' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
