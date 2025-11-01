# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842551");
  script_cve_id("CVE-2015-5283", "CVE-2015-7872");
  script_tag(name:"creation_date", value:"2015-12-05 07:42:55 +0000 (Sat, 05 Dec 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2829-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2829-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2829-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-vivid' package(s) announced via the USN-2829-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the SCTP protocol implementation in the Linux kernel
performed an incorrect sequence of protocol-initialization steps. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2015-5283)

Dmitry Vyukov discovered that the Linux kernel's keyring handler attempted
to garbage collect incompletely instantiated keys. A local unprivileged
attacker could use this to cause a denial of service (system crash).
(CVE-2015-7872)");

  script_tag(name:"affected", value:"'linux-lts-vivid' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
