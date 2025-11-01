# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845391");
  script_cve_id("CVE-2022-1116", "CVE-2022-29581", "CVE-2022-30594");
  script_tag(name:"creation_date", value:"2022-06-01 13:28:47 +0000 (Wed, 01 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 00:05:00 +0000 (Thu, 26 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5442-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5442-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5442-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield, linux-gcp-5.4, linux-gkeop, linux-gkeop-5.4, linux-ibm-5.4, linux-meta-bluefield, linux-meta-gcp-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-ibm-5.4, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed-bluefield, linux-signed-gcp-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-ibm-5.4, linux-signed-oracle, linux-signed-oracle-5.4' package(s) announced via the USN-5442-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kyle Zeng discovered that the Network Queuing and Scheduling subsystem of
the Linux kernel did not properly perform reference counting in some
situations, leading to a use-after-free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2022-29581)

Bing-Jhong Billy Jheng discovered that the io_uring subsystem in the Linux
kernel contained in integer overflow. A local attacker could use this to
cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-1116)

Jann Horn discovered that the Linux kernel did not properly enforce seccomp
restrictions in some situations. A local attacker could use this to bypass
intended seccomp sandbox restrictions. (CVE-2022-30594)");

  script_tag(name:"affected", value:"'linux-bluefield, linux-gcp-5.4, linux-gkeop, linux-gkeop-5.4, linux-ibm-5.4, linux-meta-bluefield, linux-meta-gcp-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-ibm-5.4, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed-bluefield, linux-signed-gcp-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-ibm-5.4, linux-signed-oracle, linux-signed-oracle-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
