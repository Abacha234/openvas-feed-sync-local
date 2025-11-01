# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705222");
  script_cve_id("CVE-2022-2132", "CVE-2022-28199");
  script_tag(name:"creation_date", value:"2022-09-01 01:00:06 +0000 (Thu, 01 Sep 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-06 18:20:00 +0000 (Tue, 06 Sep 2022)");

  script_name("Debian: Security Advisory (DSA-5222)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5222");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5222");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dpdk");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dpdk' package(s) announced via the DSA-5222 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow was discovered in the vhost code of DPDK, a set of libraries for fast packet processing, which could result in denial of service or the execution of arbitrary code by malicious guests/containers.

For the stable distribution (bullseye), these problems have been fixed in version 20.11.6-1~deb11u1.

We recommend that you upgrade your dpdk packages.

For the detailed security status of dpdk please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dpdk' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);