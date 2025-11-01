# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844463");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_tag(name:"creation_date", value:"2020-06-10 03:01:41 +0000 (Wed, 10 Jun 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-09 08:15:00 +0000 (Wed, 09 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-4385-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4385-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4385-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SRBDS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode' package(s) announced via the USN-4385-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that memory contents previously stored in
microarchitectural special registers after RDRAND, RDSEED, and SGX EGETKEY
read operations on Intel client and Xeon E3 processors may be briefly
exposed to processes on the same or different processor cores. A local
attacker could use this to expose sensitive information. (CVE-2020-0543)

It was discovered that on some Intel processors, partial data values
previously read from a vector register on a physical core may be propagated
into unused portions of the store buffer. A local attacker could possible
use this to expose sensitive information. (CVE-2020-0548)

It was discovered that on some Intel processors, data from the most
recently evicted modified L1 data cache (L1D) line may be propagated into
an unused (invalid) L1D fill buffer. A local attacker could possibly use
this to expose sensitive information. (CVE-2020-0549)");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
