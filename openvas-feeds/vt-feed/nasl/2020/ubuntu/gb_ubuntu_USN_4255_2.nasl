# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844318");
  script_cve_id("CVE-2019-14615", "CVE-2020-7053");
  script_tag(name:"creation_date", value:"2020-01-29 04:00:42 +0000 (Wed, 29 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-30 16:15:00 +0000 (Thu, 30 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-4255-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4255-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4255-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-hwe, linux-hwe, linux-meta-aws-hwe, linux-meta-hwe, linux-signed-hwe' package(s) announced via the USN-4255-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4255-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 18.04 LTS for Ubuntu
16.04 LTS.

It was discovered that the Linux kernel did not properly clear data
structures on context switches for certain Intel graphics processors. A
local attacker could use this to expose sensitive information.
(CVE-2019-14615)

It was discovered that a race condition can lead to a use-after-free while
destroying GEM contexts in the i915 driver for the Linux kernel. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2020-7053)");

  script_tag(name:"affected", value:"'linux-aws-hwe, linux-hwe, linux-meta-aws-hwe, linux-meta-hwe, linux-signed-hwe' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
