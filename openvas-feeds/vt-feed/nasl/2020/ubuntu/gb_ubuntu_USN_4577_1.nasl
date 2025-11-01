# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844651");
  script_cve_id("CVE-2020-16119", "CVE-2020-16120");
  script_tag(name:"creation_date", value:"2020-10-14 03:00:36 +0000 (Wed, 14 Oct 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 21:40:00 +0000 (Thu, 04 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4577-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4577-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4577-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gke-5.0, linux-gke-5.3, linux-hwe, linux-meta-gke-5.0, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-oem-osp1, linux-meta-raspi2-5.3, linux-oem-osp1, linux-raspi2-5.3, linux-signed-gke-5.0, linux-signed-gke-5.3, linux-signed-hwe, linux-signed-oem-osp1' package(s) announced via the USN-4577-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hadar Manor discovered that the DCCP protocol implementation in the Linux
kernel improperly handled socket reuse, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2020-16119)

Giuseppe Scrivano discovered that the overlay file system in the Linux
kernel did not properly perform permission checks in some situations. A
local attacker could possibly use this to bypass intended restrictions and
gain read access to restricted files. (CVE-2020-16120)");

  script_tag(name:"affected", value:"'linux-gke-5.0, linux-gke-5.3, linux-hwe, linux-meta-gke-5.0, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-oem-osp1, linux-meta-raspi2-5.3, linux-oem-osp1, linux-raspi2-5.3, linux-signed-gke-5.0, linux-signed-gke-5.3, linux-signed-hwe, linux-signed-oem-osp1' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
