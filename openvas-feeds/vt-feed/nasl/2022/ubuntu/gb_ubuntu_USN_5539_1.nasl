# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845456");
  script_cve_id("CVE-2022-1195", "CVE-2022-1199", "CVE-2022-1204", "CVE-2022-1205", "CVE-2022-1789", "CVE-2022-28388", "CVE-2022-33981");
  script_tag(name:"creation_date", value:"2022-07-29 01:00:37 +0000 (Fri, 29 Jul 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-11 00:47:00 +0000 (Sat, 11 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5539-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5539-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5539-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield, linux-gcp-5.4, linux-gke-5.4, linux-meta-bluefield, linux-meta-gcp-5.4, linux-meta-gke-5.4, linux-signed-bluefield, linux-signed-gcp-5.4, linux-signed-gke-5.4' package(s) announced via the USN-5539-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the implementation of the 6pack and mkiss protocols
in the Linux kernel did not handle detach events properly in some
situations, leading to a use-after-free vulnerability. A local attacker
could possibly use this to cause a denial of service (system crash).
(CVE-2022-1195)

Duoming Zhou discovered that the AX.25 amateur radio protocol
implementation in the Linux kernel did not handle detach events properly in
some situations. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2022-1199)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel during device detach operations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-1204)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel, leading to use-after-free
vulnerabilities. A local attacker could possibly use this to cause a denial
of service (system crash). (CVE-2022-1205)

Yongkang Jia discovered that the KVM hypervisor implementation in the Linux
kernel did not properly handle guest TLB mapping invalidation requests in
some situations. An attacker in a guest VM could use this to cause a denial
of service (system crash) in the host OS. (CVE-2022-1789)

It was discovered that the 8 Devices USB2CAN interface implementation in
the Linux kernel did not properly handle certain error conditions, leading
to a double-free. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2022-28388)

Minh Yuan discovered that the floppy driver in the Linux kernel contained a
race condition in some situations, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-33981)");

  script_tag(name:"affected", value:"'linux-bluefield, linux-gcp-5.4, linux-gke-5.4, linux-meta-bluefield, linux-meta-gcp-5.4, linux-meta-gke-5.4, linux-signed-bluefield, linux-signed-gcp-5.4, linux-signed-gke-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
