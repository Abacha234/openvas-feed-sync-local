# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844434");
  script_cve_id("CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11669", "CVE-2020-12657");
  script_tag(name:"creation_date", value:"2020-05-19 03:00:36 +0000 (Tue, 19 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-13 09:15:00 +0000 (Sat, 13 Jun 2020)");

  script_name("Ubuntu: Security Advisory (USN-4363-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4363-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4363-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-gcp, linux-gke-4.15, linux-hwe, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-oem, linux-meta-oracle, linux-meta-snapdragon, linux-oem, linux-oracle, linux-signed, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4363-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Serial CAN interface driver in the Linux kernel
did not properly initialize data. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2020-11494)

It was discovered that the linux kernel did not properly validate certain
mount options to the tmpfs virtual memory file system. A local attacker
with the ability to specify mount options could use this to cause a denial
of service (system crash). (CVE-2020-11565)

David Gibson discovered that the Linux kernel on Power9 CPUs did not
properly save and restore Authority Mask registers state in some
situations. A local attacker in a guest VM could use this to cause a denial
of service (host system crash). (CVE-2020-11669)

It was discovered that the block layer in the Linux kernel contained a race
condition leading to a use-after-free vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2020-12657)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-gcp, linux-gke-4.15, linux-hwe, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-oem, linux-meta-oracle, linux-meta-snapdragon, linux-oem, linux-oracle, linux-signed, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
