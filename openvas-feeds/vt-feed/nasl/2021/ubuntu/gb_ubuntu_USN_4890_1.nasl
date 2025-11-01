# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844879");
  script_cve_id("CVE-2020-27170", "CVE-2020-27171");
  script_tag(name:"creation_date", value:"2021-03-25 04:00:28 +0000 (Thu, 25 Mar 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-08 00:15:00 +0000 (Thu, 08 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-4890-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4890-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4890-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-snapdragon, linux-oracle, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-hwe, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4890-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Piotr Krysiuk discovered that the BPF subsystem in the Linux kernel did not
properly compute a speculative execution limit on pointer arithmetic in
some situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2020-27171)

Piotr Krysiuk discovered that the BPF subsystem in the Linux kernel did not
properly apply speculative execution limits on some pointer types. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2020-27170)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-snapdragon, linux-oracle, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-hwe, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
