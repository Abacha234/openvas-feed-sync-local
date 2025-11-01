# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845336");
  script_cve_id("CVE-2022-1015", "CVE-2022-1016", "CVE-2022-26490");
  script_tag(name:"creation_date", value:"2022-04-27 01:00:23 +0000 (Wed, 27 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-11 13:39:00 +0000 (Fri, 11 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5390-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5390-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5390-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-gke, linux-ibm, linux-kvm, linux-lowlatency, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-gke, linux-meta-ibm, linux-meta-kvm, linux-meta-lowlatency, linux-meta-oracle, linux-oracle, linux-signed, linux-signed-aws, linux-signed-azure, linux-signed-gcp, linux-signed-gke, linux-signed-ibm, linux-signed-kvm, linux-signed-lowlatency, linux-signed-oracle' package(s) announced via the USN-5390-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Bouman discovered that the netfilter subsystem in the Linux kernel
did not properly validate passed user register indices. A local attacker
could use this to cause a denial of service or possibly execute arbitrary
code. (CVE-2022-1015)

David Bouman discovered that the netfilter subsystem in the Linux kernel
did not initialize memory in some situations. A local attacker could use
this to expose sensitive information (kernel memory). (CVE-2022-1016)

It was discovered that the ST21NFCA NFC driver in the Linux kernel did not
properly validate the size of certain data in EVT_TRANSACTION events. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-26490)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-gke, linux-ibm, linux-kvm, linux-lowlatency, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-gke, linux-meta-ibm, linux-meta-kvm, linux-meta-lowlatency, linux-meta-oracle, linux-oracle, linux-signed, linux-signed-aws, linux-signed-azure, linux-signed-gcp, linux-signed-gke, linux-signed-ibm, linux-signed-kvm, linux-signed-lowlatency, linux-signed-oracle' package(s) on Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
