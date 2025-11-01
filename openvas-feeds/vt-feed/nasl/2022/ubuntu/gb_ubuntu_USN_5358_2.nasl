# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845310");
  script_cve_id("CVE-2022-1055", "CVE-2022-27666");
  script_tag(name:"creation_date", value:"2022-04-02 01:00:38 +0000 (Sat, 02 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-29 19:23:00 +0000 (Tue, 29 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5358-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5358-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5358-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-5.4, linux-aws-5.13, linux-azure, linux-azure-5.4, linux-azure-fde, linux-gcp, linux-gcp-5.4, linux-gcp-5.13, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-ibm, linux-ibm-5.4, linux-meta-aws-5.4, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-5.4, linux-meta-azure-fde, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gcp-5.13, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-ibm, linux-meta-ibm-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-raspi, linux-raspi-5.4, linux-signed-aws-5.4, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-5.4, linux-signed-azure-fde, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gcp-5.13, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-ibm, linux-signed-ibm-5.4' package(s) announced via the USN-5358-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the network traffic control implementation in the
Linux kernel contained a use-after-free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-1055)

It was discovered that the IPsec implementation in the Linux kernel did not
properly allocate enough memory when performing ESP transformations,
leading to a heap-based buffer overflow. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-27666)");

  script_tag(name:"affected", value:"'linux-aws-5.4, linux-aws-5.13, linux-azure, linux-azure-5.4, linux-azure-fde, linux-gcp, linux-gcp-5.4, linux-gcp-5.13, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-ibm, linux-ibm-5.4, linux-meta-aws-5.4, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-5.4, linux-meta-azure-fde, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gcp-5.13, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-ibm, linux-meta-ibm-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-raspi, linux-raspi-5.4, linux-signed-aws-5.4, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-5.4, linux-signed-azure-fde, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gcp-5.13, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-ibm, linux-signed-ibm-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
