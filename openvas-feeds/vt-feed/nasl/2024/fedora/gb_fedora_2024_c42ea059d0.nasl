# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886338");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-2794", "CVE-2023-4232", "CVE-2023-4233", "CVE-2023-4234", "CVE-2023-4235");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-03-28 02:11:22 +0000 (Thu, 28 Mar 2024)");
  script_name("Fedora: Security Advisory for ofono (FEDORA-2024-c42ea059d0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c42ea059d0");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RLAWJAAS3HDI2KMCZXF4DMR3Y4BQNMKO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ofono'
  package(s) announced via the FEDORA-2024-c42ea059d0 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"oFono includes a high-level D-Bus API for use by
 telephony applications. oFono also includes a low-level plug-in API for integrating
 with telephony stacks, cellular modems and storage back-ends.");

  script_tag(name:"affected", value:"'ofono' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
