# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886873");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-26922", "CVE-2024-26924", "CVE-2024-27022", "CVE-2024-27021", "CVE-2024-27020", "CVE-2024-27019", "CVE-2024-27018", "CVE-2024-27017", "CVE-2024-27016", "CVE-2024-27015", "CVE-2024-27014", "CVE-2024-27013", "CVE-2024-27012", "CVE-2024-27011", "CVE-2024-27010", "CVE-2024-27009", "CVE-2024-27008", "CVE-2024-27007", "CVE-2024-27006", "CVE-2024-27005", "CVE-2024-27004", "CVE-2024-27003", "CVE-2024-27002", "CVE-2024-27001", "CVE-2024-27000", "CVE-2024-26999", "CVE-2024-26998", "CVE-2024-26996", "CVE-2024-26995", "CVE-2024-26994", "CVE-2024-26993", "CVE-2024-26992", "CVE-2024-26991", "CVE-2024-26990", "CVE-2024-26989", "CVE-2024-26988", "CVE-2024-26987", "CVE-2024-26986", "CVE-2024-26985", "CVE-2024-26984", "CVE-2024-26983", "CVE-2024-26982", "CVE-2024-26981", "CVE-2024-26980");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 19:37:12 +0000 (Thu, 23 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:50:00 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for kernel (FEDORA-2024-bc0db39a14)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-bc0db39a14");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4EZ6PJW7VOZ224TD7N4JZNU6KV32ZJ53");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the FEDORA-2024-bc0db39a14 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel meta package");

  script_tag(name:"affected", value:"'kernel' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
