# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887385");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-1062", "CVE-2024-2199", "CVE-2024-3657", "CVE-2024-5953");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-08-15 04:04:18 +0000 (Thu, 15 Aug 2024)");
  script_name("Fedora: Security Advisory for 389-ds-base (FEDORA-2024-ac07913be8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ac07913be8");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7OICYGRRXV2H3UVMYWNZ6W2TQ5FPACS5");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base'
  package(s) announced via the FEDORA-2024-ac07913be8 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"389 Directory Server is an LDAPv3 compliant server");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
