# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887381");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-22655", "CVE-2023-23583", "CVE-2023-28746", "CVE-2023-38575", "CVE-2023-39368", "CVE-2023-42667", "CVE-2023-43490", "CVE-2023-45733", "CVE-2023-46103", "CVE-2023-49141");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 17:07:45 +0000 (Tue, 28 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-08-13 04:04:46 +0000 (Tue, 13 Aug 2024)");
  script_name("Fedora: Security Advisory for microcode_ctl (FEDORA-2024-f3692f8528)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f3692f8528");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/L5XIGZZQ4UHWLTIEVM223EMTHGXYOA2F");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl'
  package(s) announced via the FEDORA-2024-f3692f8528 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The microcode_ctl utility is a companion to the microcode driver written
by Tigran Aivazian <a target='_blank' href='mailto:tigran@aivazian");

  script_tag(name:"affected", value:"'microcode_ctl' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
