# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886290");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2022-36764", "CVE-2022-36763", "CVE-2022-36765", "CVE-2023-4522", "CVE-2023-45230", "CVE-2023-45231", "CVE-2023-45232", "CVE-2023-45233", "CVE-2023-45234", "CVE-2023-45235");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-23 15:58:27 +0000 (Tue, 23 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:06 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for edk2 (FEDORA-2024-a9dead34c5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a9dead34c5");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SJ42V7O7F4OU6R7QSQQECLB6LDHKZIMQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2'
  package(s) announced via the FEDORA-2024-a9dead34c5 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"EDK II is a modern, feature-rich, cross-platform firmware development
environment for the UEFI and PI specifications. This package contains sample
64-bit UEFI firmware builds for QEMU and KVM.");

  script_tag(name:"affected", value:"'edk2' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
