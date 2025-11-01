# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885169");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-39512", "CVE-2023-39514", "CVE-2023-39513", "CVE-2023-39515", "CVE-2023-39359", "CVE-2023-39360", "CVE-2023-39361", "CVE-2023-39366", "CVE-2023-39510", "CVE-2023-39357", "CVE-2023-39358", "CVE-2023-39364", "CVE-2023-39365", "CVE-2023-30534", "CVE-2023-31132", "CVE-2023-39362", "CVE-2023-39516", "CVE-2023-39511");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-08 17:42:00 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:39 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for cacti-spine (FEDORA-2023-248dff7cbe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-248dff7cbe");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WOQFYGLZBAWT4AWNMO7DU73QXWPXTCKH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti-spine'
  package(s) announced via the FEDORA-2023-248dff7cbe advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Spine is a supplemental poller for Cacti that makes use of pthreads to achieve
excellent performance.");

  script_tag(name:"affected", value:"'cacti-spine' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
